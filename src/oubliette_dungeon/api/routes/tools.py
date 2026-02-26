"""
Tool integration endpoints for the Oubliette Dungeon API.

Routes:
    GET  /api/dungeon/tools                     - List available tools
    POST /api/dungeon/tools/<name>/run          - Run campaign with tool
    POST /api/dungeon/tools/pyrit/crescendo     - PyRIT crescendo attack
    POST /api/dungeon/tools/pyrit/variations    - Generate prompt variations
    POST /api/dungeon/tools/deepteam/scan       - DeepTeam vulnerability scan
    POST /api/dungeon/tools/garak/import        - Import Garak probes
    GET  /api/dungeon/tools/compare             - Compare results across tools
"""

from flask import request, jsonify

from oubliette_dungeon.core import DEFAULT_TARGET_URL
from oubliette_dungeon.api.middleware import (
    dungeon_bp,
    _require_api_key,
    _get_loader,
    _get_results_db,
    _get_tool_manager,
    _result_to_dict,
    SCENARIOS_FILE,
)


@dungeon_bp.route("/api/dungeon/tools")
@_require_api_key
def list_tools():
    """List available third-party red team tools and their status."""
    tm = _get_tool_manager()
    return jsonify({"tools": tm.list_tools()})


@dungeon_bp.route("/api/dungeon/tools/<tool_name>/run", methods=["POST"])
@_require_api_key
def run_tool_campaign(tool_name):
    """Run a campaign through a specific tool.

    JSON body:
        target_url: Override target URL (optional)
        scenario_ids: List of scenario IDs to run (optional, default=all)
        category: Filter scenarios by category (optional)
    """
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", DEFAULT_TARGET_URL)
    scenario_ids = data.get("scenario_ids")
    category = data.get("category")

    loader = _get_loader()
    if scenario_ids:
        scenarios = [loader.get_by_id(sid) for sid in scenario_ids]
        scenarios = [s for s in scenarios if s is not None]
    elif category:
        scenarios = loader.get_by_category(category)
    else:
        scenarios = loader.get_all_scenarios()

    if not scenarios:
        return jsonify({"error": "No scenarios matched"}), 404

    tm = _get_tool_manager()
    try:
        results = tm.run_with_tool(tool_name, scenarios, target_url)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503

    return jsonify({
        "tool": tool_name,
        "results": [_result_to_dict(r) for r in results],
        "count": len(results),
    })


@dungeon_bp.route("/api/dungeon/tools/pyrit/crescendo", methods=["POST"])
@_require_api_key
def pyrit_crescendo():
    """Run a PyRIT crescendo (multi-turn escalation) attack.

    JSON body:
        objective: Attack objective string (required)
        target_url: Override target URL (optional)
        max_turns: Max conversation turns (optional, default=10)
    """
    data = request.get_json(silent=True) or {}
    objective = data.get("objective", "")
    if not objective:
        return jsonify({"error": "objective is required"}), 400

    target_url = data.get("target_url", DEFAULT_TARGET_URL)
    max_turns = data.get("max_turns", 10)

    tm = _get_tool_manager()
    adapter = tm.get_tool("pyrit")
    if not adapter:
        return jsonify({"error": "PyRIT adapter not found"}), 404
    if not adapter.is_available():
        return jsonify({"error": "pyrit-core is not installed"}), 503

    try:
        results = adapter.run_crescendo(
            objective=objective,
            target_url=target_url,
            max_turns=max_turns,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "tool": "pyrit",
        "attack_type": "crescendo",
        "results": [_result_to_dict(r) for r in results],
        "count": len(results),
    })


@dungeon_bp.route("/api/dungeon/tools/pyrit/variations", methods=["POST"])
@_require_api_key
def pyrit_variations():
    """Generate attack prompt variations using PyRIT converters.

    JSON body:
        prompt: Seed attack prompt (required)
        num_variations: Number of variations (optional, default=10)
    """
    data = request.get_json(silent=True) or {}
    prompt = data.get("prompt", "")
    if not prompt:
        return jsonify({"error": "prompt is required"}), 400

    num_variations = data.get("num_variations", 10)

    tm = _get_tool_manager()
    adapter = tm.get_tool("pyrit")
    if not adapter:
        return jsonify({"error": "PyRIT adapter not found"}), 404

    variations = adapter.generate_variations(prompt, num_variations)
    return jsonify({
        "tool": "pyrit",
        "original_prompt": prompt,
        "variations": variations,
        "count": len(variations),
    })


@dungeon_bp.route("/api/dungeon/tools/deepteam/scan", methods=["POST"])
@_require_api_key
def deepteam_scan():
    """Run DeepTeam's built-in vulnerability scanner.

    JSON body:
        target_url: Override target URL (optional)
        vulnerabilities: List of vulnerability names (optional, default=all)
        attacks_per_vuln: Attacks per vulnerability (optional, default=5)
    """
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", DEFAULT_TARGET_URL)
    vulns = data.get("vulnerabilities")
    attacks_per_vuln = data.get("attacks_per_vuln", 5)

    tm = _get_tool_manager()
    adapter = tm.get_tool("deepteam")
    if not adapter:
        return jsonify({"error": "DeepTeam adapter not found"}), 404
    if not adapter.is_available():
        return jsonify({"error": "deepteam is not installed"}), 503

    try:
        results = adapter.run_vulnerability_scan(
            target_url=target_url,
            vulns=vulns,
            attacks_per_vuln=attacks_per_vuln,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "tool": "deepteam",
        "attack_type": "vulnerability_scan",
        "results": [_result_to_dict(r) for r in results],
        "count": len(results),
    })


@dungeon_bp.route("/api/dungeon/tools/garak/import", methods=["POST"])
@_require_api_key
def garak_import():
    """Import Garak probes and optionally merge with existing scenarios.

    JSON body:
        garak_path: Path to cloned garak repo (optional)
        probe_categories: List of probe categories to import (optional)
        merge: Whether to merge with existing scenario file (default=false)
    """
    data = request.get_json(silent=True) or {}
    garak_path = data.get("garak_path")
    probe_categories = data.get("probe_categories")
    merge = data.get("merge", False)

    from oubliette_dungeon.tools.garak_importer import GarakImporter

    importer = GarakImporter(garak_path=garak_path)
    scenarios = importer.import_probes(probe_categories=probe_categories)

    result = {
        "tool": "garak",
        "imported_count": len(scenarios),
        "scenarios": [
            {
                "id": s.id,
                "name": s.name,
                "category": s.category,
                "difficulty": s.difficulty,
                "prompt": s.prompt[:200] + "..." if len(s.prompt) > 200 else s.prompt,
            }
            for s in scenarios
        ],
    }

    if merge:
        merged_yaml = importer.merge_with_existing(SCENARIOS_FILE, scenarios)
        result["merged_yaml_length"] = len(merged_yaml)
        result["note"] = "Merged YAML generated but not written to disk. POST with write=true to persist."

    return jsonify(result)


@dungeon_bp.route("/api/dungeon/tools/compare")
@_require_api_key
def compare_tools():
    """Compare results across all available tools.

    Query params:
        session_prefix: Filter sessions by prefix (e.g. "pyrit_", "deepteam_")
    """
    db = _get_results_db()
    sessions = db.list_sessions()

    tool_results = {}
    for session_info in sessions:
        sid = session_info.get("session_id", "")
        # Group by tool prefix
        for tool_name in ("pyrit", "deepteam"):
            if sid.startswith(f"{tool_name}_"):
                session_data = db.get_session(sid)
                if session_data:
                    raw_results = session_data.get("results", [])
                    if tool_name not in tool_results:
                        tool_results[tool_name] = []
                    tool_results[tool_name].extend(raw_results)

    # Build comparison stats
    comparison = {"tools": {}}
    for tool_name, results in tool_results.items():
        total = len(results)
        detected = sum(1 for r in results if r.get("result") == "detected")
        bypassed = sum(1 for r in results if r.get("result") == "bypass")

        comparison["tools"][tool_name] = {
            "total": total,
            "detected": detected,
            "bypassed": bypassed,
            "detection_rate": round(detected / total * 100, 1) if total else 0,
            "bypass_rate": round(bypassed / total * 100, 1) if total else 0,
        }

    return jsonify(comparison)
