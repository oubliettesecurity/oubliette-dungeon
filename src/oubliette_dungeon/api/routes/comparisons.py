"""
Comparison endpoints for the Oubliette Dungeon API.

Routes:
    GET  /api/dungeon/comparisons                - List saved comparison reports
    GET  /api/dungeon/comparisons/<comparison_id> - Get a specific comparison
    POST /api/dungeon/comparisons/run             - Run a new comparison
"""

import glob
import json
import os
import threading
from datetime import UTC, datetime

from flask import jsonify, request

from oubliette_dungeon.api.middleware import (
    DEFAULT_TIMEOUT,
    RESULTS_DB_DIR,
    SCENARIOS_FILE,
    _audit,
    _get_results_db,
    _require_api_key,
    _session_lock,
    _validate_target_url,
    dungeon_bp,
)


def _comparisons_dir() -> str:
    """Return the directory where comparison reports are stored."""
    d = os.path.join(RESULTS_DB_DIR, "comparisons")
    os.makedirs(d, exist_ok=True)
    return d


def _comparison_path(comparison_id: str) -> str:
    """Return the file path for a comparison report."""
    return os.path.join(_comparisons_dir(), f"comparison_{comparison_id}.json")


@dungeon_bp.route("/api/dungeon/comparisons")
@_require_api_key
def list_comparisons():
    """List all saved comparison reports."""
    cdir = _comparisons_dir()
    pattern = os.path.join(cdir, "comparison_*.json")
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

    comparisons = []
    for fpath in files:
        fname = os.path.basename(fpath)
        # Extract comparison_id from filename: comparison_<id>.json
        cid = fname.replace("comparison_", "").replace(".json", "")
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
            comparisons.append(
                {
                    "comparison_id": cid,
                    "timestamp": data.get("timestamp", ""),
                    "model_count": data.get("model_count", 0),
                    "models": [r.get("model_id", "") for r in data.get("ranking", [])],
                    "status": data.get("status", "complete"),
                }
            )
        except (json.JSONDecodeError, OSError):
            comparisons.append(
                {
                    "comparison_id": cid,
                    "timestamp": "",
                    "model_count": 0,
                    "models": [],
                    "status": "error",
                }
            )

    return jsonify(
        {
            "comparisons": comparisons,
            "count": len(comparisons),
        }
    )


@dungeon_bp.route("/api/dungeon/comparisons/<comparison_id>")
@_require_api_key
def get_comparison(comparison_id):
    """Get a specific comparison report by ID."""
    # Validate comparison_id
    if not comparison_id.replace("_", "").replace("-", "").isalnum():
        return jsonify({"error": "Invalid comparison ID"}), 400

    fpath = _comparison_path(comparison_id)
    if not os.path.exists(fpath):
        return jsonify({"error": f"Comparison not found: {comparison_id}"}), 404

    try:
        with open(fpath, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return jsonify({"error": f"Failed to read comparison: {e}"}), 500

    return jsonify(data)


@dungeon_bp.route("/api/dungeon/comparisons/run", methods=["POST"])
@_require_api_key
def run_comparison():
    """
    Trigger a multi-model comparison run.

    Runs attack scenarios against multiple models and saves a comparison
    report. The comparison runs in a background thread; this endpoint
    returns the comparison_id immediately.

    JSON body:
        models: list[str]         - Model IDs to compare (required)
        target_url: str           - Override target URL (optional)
        timeout: int              - Per-request timeout in seconds (optional)
        category: str             - Restrict to a single category (optional)
    """
    import oubliette_dungeon.api.middleware as mw

    data = request.get_json(silent=True) or {}

    models = data.get("models")
    if not models or not isinstance(models, list) or len(models) < 2:
        return jsonify({"error": "At least 2 model IDs required in 'models' list"}), 400

    if len(models) > 10:
        return jsonify({"error": "Maximum 10 models per comparison"}), 400

    # Validate model IDs are simple strings
    for m in models:
        if not isinstance(m, str) or not m.strip():
            return jsonify({"error": f"Invalid model ID: {m}"}), 400

    # Check no session is already running
    with _session_lock:
        if mw._running_session is not None:
            return jsonify(
                {
                    "error": "A session is already running",
                    "running_session": mw._running_session,
                }
            ), 409

    target_url = data.get("target_url")
    timeout = data.get("timeout", DEFAULT_TIMEOUT)
    category = data.get("category")

    # SSRF validation (when target_url is explicitly provided)
    if target_url:
        is_safe, error_msg = _validate_target_url(target_url)
        if not is_safe:
            return jsonify({"error": f"Blocked target URL: {error_msg}"}), 400

    comparison_id = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    _audit(
        "run_comparison",
        f"comparison={comparison_id} models={models} category={category}",
    )

    # Write a placeholder so the listing shows "running"
    placeholder = {
        "comparison_id": comparison_id,
        "status": "running",
        "timestamp": datetime.now(UTC).isoformat(),
        "model_count": len(models),
        "models": models,
        "ranking": [],
        "scenario_matrix": [],
        "category_comparison": {},
    }
    fpath = _comparison_path(comparison_id)
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump(placeholder, f, indent=2, default=str)

    def _run():
        """Execute the comparison in a background thread."""
        try:
            from oubliette_dungeon.core import (
                AttackTestResult,
                RedTeamOrchestrator,
            )
            from oubliette_dungeon.core.comparison import ModelComparison

            comp = ModelComparison()

            for model_id in models:
                kwargs = {
                    "scenario_file": SCENARIOS_FILE,
                    "results_db": _get_results_db(),
                    "timeout": timeout,
                }
                if target_url:
                    kwargs["target_url"] = target_url

                orchestrator = RedTeamOrchestrator(**kwargs)

                if category:
                    orchestrator.run_by_category(category)
                else:
                    orchestrator.run_all_scenarios()

                # Collect results from the session
                db = _get_results_db()
                session_data = db.get_session(orchestrator.current_session_id)
                results = []
                if session_data and "results" in session_data:
                    for r in session_data["results"]:
                        results.append(
                            AttackTestResult(
                                scenario_id=r.get("scenario_id", ""),
                                scenario_name=r.get("scenario_name", ""),
                                category=r.get("category", ""),
                                difficulty=r.get("difficulty", ""),
                                result=r.get("result", ""),
                                confidence=r.get("confidence", 0),
                                response=r.get("response", ""),
                                execution_time_ms=r.get("execution_time_ms", 0),
                                bypass_indicators_found=r.get("bypass_indicators_found", []),
                                safe_indicators_found=r.get("safe_indicators_found", []),
                                ml_score=r.get("ml_score"),
                                llm_verdict=r.get("llm_verdict"),
                                notes=r.get("notes", ""),
                            )
                        )

                comp.add_results(model_id, results)

            # Save completed comparison
            report = comp.to_dict()
            report["comparison_id"] = comparison_id
            report["status"] = "complete"

            with open(fpath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)

        except Exception as e:
            # Mark comparison as failed
            try:
                error_report = {
                    "comparison_id": comparison_id,
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.now(UTC).isoformat(),
                    "model_count": len(models),
                    "models": models,
                    "ranking": [],
                    "scenario_matrix": [],
                    "category_comparison": {},
                }
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(error_report, f, indent=2, default=str)
            except OSError:
                pass
            print(f"[DUNGEON-API] Comparison {comparison_id} error: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify(
        {
            "comparison_id": comparison_id,
            "status": "started",
            "models": models,
            "category": category,
        }
    )
