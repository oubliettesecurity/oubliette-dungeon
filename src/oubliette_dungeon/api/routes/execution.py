"""
Execution endpoints for the Oubliette Dungeon API.

Routes:
    POST /api/dungeon/start                     - Start a full red team session
    POST /api/dungeon/execute/<id>              - Execute a single scenario
    POST /api/dungeon/execute/category/<cat>    - Execute all in category
"""

import threading

from flask import request, jsonify

from oubliette_dungeon.core import (
    RedTeamOrchestrator, DEFAULT_TARGET_URL,
)
from oubliette_dungeon.api.middleware import (
    dungeon_bp,
    _require_api_key,
    _audit,
    _get_loader,
    _get_results_db,
    _result_to_dict,
    _running_session,
    _session_lock,
    SCENARIOS_FILE,
    DEFAULT_TIMEOUT,
)


@dungeon_bp.route("/api/dungeon/start", methods=["POST"])
@_require_api_key
def start_session():
    """
    Start a full red team session (runs all scenarios).
    Runs in background thread. Returns session_id immediately.

    Optional JSON body:
        target_url: Override target URL
        timeout: Override timeout
        category: Only run scenarios in this category
        difficulty: Only run scenarios at this difficulty
    """
    import oubliette_dungeon.api.middleware as mw

    with _session_lock:
        if mw._running_session is not None:
            return jsonify({
                "error": "A session is already running",
                "running_session": mw._running_session,
            }), 409

    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", DEFAULT_TARGET_URL)
    timeout = data.get("timeout", DEFAULT_TIMEOUT)
    category = data.get("category")
    difficulty = data.get("difficulty")

    results_db = _get_results_db()
    orchestrator = RedTeamOrchestrator(
        scenario_file=SCENARIOS_FILE,
        target_url=target_url,
        results_db=results_db,
        timeout=timeout,
    )
    session_id = orchestrator.current_session_id

    with _session_lock:
        mw._running_session = session_id

    _audit("start_session", f"session={session_id} target={target_url} cat={category} diff={difficulty}")

    def _run():
        """Execute the red team session in a background daemon thread."""
        try:
            if category:
                orchestrator.run_by_category(category)
            elif difficulty:
                orchestrator.run_by_difficulty(difficulty)
            else:
                orchestrator.run_all_scenarios()
        except Exception as e:
            print(f"[DUNGEON-API] Session {session_id} error: {e}")
        finally:
            with _session_lock:
                mw._running_session = None

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify({
        "session_id": session_id,
        "status": "started",
        "target_url": target_url,
        "category": category,
        "difficulty": difficulty,
    })


@dungeon_bp.route("/api/dungeon/execute/<scenario_id>", methods=["POST"])
@_require_api_key
def execute_scenario(scenario_id):
    """
    Execute a single scenario synchronously.
    Returns the result immediately.

    Optional JSON body:
        target_url: Override target URL
        timeout: Override timeout
    """
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", DEFAULT_TARGET_URL)
    timeout = data.get("timeout", DEFAULT_TIMEOUT)

    _audit("execute_scenario", f"scenario={scenario_id} target={target_url}")

    results_db = _get_results_db()
    orchestrator = RedTeamOrchestrator(
        scenario_file=SCENARIOS_FILE,
        target_url=target_url,
        results_db=results_db,
        timeout=timeout,
    )

    try:
        result = orchestrator.run_single_scenario(scenario_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": "Execution failed"}), 500

    return jsonify({
        "session_id": orchestrator.current_session_id,
        "result": _result_to_dict(result),
    })


@dungeon_bp.route("/api/dungeon/execute/category/<category>", methods=["POST"])
@_require_api_key
def execute_category(category):
    """
    Execute all scenarios in a category.
    Runs in background, returns session_id.
    """
    import oubliette_dungeon.api.middleware as mw

    with _session_lock:
        if mw._running_session is not None:
            return jsonify({
                "error": "A session is already running",
                "running_session": mw._running_session,
            }), 409

    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", DEFAULT_TARGET_URL)
    timeout = data.get("timeout", DEFAULT_TIMEOUT)

    results_db = _get_results_db()
    orchestrator = RedTeamOrchestrator(
        scenario_file=SCENARIOS_FILE,
        target_url=target_url,
        results_db=results_db,
        timeout=timeout,
    )
    session_id = orchestrator.current_session_id

    # Verify category has scenarios
    loader = _get_loader()
    scenarios = loader.get_by_category(category)
    if not scenarios:
        return jsonify({"error": f"No scenarios found for category: {category}"}), 404

    with _session_lock:
        mw._running_session = session_id

    _audit("execute_category", f"session={session_id} category={category} target={target_url}")

    def _run():
        try:
            orchestrator.run_by_category(category)
        except Exception as e:
            print(f"[DUNGEON-API] Category run error: {e}")
        finally:
            with _session_lock:
                mw._running_session = None

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify({
        "session_id": session_id,
        "status": "started",
        "category": category,
        "scenario_count": len(scenarios),
    })
