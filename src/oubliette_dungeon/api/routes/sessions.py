"""
Session and results endpoints for the Oubliette Dungeon API.

Routes:
    GET  /api/dungeon/status                    - Check if a session is running
    GET  /api/dungeon/sessions                  - List all test sessions
    GET  /api/dungeon/sessions/latest           - Get latest session results
    GET  /api/dungeon/results/<session>         - Get results for a session
    GET  /api/dungeon/results/<session>/summary - Get session summary
"""

from flask import jsonify

from oubliette_dungeon.api.middleware import (
    dungeon_bp,
    _require_api_key,
    _get_results_db,
    _session_lock,
)


@dungeon_bp.route("/api/dungeon/status")
@_require_api_key
def session_status():
    """Check if a session is currently running."""
    import oubliette_dungeon.api.middleware as mw

    with _session_lock:
        running = mw._running_session
    return jsonify({
        "running": running is not None,
        "session_id": running,
    })


@dungeon_bp.route("/api/dungeon/sessions")
@_require_api_key
def list_sessions():
    """List all test sessions."""
    db = _get_results_db()
    sessions = db.list_sessions()
    return jsonify({
        "sessions": sessions,
        "count": len(sessions),
    })


@dungeon_bp.route("/api/dungeon/sessions/latest")
@_require_api_key
def latest_session():
    """Get the latest session results."""
    db = _get_results_db()
    session = db.get_latest_session()
    if not session:
        return jsonify({"error": "No sessions found"}), 404
    return jsonify(session)


@dungeon_bp.route("/api/dungeon/results/<session_id>")
@_require_api_key
def get_results(session_id):
    """Get results for a specific session."""
    # Validate session_id
    if not session_id.replace("_", "").isalnum():
        return jsonify({"error": "Invalid session ID"}), 400

    db = _get_results_db()
    session = db.get_session(session_id)
    if not session:
        return jsonify({"error": f"Session not found: {session_id}"}), 404
    return jsonify(session)


@dungeon_bp.route("/api/dungeon/results/<session_id>/summary")
@_require_api_key
def get_summary(session_id):
    """Get summary statistics for a session."""
    if not session_id.replace("_", "").isalnum():
        return jsonify({"error": "Invalid session ID"}), 400

    db = _get_results_db()
    stats = db.get_statistics(session_id)
    if "error" in stats:
        return jsonify(stats), 404
    return jsonify(stats)
