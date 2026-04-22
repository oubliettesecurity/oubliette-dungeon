"""
Human-in-the-Loop (HITL) review endpoints for the Oubliette Dungeon API.

Routes:
    GET  /api/dungeon/reviews                     - Get review queue summary
    GET  /api/dungeon/reviews/pending              - Get items pending review
    GET  /api/dungeon/reviews/items/<scenario_id>  - Get a specific reviewable item
    POST /api/dungeon/reviews/flag                 - Flag results for review
    POST /api/dungeon/reviews/submit               - Submit a human review
    GET  /api/dungeon/reviews/export               - Export reviewed results as JSON
"""

from flask import jsonify, request

from oubliette_dungeon.api.middleware import (
    _get_results_db,
    _require_api_key,
    dungeon_bp,
)
from oubliette_dungeon.core.hitl import ReviewQueue
from oubliette_dungeon.core.models import AttackTestResult

# Module-level review queue (populated on first flag/load)
_review_queue = None


def _get_or_create_queue():
    """Get or create the review queue from the latest session."""
    global _review_queue
    if _review_queue is None:
        db = _get_results_db()
        session = db.get_latest_session()
        if session and "results" in session:
            results = []
            for r in session["results"]:
                results.append(AttackTestResult(
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
                ))
            _review_queue = ReviewQueue.from_results(results)
        else:
            _review_queue = ReviewQueue()
    return _review_queue


@dungeon_bp.route("/api/dungeon/reviews")
@_require_api_key
def review_summary():
    """Get review queue summary and metrics."""
    queue = _get_or_create_queue()
    return jsonify(queue.summary())


@dungeon_bp.route("/api/dungeon/reviews/pending")
@_require_api_key
def pending_reviews():
    """Get items pending human review."""
    queue = _get_or_create_queue()
    pending = queue.pending_review
    return jsonify({
        "count": len(pending),
        "items": [
            {
                "scenario_id": item.scenario_id,
                "scenario_name": item.scenario_name,
                "category": item.category,
                "difficulty": item.difficulty,
                "automated_result": item.automated_result,
                "automated_confidence": item.automated_confidence,
                "response_snippet": item.response_snippet[:300],
                "review_reason": item.review_reason,
                "bypass_indicators_found": item.bypass_indicators_found,
                "safe_indicators_found": item.safe_indicators_found,
            }
            for item in pending
        ],
    })


@dungeon_bp.route("/api/dungeon/reviews/items/<scenario_id>")
@_require_api_key
def get_review_item(scenario_id):
    """Get a specific reviewable item with full details."""
    if not scenario_id.replace("-", "").replace("_", "").isalnum():
        return jsonify({"error": "Invalid scenario ID"}), 400

    queue = _get_or_create_queue()
    item = queue.get_item(scenario_id)
    if item is None:
        return jsonify({"error": f"Scenario not found: {scenario_id}"}), 404

    from dataclasses import asdict
    return jsonify(asdict(item))


@dungeon_bp.route("/api/dungeon/reviews/flag", methods=["POST"])
@_require_api_key
def flag_for_review():
    """Flag results for human review based on criteria."""
    data = request.get_json() or {}
    threshold = data.get("confidence_threshold", 0.75)
    flag_partial = data.get("flag_partial", True)
    flag_categories = data.get("flag_categories", None)

    if not isinstance(threshold, (int, float)) or not (0 <= threshold <= 1):
        return jsonify({"error": "confidence_threshold must be between 0 and 1"}), 400

    queue = _get_or_create_queue()
    flagged = queue.flag_for_review(
        confidence_threshold=threshold,
        flag_partial=flag_partial,
        flag_categories=flag_categories,
    )

    return jsonify({
        "flagged": flagged,
        "total": queue.total,
        "pending_review": len(queue.pending_review),
    })


@dungeon_bp.route("/api/dungeon/reviews/submit", methods=["POST"])
@_require_api_key
def submit_review():
    """Submit a human review for a scenario."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    required = ["scenario_id", "reviewer", "override_result", "justification"]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({"error": f"Missing required fields: {missing}"}), 400

    valid_results = ("detected", "bypass", "partial")
    if data["override_result"] not in valid_results:
        return jsonify({
            "error": f"override_result must be one of: {valid_results}"
        }), 400

    queue = _get_or_create_queue()
    success = queue.submit_review(
        scenario_id=data["scenario_id"],
        reviewer=data["reviewer"],
        override_result=data["override_result"],
        override_confidence=data.get("override_confidence", 0.90),
        justification=data["justification"],
        tags=data.get("tags", []),
    )

    if not success:
        return jsonify({"error": f"Scenario not found: {data['scenario_id']}"}), 404

    item = queue.get_item(data["scenario_id"])
    return jsonify({
        "success": True,
        "scenario_id": data["scenario_id"],
        "final_result": item.final_result,
        "final_confidence": item.final_confidence,
        "total_reviews": len(item.reviews),
    })


@dungeon_bp.route("/api/dungeon/reviews/export")
@_require_api_key
def export_reviews():
    """Export the full review queue with all reviews."""
    queue = _get_or_create_queue()
    return jsonify(queue.to_dict())
