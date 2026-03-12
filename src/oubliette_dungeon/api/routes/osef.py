"""
OSEF (Oubliette Structured Evaluation Format) endpoints for the Oubliette Dungeon API.

Routes:
    GET  /api/dungeon/osef/<session_id>  - Generate OSEF report for a session
    GET  /api/dungeon/osef/latest        - Generate OSEF report for latest session
    POST /api/dungeon/osef/validate      - Validate an OSEF document
"""

import json
from typing import List

from flask import jsonify, request

from oubliette_dungeon.api.middleware import (
    dungeon_bp,
    _require_api_key,
    _get_results_db,
)
from oubliette_dungeon.core.models import AttackTestResult
from oubliette_dungeon.core.osef import OSEFReport, OSEF_VERSION


def _build_results_from_session(session_data: dict) -> List[AttackTestResult]:
    """Convert raw session result dicts into AttackTestResult objects."""
    results = []
    for r in session_data.get("results", []):
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
    return results


@dungeon_bp.route("/api/dungeon/osef/latest")
@_require_api_key
def osef_latest():
    """Generate an OSEF report for the most recent session."""
    db = _get_results_db()
    session_data = db.get_latest_session()
    if not session_data:
        return jsonify({"error": "No sessions found"}), 404

    results = _build_results_from_session(session_data)
    if not results:
        return jsonify({"error": "Session has no results"}), 404

    session_id = session_data.get("session_id", "")
    model_id = session_data.get("model_id", "unknown")

    report = OSEFReport.from_results(
        results,
        model_id=model_id,
        session_id=session_id,
    )

    return jsonify(report.to_dict())


@dungeon_bp.route("/api/dungeon/osef/<session_id>")
@_require_api_key
def osef_for_session(session_id):
    """Generate an OSEF report for a specific session."""
    # Validate session_id
    if not session_id.replace("_", "").isalnum():
        return jsonify({"error": "Invalid session ID"}), 400

    db = _get_results_db()
    session_data = db.get_session(session_id)
    if not session_data:
        return jsonify({"error": f"Session not found: {session_id}"}), 404

    results = _build_results_from_session(session_data)
    if not results:
        return jsonify({"error": "Session has no results"}), 404

    model_id = session_data.get("model_id", "unknown")

    report = OSEFReport.from_results(
        results,
        model_id=model_id,
        session_id=session_id,
    )

    return jsonify(report.to_dict())


@dungeon_bp.route("/api/dungeon/osef/validate", methods=["POST"])
@_require_api_key
def validate_osef():
    """
    Validate an OSEF document against the schema.

    Accepts a JSON body containing the OSEF document to validate.
    Returns a list of validation errors (empty if valid).
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be a valid JSON OSEF document"}), 400

    errors = []

    # Check required top-level fields
    required_top = [
        "osef_version", "tool", "model_id", "timestamp",
        "aggregate", "results", "framework_coverage",
    ]
    for key in required_top:
        if key not in data:
            errors.append(f"Missing required top-level field: {key}")

    # Validate version
    if "osef_version" in data:
        version = data["osef_version"]
        if not isinstance(version, str):
            errors.append("osef_version must be a string")

    # Validate aggregate
    if "aggregate" in data:
        agg = data["aggregate"]
        if not isinstance(agg, dict):
            errors.append("'aggregate' must be an object")
        else:
            for key in ["total_scenarios", "overall_detection_rate", "overall_bypass_rate"]:
                if key not in agg:
                    errors.append(f"Missing aggregate field: {key}")

    # Validate results
    if "results" in data:
        if not isinstance(data["results"], list):
            errors.append("'results' must be a list")
        elif data["results"]:
            r0 = data["results"][0]
            for key in ["scenario_id", "result", "confidence", "framework_mappings"]:
                if key not in r0:
                    errors.append(f"Result missing required field: {key}")

    # Validate framework_coverage
    if "framework_coverage" in data:
        fc = data["framework_coverage"]
        if not isinstance(fc, dict):
            errors.append("'framework_coverage' must be an object")

    valid = len(errors) == 0

    return jsonify({
        "valid": valid,
        "osef_version": OSEF_VERSION,
        "errors": errors,
        "fields_checked": len(required_top),
    })
