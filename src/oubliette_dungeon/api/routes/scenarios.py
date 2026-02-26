"""
Scenario endpoints for the Oubliette Dungeon API.

Routes:
    GET  /api/dungeon/scenarios           - List all attack scenarios
    GET  /api/dungeon/scenarios/stats     - Scenario library statistics
    GET  /api/dungeon/scenarios/<id>      - Get single scenario detail
"""

from flask import request, jsonify

from oubliette_dungeon.api.middleware import (
    dungeon_bp,
    _require_api_key,
    _get_loader,
    _scenario_to_dict,
)


@dungeon_bp.route("/api/dungeon/scenarios")
@_require_api_key
def list_scenarios():
    """List all attack scenarios with optional filters."""
    loader = _get_loader()

    category = request.args.get("category")
    difficulty = request.args.get("difficulty")

    if category:
        scenarios = loader.get_by_category(category)
    elif difficulty:
        scenarios = loader.get_by_difficulty(difficulty)
    else:
        scenarios = loader.get_all_scenarios()

    return jsonify({
        "scenarios": [_scenario_to_dict(s) for s in scenarios],
        "count": len(scenarios),
    })


@dungeon_bp.route("/api/dungeon/scenarios/stats")
@_require_api_key
def scenario_stats():
    """Get scenario library statistics."""
    loader = _get_loader()
    stats = loader.get_statistics()
    return jsonify(stats)


@dungeon_bp.route("/api/dungeon/scenarios/<scenario_id>")
@_require_api_key
def get_scenario(scenario_id):
    """Get a single scenario by ID."""
    loader = _get_loader()
    scenario = loader.get_by_id(scenario_id)
    if not scenario:
        return jsonify({"error": f"Scenario not found: {scenario_id}"}), 404
    return jsonify(_scenario_to_dict(scenario))
