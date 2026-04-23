"""
PDF export endpoint for the Oubliette Dungeon API.

Routes:
    POST/GET /api/dungeon/results/<session_id>/pdf - Generate a PDF report
"""

from flask import Response, jsonify

from oubliette_dungeon.api.middleware import (
    _get_results_db,
    _require_api_key,
    dungeon_bp,
)
from oubliette_dungeon.storage.json_file import is_valid_session_id


@dungeon_bp.route("/api/dungeon/results/<session_id>/pdf", methods=["POST", "GET"])
@_require_api_key
def export_pdf(session_id):
    """Generate a PDF report for a red team session."""
    if not is_valid_session_id(session_id):
        return jsonify({"error": "Invalid session ID"}), 400

    try:
        from oubliette_dungeon.report import ReportGenerator
    except ImportError:
        return jsonify({"error": "PDF generation not available (pip install fpdf2)"}), 503

    db = _get_results_db()
    session_data = db.get_session(session_id)
    if not session_data:
        return jsonify({"error": f"Session not found: {session_id}"}), 404

    stats = db.get_statistics(session_id)
    results = session_data.get("results", [])

    gen = ReportGenerator()
    pdf_bytes = gen.red_team_report(session_id=session_id, stats=stats, results=results)

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="dungeon_{session_id}.pdf"',
        },
    )
