"""
Scheduler endpoints for the Oubliette Dungeon API.

Routes:
    POST   /api/dungeon/schedule                - Create a new scheduled job
    GET    /api/dungeon/schedule                - List all scheduled jobs
    GET    /api/dungeon/schedule/<job_id>       - Get a scheduled job by ID
    PUT    /api/dungeon/schedule/<job_id>       - Update a scheduled job
    DELETE /api/dungeon/schedule/<job_id>       - Delete a scheduled job
    POST   /api/dungeon/schedule/<job_id>/run   - Trigger a job immediately
    GET    /api/dungeon/schedule/history        - Get run history
"""

from flask import request, jsonify

from oubliette_dungeon.api.middleware import (
    dungeon_bp,
    _require_api_key,
    _audit,
    _get_scheduler,
    _is_safe_webhook_url,
)


@dungeon_bp.route("/api/dungeon/schedule", methods=["POST"])
@_require_api_key
def create_schedule():
    """Create a new scheduled red team job."""
    data = request.get_json(silent=True) or {}

    name = data.get("name", "Unnamed Job")
    cron = data.get("cron", "")
    if not cron:
        return jsonify({"error": "cron expression required"}), 400

    # Validate webhook URL if provided
    notification = data.get("notification")
    if notification and notification.get("type") == "webhook":
        url = notification.get("url", "")
        if url and not _is_safe_webhook_url(url):
            return jsonify({"error": "Webhook URL blocked: private/internal addresses not allowed"}), 400

    try:
        scheduler = _get_scheduler()
        job_id = scheduler.schedule_run(
            name=name,
            cron=cron,
            target_url=data.get("target_url"),
            categories=data.get("categories"),
            difficulty=data.get("difficulty"),
            scenarios=data.get("scenarios"),
            notification=notification,
            timeout=data.get("timeout", 30),
            enabled=data.get("enabled", True),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    _audit("create_schedule", f"job={job_id} name={name} cron={cron}")
    return jsonify({"job_id": job_id, "status": "created"})


@dungeon_bp.route("/api/dungeon/schedule", methods=["GET"])
@_require_api_key
def list_schedules():
    """List all scheduled red team jobs."""
    scheduler = _get_scheduler()
    jobs = scheduler.list_jobs()
    return jsonify({"jobs": jobs, "count": len(jobs)})


@dungeon_bp.route("/api/dungeon/schedule/<job_id>", methods=["GET"])
@_require_api_key
def get_schedule(job_id):
    """Get a scheduled job by ID."""
    if not job_id.replace("-", "").isalnum():
        return jsonify({"error": "Invalid job ID"}), 400

    scheduler = _get_scheduler()
    job = scheduler.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@dungeon_bp.route("/api/dungeon/schedule/<job_id>", methods=["PUT"])
@_require_api_key
def update_schedule(job_id):
    """Update a scheduled job."""
    if not job_id.replace("-", "").isalnum():
        return jsonify({"error": "Invalid job ID"}), 400

    data = request.get_json(silent=True) or {}

    # Validate webhook URL on update too
    notification = data.get("notification")
    if notification and notification.get("type") == "webhook":
        url = notification.get("url", "")
        if url and not _is_safe_webhook_url(url):
            return jsonify({"error": "Webhook URL blocked: private/internal addresses not allowed"}), 400

    scheduler = _get_scheduler()

    try:
        job = scheduler.update_job(job_id, **data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@dungeon_bp.route("/api/dungeon/schedule/<job_id>", methods=["DELETE"])
@_require_api_key
def delete_schedule(job_id):
    """Delete a scheduled job."""
    if not job_id.replace("-", "").isalnum():
        return jsonify({"error": "Invalid job ID"}), 400

    scheduler = _get_scheduler()
    if scheduler.cancel_job(job_id):
        _audit("delete_schedule", f"job={job_id}")
        return jsonify({"status": "deleted", "job_id": job_id})
    return jsonify({"error": "Job not found"}), 404


@dungeon_bp.route("/api/dungeon/schedule/<job_id>/run", methods=["POST"])
@_require_api_key
def trigger_schedule(job_id):
    """Trigger a scheduled job to run immediately."""
    if not job_id.replace("-", "").isalnum():
        return jsonify({"error": "Invalid job ID"}), 400

    _audit("trigger_schedule", f"job={job_id}")

    scheduler = _get_scheduler()
    job = scheduler.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    run_id = scheduler.run_now(job_id=job_id)
    return jsonify({"run_id": run_id, "status": "started", "job_id": job_id})


@dungeon_bp.route("/api/dungeon/schedule/history", methods=["GET"])
@_require_api_key
def schedule_history():
    """Get run history for scheduled jobs."""
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
    except (ValueError, TypeError):
        limit = 50

    scheduler = _get_scheduler()
    history = scheduler.get_history(limit=limit)
    return jsonify({"runs": history, "count": len(history)})
