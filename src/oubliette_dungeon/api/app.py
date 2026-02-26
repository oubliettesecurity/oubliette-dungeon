"""Flask app factory for Oubliette Dungeon API."""

import os
from flask import Flask, send_from_directory
from oubliette_dungeon.api.middleware import dungeon_bp, set_unified_storage


def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)

    if config:
        app.config.update(config)

    # Register the dungeon blueprint
    app.register_blueprint(dungeon_bp)

    # Serve React dashboard static files
    # Check common locations: relative to project root, or via DUNGEON_DASHBOARD_DIR env
    dashboard_dir = os.environ.get('DUNGEON_DASHBOARD_DIR', '')
    if not dashboard_dir or not os.path.isdir(dashboard_dir):
        # Walk up from this file to find the project root's dashboard/dist
        _here = os.path.dirname(os.path.abspath(__file__))
        for _up in [
            os.path.join(_here, '..', '..', '..', '..', 'dashboard', 'dist'),  # src layout
            os.path.join(_here, '..', '..', 'dashboard', 'dist'),              # installed
            os.path.join(os.getcwd(), 'dashboard', 'dist'),                     # cwd
        ]:
            _candidate = os.path.normpath(_up)
            if os.path.isdir(_candidate):
                dashboard_dir = _candidate
                break
        else:
            dashboard_dir = os.path.normpath(os.path.join(os.getcwd(), 'dashboard', 'dist'))

    @app.route('/')
    @app.route('/<path:path>')
    def serve_dashboard(path=''):
        if path and os.path.exists(os.path.join(dashboard_dir, path)):
            return send_from_directory(dashboard_dir, path)
        index = os.path.join(dashboard_dir, 'index.html')
        if os.path.exists(index):
            return send_from_directory(dashboard_dir, 'index.html')
        return {"message": "Oubliette Dungeon API", "version": "1.0.0"}

    return app
