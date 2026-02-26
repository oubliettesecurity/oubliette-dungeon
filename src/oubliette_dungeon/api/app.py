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
    dashboard_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'dashboard', 'dist')
    dashboard_dir = os.path.normpath(dashboard_dir)

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
