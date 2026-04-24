"""Flask app factory for Oubliette Dungeon API."""

import os

from flask import Flask, request, send_from_directory

from oubliette_dungeon.api.middleware import dungeon_bp, set_unified_storage

__all__ = ["create_app", "dungeon_bp", "set_unified_storage"]


def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)

    if config:
        app.config.update(config)

    # MED-8 fix (2026-04-22 audit): on Fly.io (and any PaaS that terminates
    # TLS in a proxy) ``request.remote_addr`` is the proxy's IP, not the
    # client's -- so the rate limiter keyed every user into a single bucket
    # and legitimate users could DoS each other. Enable ProxyFix only when
    # ``DUNGEON_TRUSTED_PROXY=true`` is set explicitly, so we do not trust
    # upstream headers on deployments that are NOT behind a proxy.
    if os.getenv("DUNGEON_TRUSTED_PROXY", "").lower() == "true":
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Register the dungeon blueprint
    app.register_blueprint(dungeon_bp)

    # CORS and security headers
    @app.after_request
    def add_security_headers(response):
        # CORS - restrict to same origin by default
        cors_env = os.getenv("DUNGEON_CORS_ORIGINS", "")
        allowed_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
        origin = request.headers.get("Origin", "")
        if origin and allowed_origins and origin in allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Vary"] = "Origin"
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # Serve React dashboard static files
    # Check common locations: relative to project root, or via DUNGEON_DASHBOARD_DIR env
    dashboard_dir = os.environ.get("DUNGEON_DASHBOARD_DIR", "")
    if not dashboard_dir or not os.path.isdir(dashboard_dir):
        # Walk up from this file to find the project root's dashboard/dist
        _here = os.path.dirname(os.path.abspath(__file__))
        for _up in [
            os.path.join(_here, "..", "..", "..", "..", "dashboard", "dist"),  # src layout
            os.path.join(_here, "..", "..", "dashboard", "dist"),  # installed
            os.path.join(os.getcwd(), "dashboard", "dist"),  # cwd
        ]:
            _candidate = os.path.normpath(_up)
            if os.path.isdir(_candidate):
                dashboard_dir = _candidate
                break
        else:
            dashboard_dir = os.path.normpath(os.path.join(os.getcwd(), "dashboard", "dist"))

    @app.route("/")
    @app.route("/<path:path>")
    def serve_dashboard(path=""):
        if path and os.path.exists(os.path.join(dashboard_dir, path)):
            return send_from_directory(dashboard_dir, path)
        index = os.path.join(dashboard_dir, "index.html")
        if os.path.exists(index):
            # MED-9 fix (2026-04-22 audit): the React dashboard historically
            # fetched the API with no X-API-Key header, so the /demo
            # deployment was forced into FLASK_ENV=development (auth off)
            # to function at all -- shipping an "AI security" product
            # with its own auth disabled. Inject the configured API key
            # into the HTML via a <meta> tag so the SPA can read it at
            # load time and attach it to every request. The key is only
            # sent when the index is served by this server (same-origin),
            # so a third-party site can't trigger the meta injection.
            try:
                with open(index, encoding="utf-8") as fh:
                    html = fh.read()
            except OSError:
                return send_from_directory(dashboard_dir, "index.html")

            api_key = os.getenv("OUBLIETTE_DASHBOARD_API_KEY") or os.getenv(
                "OUBLIETTE_API_KEY", ""
            )
            meta_tag = (
                '<meta name="oubliette-api-key" content="'
                + _html_escape(api_key)
                + '">'
            )
            if "</head>" in html:
                html = html.replace("</head>", f"    {meta_tag}\n  </head>", 1)
            else:
                html = meta_tag + html
            response = app.make_response(html)
            response.headers["Content-Type"] = "text/html; charset=utf-8"
            # Same Cache-Control the static file handler uses, so the meta
            # tag refreshes when the operator rotates the key.
            response.headers["Cache-Control"] = "no-store"
            return response
        return {"message": "Oubliette Dungeon API", "version": "1.0.0"}

    return app


def _html_escape(value: str) -> str:
    """Escape a string for safe inclusion in an HTML attribute value."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
