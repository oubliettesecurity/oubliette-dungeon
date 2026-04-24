"""MED-9 regression (2026-04-22 audit): the Dungeon dashboard previously
sent no X-API-Key header, forcing the hosted /demo to run with
FLASK_ENV=development (auth off). The fix is server-side <meta> tag
injection that the SPA reads at load time. Confirm that:

1. When a dashboard API key is configured, serving the SPA produces an
   HTML response with the operator key embedded as a meta tag.
2. When the key is unset (dev mode), the tag is still present but empty
   so the client doesn't send a bogus header.
3. Key values with HTML-unsafe characters are escaped -- no raw ``<``,
   ``"``, or ``&`` into the attribute.
"""

import os

import pytest

from oubliette_dungeon.api.app import _html_escape, create_app


@pytest.fixture
def dashboard_dir(tmp_path):
    """Minimal dashboard/dist with a real index.html so serve_dashboard
    exercises the meta-injection branch instead of the fallback JSON."""
    d = tmp_path / "dashboard-dist"
    d.mkdir()
    (d / "index.html").write_text(
        "<!doctype html><html><head><title>t</title></head><body>x</body></html>",
        encoding="utf-8",
    )
    return d


@pytest.fixture
def client(dashboard_dir, monkeypatch):
    monkeypatch.setenv("DUNGEON_DASHBOARD_DIR", str(dashboard_dir))
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setenv("OUBLIETTE_API_KEY", "secret-demo-key")
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestDashboardMetaInjection:
    def test_index_contains_meta_tag_with_key(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert 'name="oubliette-api-key"' in html
        assert 'content="secret-demo-key"' in html

    def test_dashboard_subroute_also_injects(self, client):
        # SPA routes like /scenarios, /results/foo all fall through to
        # the index handler and must also receive the meta tag.
        resp = client.get("/scenarios")
        assert resp.status_code == 200
        assert 'name="oubliette-api-key"' in resp.data.decode()

    def test_unset_key_yields_empty_content(self, dashboard_dir, monkeypatch):
        monkeypatch.setenv("DUNGEON_DASHBOARD_DIR", str(dashboard_dir))
        monkeypatch.delenv("OUBLIETTE_API_KEY", raising=False)
        monkeypatch.delenv("OUBLIETTE_DASHBOARD_API_KEY", raising=False)
        monkeypatch.setenv("FLASK_ENV", "development")
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as c:
            resp = c.get("/")
        html = resp.data.decode()
        assert 'name="oubliette-api-key"' in html
        assert 'content=""' in html

    def test_separate_dashboard_key_overrides_server_key(
        self, dashboard_dir, monkeypatch
    ):
        """OUBLIETTE_DASHBOARD_API_KEY lets operators hand the dashboard a
        different key than the one the CLI / CI uses -- so a browser-
        facing key can be rotated independently of automation keys."""
        monkeypatch.setenv("DUNGEON_DASHBOARD_DIR", str(dashboard_dir))
        monkeypatch.setenv("FLASK_ENV", "development")
        monkeypatch.setenv("OUBLIETTE_API_KEY", "cli-key")
        monkeypatch.setenv("OUBLIETTE_DASHBOARD_API_KEY", "browser-key")
        app = create_app()
        app.config["TESTING"] = True
        with app.test_client() as c:
            resp = c.get("/")
        html = resp.data.decode()
        assert 'content="browser-key"' in html
        assert "cli-key" not in html

    def test_html_escape_prevents_attribute_breakout(self):
        """If an operator sets an API key with HTML-unsafe chars (shouldn't
        happen, but the server must not be the party that creates a XSS
        bug). Attribute-breakout characters must be escaped."""
        key = 'abc"><script>alert(1)</script>'
        escaped = _html_escape(key)
        assert "<script>" not in escaped
        assert '"' not in escaped

    def test_cache_control_no_store_on_injected_index(self, client):
        """Injected HTML must not be cached -- otherwise a key rotation
        leaves stale keys in browser caches."""
        resp = client.get("/")
        assert resp.headers.get("Cache-Control") == "no-store"
