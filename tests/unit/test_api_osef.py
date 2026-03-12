"""
Tests for the OSEF API endpoints.
"""

import json

import pytest

from flask import Flask
from oubliette_dungeon.api import dungeon_bp
import oubliette_dungeon.api.middleware as mw


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create a Flask test client with isolated DB directory."""
    monkeypatch.setattr(mw, "RESULTS_DB_DIR", str(tmp_path))
    monkeypatch.setattr(mw, "_results_db", None)
    monkeypatch.setattr(mw, "_unified_storage", None)

    app = Flask(__name__)
    app.register_blueprint(dungeon_bp)
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client


class TestOSEFLatest:

    def test_no_sessions(self, client):
        resp = client.get("/api/dungeon/osef/latest")
        assert resp.status_code == 404
        assert "No sessions" in resp.get_json()["error"]


class TestOSEFSession:

    def test_invalid_session_id(self, client):
        resp = client.get("/api/dungeon/osef/bad!id@here")
        assert resp.status_code == 400

    def test_session_not_found(self, client):
        resp = client.get("/api/dungeon/osef/nonexistent_session")
        assert resp.status_code == 404


class TestOSEFValidate:

    def test_empty_body(self, client):
        resp = client.post(
            "/api/dungeon/osef/validate",
            data="",
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_valid_document(self, client):
        doc = {
            "osef_version": "1.0.0",
            "tool": "oubliette-dungeon",
            "model_id": "test",
            "timestamp": "2026-03-12T00:00:00Z",
            "aggregate": {
                "total_scenarios": 10,
                "overall_detection_rate": 0.8,
                "overall_bypass_rate": 0.1,
            },
            "results": [
                {
                    "scenario_id": "ATK-001",
                    "result": "detected",
                    "confidence": 0.95,
                    "framework_mappings": {"owasp": ["LLM01"]},
                }
            ],
            "framework_coverage": {"owasp_llm_top_10": {}},
        }
        resp = client.post(
            "/api/dungeon/osef/validate",
            json=doc,
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["valid"] is True
        assert data["errors"] == []

    def test_missing_fields(self, client):
        doc = {"osef_version": "1.0.0"}
        resp = client.post(
            "/api/dungeon/osef/validate",
            json=doc,
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["valid"] is False
        assert len(data["errors"]) > 0
        assert any("aggregate" in e for e in data["errors"])

    def test_invalid_aggregate(self, client):
        doc = {
            "osef_version": "1.0.0",
            "tool": "test",
            "model_id": "test",
            "timestamp": "now",
            "aggregate": {"total_scenarios": 1},  # missing required fields
            "results": [],
            "framework_coverage": {},
        }
        resp = client.post(
            "/api/dungeon/osef/validate",
            json=doc,
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["valid"] is False
        assert any("overall_detection_rate" in e for e in data["errors"])

    def test_invalid_results_type(self, client):
        doc = {
            "osef_version": "1.0.0",
            "tool": "test",
            "model_id": "test",
            "timestamp": "now",
            "aggregate": {
                "total_scenarios": 0,
                "overall_detection_rate": 0,
                "overall_bypass_rate": 0,
            },
            "results": "not_a_list",
            "framework_coverage": {},
        }
        resp = client.post(
            "/api/dungeon/osef/validate",
            json=doc,
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["valid"] is False
        assert any("list" in e for e in data["errors"])
