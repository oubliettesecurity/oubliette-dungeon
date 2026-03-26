"""
Tests for the comparison API endpoints.
"""

import json
import os
import tempfile

import pytest

from flask import Flask
from oubliette_dungeon.api import dungeon_bp
import oubliette_dungeon.api.middleware as mw
import oubliette_dungeon.api.routes.comparisons as comp_mod


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create a Flask test client with isolated DB directory."""
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setattr(mw, "RESULTS_DB_DIR", str(tmp_path))
    monkeypatch.setattr(comp_mod, "RESULTS_DB_DIR", str(tmp_path))
    monkeypatch.setattr(mw, "_running_session", None)

    app = Flask(__name__)
    app.register_blueprint(dungeon_bp)
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client


class TestListComparisons:

    def test_empty_list(self, client):
        resp = client.get("/api/dungeon/comparisons")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 0
        assert data["comparisons"] == []

    def test_list_with_saved_comparison(self, client, tmp_path):
        cdir = tmp_path / "comparisons"
        cdir.mkdir()
        report = {
            "timestamp": "2026-03-12T00:00:00Z",
            "model_count": 2,
            "ranking": [
                {"model_id": "model_a"},
                {"model_id": "model_b"},
            ],
            "status": "complete",
        }
        (cdir / "comparison_test123.json").write_text(json.dumps(report))

        resp = client.get("/api/dungeon/comparisons")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["comparisons"][0]["comparison_id"] == "test123"
        assert data["comparisons"][0]["model_count"] == 2
        assert data["comparisons"][0]["status"] == "complete"


class TestGetComparison:

    def test_not_found(self, client):
        resp = client.get("/api/dungeon/comparisons/nonexistent")
        assert resp.status_code == 404

    def test_invalid_id(self, client):
        resp = client.get("/api/dungeon/comparisons/bad!id@here")
        assert resp.status_code == 400

    def test_get_existing(self, client, tmp_path):
        cdir = tmp_path / "comparisons"
        cdir.mkdir()
        report = {
            "comparison_id": "abc123",
            "model_count": 3,
            "ranking": [],
            "status": "complete",
        }
        (cdir / "comparison_abc123.json").write_text(json.dumps(report))

        resp = client.get("/api/dungeon/comparisons/abc123")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["comparison_id"] == "abc123"
        assert data["model_count"] == 3


class TestRunComparison:

    def test_missing_models(self, client):
        resp = client.post(
            "/api/dungeon/comparisons/run",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "model" in resp.get_json()["error"].lower()

    def test_single_model_rejected(self, client):
        resp = client.post(
            "/api/dungeon/comparisons/run",
            json={"models": ["only_one"]},
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "2" in resp.get_json()["error"]

    def test_too_many_models(self, client):
        resp = client.post(
            "/api/dungeon/comparisons/run",
            json={"models": [f"m{i}" for i in range(11)]},
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "10" in resp.get_json()["error"]

    def test_conflict_when_session_running(self, client, monkeypatch):
        monkeypatch.setattr(mw, "_running_session", "existing_session")
        resp = client.post(
            "/api/dungeon/comparisons/run",
            json={"models": ["a", "b"]},
            content_type="application/json",
        )
        assert resp.status_code == 409

    def test_valid_run_starts(self, client, tmp_path):
        resp = client.post(
            "/api/dungeon/comparisons/run",
            json={"models": ["model_a", "model_b"]},
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "started"
        assert len(data["models"]) == 2
        assert "comparison_id" in data
