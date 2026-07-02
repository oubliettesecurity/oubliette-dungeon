"""
Regression tests for the 2026-07-02 security review.

Covers:
  1. [HIGH] Concurrent per-session saves must not drop results
     (threading.Lock + atomic replace) and session IDs must not collide
     at second granularity.
  2. [HIGH] OSEF / PDF routes must scope reads to the caller's API key
     (cross-caller data access).
  3. [MED]  Multi-turn executors must populate self._last_meta so CAT-07
     scenarios get the pipeline-verdict / honey-token shortcut.
  4. [LOW]  requests.Session objects must be closeable (no leaks).
"""

import threading
import time
from unittest.mock import Mock, patch

import pytest
from flask import Flask

import oubliette_dungeon.api.middleware as mw
from oubliette_dungeon.api import dungeon_bp
from oubliette_dungeon.core import AttackExecutor, RedTeamOrchestrator
from oubliette_dungeon.core.offline import OfflineExecutor
from oubliette_dungeon.storage import RedTeamResultsDB


# ---------------------------------------------------------------------------
# Fix 1 -- concurrent saves + session-id collision surface
# ---------------------------------------------------------------------------


def test_concurrent_saves_do_not_drop_results(temp_db_dir, monkeypatch, sample_result):
    """Many threads saving to the same session must not lose any result.

    A non-atomic read-modify-write with no lock silently drops results
    when writes interleave. We widen the race window by slowing the read
    so the failure is deterministic without the fix.
    """
    db = RedTeamResultsDB(temp_db_dir)
    # Seed the session so every worker hits the read-modify-write branch.
    db.save_result(dict(sample_result, scenario_id="SEED"), "race-session")

    import oubliette_dungeon.storage.json_file as jf

    real_load = jf.json.load

    def slow_load(f):
        data = real_load(f)
        time.sleep(0.01)
        return data

    monkeypatch.setattr(jf.json, "load", slow_load)

    n = 20
    barrier = threading.Barrier(n)

    def worker(i):
        barrier.wait()
        db.save_result(dict(sample_result, scenario_id=f"ATK-{i:03d}"), "race-session")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    monkeypatch.setattr(jf.json, "load", real_load)
    session = db.get_session("race-session")
    assert len(session["results"]) == n + 1  # seed + n workers, none dropped


def test_session_ids_are_unique_within_same_second():
    """Two orchestrators created back-to-back must not collide on session id."""
    ids = {
        RedTeamOrchestrator("http://test.local/api/chat").current_session_id
        for _ in range(50)
    }
    assert len(ids) == 50


# ---------------------------------------------------------------------------
# Fix 2 -- per-API-key scoping on OSEF / PDF routes
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setattr(mw, "RESULTS_DB_DIR", str(tmp_path))
    monkeypatch.setattr(mw, "_results_db", None)
    monkeypatch.setattr(mw, "_unified_storage", None)

    app = Flask(__name__)
    app.register_blueprint(dungeon_bp)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c, str(tmp_path)


def _seed_owned_session(db_dir, session_id, sample_result):
    """Create a session owned by a concrete (non-anon) key hint."""
    db = RedTeamResultsDB(db_dir)
    db.save_result(
        dict(sample_result, result="bypass"),
        session_id,
        caller_key_hint="owner-key-hint",
    )


def test_osef_latest_scoped_to_caller(client, sample_result):
    c, db_dir = client
    _seed_owned_session(db_dir, "owned_session", sample_result)
    # Anonymous caller (no X-API-Key) has hint "__anon__" != owner -> 404.
    resp = c.get("/api/dungeon/osef/latest")
    assert resp.status_code == 404


def test_osef_for_session_scoped_to_caller(client, sample_result):
    c, db_dir = client
    _seed_owned_session(db_dir, "owned_session", sample_result)
    resp = c.get("/api/dungeon/osef/owned_session")
    assert resp.status_code == 404


def test_export_pdf_scoped_to_caller(client, sample_result):
    c, db_dir = client
    _seed_owned_session(db_dir, "owned_session", sample_result)
    resp = c.get("/api/dungeon/results/owned_session/pdf")
    # 404 (not yours) -- must NOT return the other caller's PDF (200) or 503.
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Fix 3 -- multi-turn _last_meta aggregation
# ---------------------------------------------------------------------------


def test_online_multi_turn_aggregates_meta(multi_turn_scenario):
    executor = AttackExecutor(target_url="http://test.local/api/chat")

    def mk(honey, verdict, ml, llm):
        r = Mock()
        r.status_code = 200
        r.json.return_value = {
            "response": "ok",
            "contains_honey_token": honey,
            "verdict": verdict,
            "ml_score": ml,
            "llm_verdict": llm,
        }
        return r

    turns = [
        mk(False, "SAFE", 0.1, "safe"),
        mk(True, "MALICIOUS", 0.9, "unsafe"),
        mk(False, "SAFE_REVIEW", 0.5, "review"),
    ]
    with patch.object(executor.session, "post", side_effect=turns), patch("time.sleep"):
        executor.execute(multi_turn_scenario)

    meta = executor.get_last_meta()
    assert meta.get("contains_honey_token") is True  # OR across turns
    assert meta.get("verdict") == "MALICIOUS"  # most severe
    assert meta.get("ml_score") == 0.9  # max


def test_offline_multi_turn_sets_meta(multi_turn_scenario):
    executor = OfflineExecutor(model="llama3")

    def mk(honey, verdict):
        r = Mock()
        r.status_code = 200
        r.json.return_value = {
            "message": {"content": "ok"},
            "contains_honey_token": honey,
            "verdict": verdict,
        }
        return r

    turns = [mk(False, "SAFE"), mk(True, "MALICIOUS")]
    with patch("oubliette_dungeon.core.offline.requests.post", side_effect=turns):
        executor.execute(multi_turn_scenario)

    meta = executor.get_last_meta()
    assert meta.get("contains_honey_token") is True
    assert meta.get("verdict") == "MALICIOUS"


# ---------------------------------------------------------------------------
# Fix 4 -- session resources are closeable
# ---------------------------------------------------------------------------


def test_executor_close_closes_session():
    executor = AttackExecutor(target_url="http://test.local/api/chat")
    with patch.object(executor.session, "close") as mock_close:
        executor.close()
        mock_close.assert_called_once()


def test_pyrit_target_close_closes_session():
    from oubliette_dungeon.tools.pyrit_adapter import OubliettePromptTarget

    target = OubliettePromptTarget("http://test.local/api/chat")
    with patch.object(target._session, "close") as mock_close:
        target.close()
        mock_close.assert_called_once()
