"""
Dungeon API Middleware
Blueprint creation, rate limiter, auth, audit, unified storage adapter,
and helper functions for the Oubliette Dungeon REST API.

All URL prefixes use /api/dungeon/ instead of /api/redteam/.
"""

import functools
import hashlib
import hmac
import logging
import os
import threading
import time
from typing import Any

from flask import Blueprint, Response, g, jsonify, request
from oubliette_sec_utils import is_ip_safe as _shared_is_ip_safe
from oubliette_sec_utils import validate_outbound_url

from oubliette_dungeon.core import (
    ScenarioLoader,
    _default_scenarios_path,
)
from oubliette_dungeon.storage import RedTeamResultsDB

dungeon_bp = Blueprint("dungeon", __name__)

# --- Config ---
SCENARIOS_FILE = _default_scenarios_path()
DEFAULT_TIMEOUT = int(os.getenv("DUNGEON_TIMEOUT", "30"))
RESULTS_DB_DIR = os.getenv("DUNGEON_DB_DIR", "redteam_results")

# Max request body size (1 MB)
MAX_CONTENT_LENGTH = int(os.getenv("DUNGEON_MAX_CONTENT_LENGTH", str(1 * 1024 * 1024)))

# --- Audit Logger ---
_audit_log = logging.getLogger("oubliette.dungeon.audit")
_audit_log.setLevel(logging.INFO)
if not _audit_log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("[AUDIT] %(asctime)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    )
    _audit_log.addHandler(_handler)


def _audit(action: str, detail: str = "") -> None:
    """Log an audit event with the client IP and action."""
    ip = request.remote_addr or "unknown"
    api_key_hint = ""
    key = request.headers.get("X-API-Key", "")
    if key:
        api_key_hint = f" key=...{key[-4:]}" if len(key) >= 4 else " key=***"
    _audit_log.info("ip=%s%s action=%s %s", ip, api_key_hint, action, detail)


# --- Rate Limiter ---
_rate_limit_store: dict[str, list[float]] = {}
_rate_limit_lock = threading.Lock()

# Defaults: 30 requests per 60 seconds per IP
RATE_LIMIT_MAX = int(os.getenv("DUNGEON_RATE_LIMIT_MAX", "30"))
RATE_LIMIT_WINDOW = int(os.getenv("DUNGEON_RATE_LIMIT_WINDOW", "60"))

# Stale entry cleanup: run every N requests
_rate_limit_request_counter = 0
_RATE_LIMIT_CLEANUP_INTERVAL = 500


def _check_rate_limit() -> Response | None:
    """Return a 429 Response if the client has exceeded the rate limit, else None."""
    global _rate_limit_request_counter

    if RATE_LIMIT_MAX <= 0:
        return None  # disabled

    ip = request.remote_addr or "unknown"
    now = time.time()

    with _rate_limit_lock:
        _rate_limit_request_counter += 1

        # Periodic cleanup of stale entries
        if _rate_limit_request_counter >= _RATE_LIMIT_CLEANUP_INTERVAL:
            _rate_limit_request_counter = 0
            cutoff = now - RATE_LIMIT_WINDOW
            stale_ips = [k for k, v in _rate_limit_store.items() if not v or v[-1] < cutoff]
            for k in stale_ips:
                del _rate_limit_store[k]

        timestamps = _rate_limit_store.setdefault(ip, [])
        # Prune old timestamps
        cutoff = now - RATE_LIMIT_WINDOW
        timestamps[:] = [t for t in timestamps if t > cutoff]

        if len(timestamps) >= RATE_LIMIT_MAX:
            return jsonify({"error": "Rate limit exceeded"}), 429

        timestamps.append(now)

    return None


# --- Request Size Limit ---


@dungeon_bp.before_request
def _enforce_limits():
    """Enforce request body size limit and rate limiting."""
    # Size limit
    content_length = request.content_length
    if content_length is not None and content_length > MAX_CONTENT_LENGTH:
        return jsonify({"error": "Request body too large"}), 413

    # Rate limit
    rate_resp = _check_rate_limit()
    if rate_resp is not None:
        return rate_resp


# --- Unified storage backend (optional, set by oubliette_security.py) ---
_unified_storage = None


def set_unified_storage(backend):
    """Set a unified StorageBackend for red team operations.

    When set, red team results are stored via the unified backend
    (typically SQLiteBackend -> oubliette.db) instead of RedTeamResultsDB.
    """
    global _unified_storage
    _unified_storage = backend


# --- Lazy singletons ---
_loader = None
_results_db = None
_init_lock = threading.Lock()

# Track running sessions to prevent concurrent runs
_running_session = None
_session_lock = threading.Lock()


def _get_loader():
    global _loader
    if _loader is None:
        with _init_lock:
            if _loader is None:
                _loader = ScenarioLoader(SCENARIOS_FILE)
    return _loader


def _get_results_db():
    """Return the unified backend if set, otherwise fall back to RedTeamResultsDB."""
    if _unified_storage is not None:
        return _UnifiedStorageAdapter(_unified_storage)
    global _results_db
    if _results_db is None:
        with _init_lock:
            if _results_db is None:
                _results_db = RedTeamResultsDB(RESULTS_DB_DIR)
    return _results_db


class _UnifiedStorageAdapter:
    """Adapts a StorageBackend to the RedTeamResultsDB interface.

    Lets the rest of the dungeon API call the same methods it always has
    (save_result, get_session, list_sessions, get_statistics, etc.) while
    routing everything through the unified StorageBackend.
    """

    def __init__(self, backend):
        self._b = backend

    def save_result(self, result, session_id, caller_key_hint=None):
        payload = result if isinstance(result, dict) else vars(result)
        # The unified backend does not expose a caller_key_hint arg yet.
        # Stash the hint on the payload so a future backend migration
        # (multi-tenant SQL) can pull it off the record instead of a new
        # signature.
        if caller_key_hint is not None:
            payload = {**payload, "_caller_key_hint": caller_key_hint}
        self._b.save_redteam_result(payload, session_id)

    def get_session(self, session_id, caller_key_hint=None):
        data = self._b.get_redteam_session(session_id)
        if data is None:
            return None
        if caller_key_hint is not None and data.get("created_by_key_hint") != caller_key_hint:
            return None
        return data

    def list_sessions(self, caller_key_hint=None):
        sessions = self._b.list_redteam_sessions()
        if caller_key_hint is None:
            return sessions
        return [s for s in sessions if s.get("created_by_key_hint") == caller_key_hint]

    def get_latest_session(self, caller_key_hint=None):
        sessions = self.list_sessions(caller_key_hint=caller_key_hint)
        if not sessions:
            return None
        return self.get_session(sessions[0]["session_id"], caller_key_hint=caller_key_hint)

    def get_statistics(self, session_id=None):
        return self._b.get_redteam_statistics(session_id)

    def delete_session(self, session_id):
        return self._b.delete_redteam_session(session_id)

    def cleanup_old_sessions(self, keep_latest=10):
        return self._b.cleanup_old_redteam_sessions(keep_latest)


def _is_ip_safe(addr) -> bool:
    """Return True if ``addr`` is a safe outbound IP literal.

    Thin wrapper over :func:`oubliette_sec_utils.is_ip_safe` kept for
    backward compatibility with existing tests and callers. The upstream
    helper returns ``False`` for non-IP strings (it does not raise), so
    callers that previously relied on a ``ValueError`` fallthrough should
    check ``ipaddress.ip_address`` themselves.
    """
    return _shared_is_ip_safe(addr)


def _is_safe_webhook_url(url: str) -> bool:
    """Validate a webhook URL to prevent SSRF attacks.

    Delegates to :func:`oubliette_sec_utils.validate_outbound_url` which
    applies the full internal-host / private-IP / DNS-rebinding checklist.
    """
    return validate_outbound_url(url).safe


def _validate_target_url(url: str) -> tuple[bool, str]:
    """Validate a target URL to prevent SSRF attacks.

    Returns ``(is_safe, error_message)`` for use in API endpoint
    validation. Set ``DUNGEON_ALLOW_PRIVATE_TARGETS=true`` to bypass all
    checks for local development.
    """
    if os.getenv("DUNGEON_ALLOW_PRIVATE_TARGETS", "").lower() == "true":
        return True, ""

    if not url:
        return False, "target_url is required"

    decision = validate_outbound_url(url)
    return decision.safe, decision.reason


# Per-process salt for caller-key hints. Rotating this is equivalent to
# invalidating every recorded ``created_by_key_hint`` (sessions become
# orphan-owned). Read from an env var so a persistent deployment can pin
# it; otherwise generate one at import so single-process test runs stay
# internally consistent.
_CALLER_HINT_SALT = os.getenv("DUNGEON_CALLER_HINT_SALT") or os.urandom(32).hex()


def _caller_key_hint() -> str:
    """Stable hint identifying the caller of the current request.

    Returns an HMAC-based hint of the presented ``X-API-Key``. Two
    requests carrying the same key get the same hint; the hint is not
    reversible to the key (pepper + SHA-256 truncation) so leaking it
    via logs / session index is safe. Unauthenticated requests (dev
    mode only) return the sentinel ``"__anon__"``.

    MED-11 fix (2026-04-22 audit): the storage layer keys every session
    on this hint so list/get/report reads only surface sessions authored
    by the calling key. Forward-compat with the multi-tenant direction:
    today there's a single shared API key so all hints collapse to one
    value, but the scoping is in place for when that changes.
    """
    key = request.headers.get("X-API-Key", "") if request else ""
    if not key:
        return "__anon__"
    # HMAC-SHA256 truncated to 16 hex chars is plenty for a session tag;
    # the full digest would bloat every index row.
    digest = hmac.new(_CALLER_HINT_SALT.encode(), key.encode(), hashlib.sha256).hexdigest()
    return digest[:16]


def _require_api_key(f):
    """Require API key authentication.

    When OUBLIETTE_API_KEY is not set:
    - In development (FLASK_ENV=development): allow unauthenticated access
    - In production: return 401 with helpful error message

    On success, stashes the caller's key hint on ``flask.g.caller_key_hint``
    so downstream routes can scope storage reads to the authoring key.
    """

    @functools.wraps(f)
    def decorated(*args, **kwargs):
        api_key = os.getenv("OUBLIETTE_API_KEY", "")
        if not api_key:
            flask_env = os.getenv("FLASK_ENV", "production")
            if flask_env == "development":
                g.caller_key_hint = _caller_key_hint()
                return f(*args, **kwargs)
            return jsonify(
                {
                    "error": "API key not configured. Set OUBLIETTE_API_KEY environment variable.",
                }
            ), 401
        key = request.headers.get("X-API-Key", "")
        if not key or not hmac.compare_digest(key.encode(), api_key.encode()):
            return jsonify({"error": "Unauthorized"}), 401
        g.caller_key_hint = _caller_key_hint()
        return f(*args, **kwargs)

    return decorated


def _warn_no_api_key():
    """Log a warning at startup if no API key is configured in production."""
    api_key = os.getenv("OUBLIETTE_API_KEY", "")
    flask_env = os.getenv("FLASK_ENV", "production")
    if not api_key and flask_env != "development":
        logging.getLogger("oubliette.dungeon").warning(
            "SECURITY WARNING: No OUBLIETTE_API_KEY set in non-development mode. "
            "All API endpoints will reject requests. "
            "Set OUBLIETTE_API_KEY or FLASK_ENV=development."
        )


# Emit startup warning
_warn_no_api_key()


def _scenario_to_dict(scenario) -> dict[str, Any]:
    """Convert AttackScenario to API-safe dict."""
    return {
        "id": scenario.id,
        "name": scenario.name,
        "category": scenario.category,
        "difficulty": scenario.difficulty,
        "description": scenario.description,
        "owasp_mapping": scenario.owasp_mapping,
        "mitre_mapping": scenario.mitre_mapping,
        "prompt": scenario.prompt,
        "multi_turn": scenario.multi_turn_prompts is not None,
        "expected_behavior": scenario.expected_behavior,
    }


def _result_to_dict(result) -> dict[str, Any]:
    """Convert AttackTestResult to API-safe dict."""
    if hasattr(result, "__dict__"):
        d = vars(result) if not hasattr(result, "to_dict") else result
        if isinstance(d, dict):
            return d
        return vars(result)
    return result


# --- Scheduler singleton ---
_scheduler = None
_scheduler_init_lock = threading.Lock()


def _get_scheduler():
    global _scheduler
    if _scheduler is None:
        with _scheduler_init_lock:
            if _scheduler is None:
                from oubliette_dungeon.scheduler import get_scheduler

                _scheduler = get_scheduler()
    return _scheduler


# --- Tool Manager singleton ---
_tool_manager = None
_tool_manager_lock = threading.Lock()


def _get_tool_manager():
    global _tool_manager
    if _tool_manager is None:
        with _tool_manager_lock:
            if _tool_manager is None:
                from oubliette_dungeon.tools.tool_manager import ToolManager

                _tool_manager = ToolManager(results_db=_get_results_db())
    return _tool_manager


# --- Register route modules (import at bottom to avoid circular imports) ---
import oubliette_dungeon.api.routes.comparisons  # noqa: E402
import oubliette_dungeon.api.routes.execution  # noqa: E402
import oubliette_dungeon.api.routes.osef  # noqa: E402
import oubliette_dungeon.api.routes.reports  # noqa: E402
import oubliette_dungeon.api.routes.reviews  # noqa: E402
import oubliette_dungeon.api.routes.scenarios  # noqa: E402
import oubliette_dungeon.api.routes.scheduler  # noqa: E402
import oubliette_dungeon.api.routes.sessions  # noqa: E402
import oubliette_dungeon.api.routes.tools  # noqa: E402, F401
