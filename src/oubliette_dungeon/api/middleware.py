"""
Dungeon API Middleware
Blueprint creation, rate limiter, auth, audit, unified storage adapter,
and helper functions for the Oubliette Dungeon REST API.

All URL prefixes use /api/dungeon/ instead of /api/redteam/.
"""

import ipaddress
import logging
import os
import hmac
import functools
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from flask import Blueprint, request, jsonify, Response

from oubliette_dungeon.core import (
    RedTeamOrchestrator, ScenarioLoader, AttackExecutor, ResultEvaluator,
    AttackResult, _default_scenarios_path, DEFAULT_TARGET_URL,
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
    _handler.setFormatter(logging.Formatter(
        "[AUDIT] %(asctime)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"
    ))
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
_rate_limit_store: Dict[str, List[float]] = {}
_rate_limit_lock = threading.Lock()

# Defaults: 30 requests per 60 seconds per IP
RATE_LIMIT_MAX = int(os.getenv("DUNGEON_RATE_LIMIT_MAX", "30"))
RATE_LIMIT_WINDOW = int(os.getenv("DUNGEON_RATE_LIMIT_WINDOW", "60"))

# Stale entry cleanup: run every N requests
_rate_limit_request_counter = 0
_RATE_LIMIT_CLEANUP_INTERVAL = 500


def _check_rate_limit() -> Optional[Response]:
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
            stale_ips = [
                k for k, v in _rate_limit_store.items()
                if not v or v[-1] < cutoff
            ]
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

    def save_result(self, result, session_id):
        self._b.save_redteam_result(result if isinstance(result, dict) else vars(result), session_id)

    def get_session(self, session_id):
        return self._b.get_redteam_session(session_id)

    def list_sessions(self):
        return self._b.list_redteam_sessions()

    def get_latest_session(self):
        sessions = self._b.list_redteam_sessions()
        if not sessions:
            return None
        return self._b.get_redteam_session(sessions[0]["session_id"])

    def get_statistics(self, session_id=None):
        return self._b.get_redteam_statistics(session_id)

    def delete_session(self, session_id):
        return self._b.delete_redteam_session(session_id)

    def cleanup_old_sessions(self, keep_latest=10):
        return self._b.cleanup_old_redteam_sessions(keep_latest)


def _is_ip_safe(addr) -> bool:
    """Check if an IP address is safe (not private/loopback/link-local/reserved).

    Handles IPv6-mapped IPv4 addresses (e.g., ::ffff:127.0.0.1).
    """
    ip = ipaddress.ip_address(addr)
    # Handle IPv6-mapped IPv4 (::ffff:x.x.x.x)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def _resolve_and_check(hostname: str) -> Tuple[bool, str]:
    """Resolve a hostname via DNS and verify all resolved IPs are safe.

    Returns (is_safe, error_message).
    """
    try:
        addrinfos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, f"DNS resolution failed for {hostname}: {e}"
    except Exception as e:
        return False, f"DNS resolution error for {hostname}: {e}"

    if not addrinfos:
        return False, f"No DNS results for {hostname}"

    for family, _type, _proto, _canonname, sockaddr in addrinfos:
        ip_str = sockaddr[0]
        try:
            if not _is_ip_safe(ip_str):
                return False, f"Hostname {hostname} resolves to private/reserved IP {ip_str}"
        except ValueError:
            return False, f"Invalid resolved IP: {ip_str}"

    return True, ""


def _is_safe_webhook_url(url: str) -> bool:
    """Validate a webhook URL to prevent SSRF attacks.

    Blocks:
    - Non-HTTP(S) schemes
    - Private/internal IP ranges (RFC 1918, loopback, link-local)
    - Common internal hostnames
    - DNS names that resolve to private IPs (rebinding protection)
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    # Only allow http/https
    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    # Block known internal hostnames
    blocked_hostnames = {
        "localhost", "localhost.localdomain",
        "metadata.google.internal", "169.254.169.254",
    }
    if hostname.lower() in blocked_hostnames:
        return False

    # Block obvious internal domain patterns
    lower = hostname.lower()
    if lower.endswith((".local", ".internal", ".corp", ".lan")):
        return False

    # Check if the hostname is an IP literal
    try:
        if not _is_ip_safe(hostname):
            return False
    except ValueError:
        pass  # Not an IP literal, continue to DNS resolution

    # DNS resolution check: resolve hostname and verify all IPs are safe
    is_safe, _error = _resolve_and_check(hostname)
    return is_safe


def _validate_target_url(url: str) -> Tuple[bool, str]:
    """Validate a target URL to prevent SSRF attacks.

    Similar to _is_safe_webhook_url but returns (is_safe, error_message)
    for use in API endpoint validation.

    Set DUNGEON_ALLOW_PRIVATE_TARGETS=true to allow private IPs (local dev).
    """
    # Allow private targets for local development
    if os.getenv("DUNGEON_ALLOW_PRIVATE_TARGETS", "").lower() == "true":
        return True, ""

    if not url:
        return False, "target_url is required"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"

    if parsed.scheme not in ("http", "https"):
        return False, f"Invalid URL scheme: {parsed.scheme}. Only http/https allowed."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL has no hostname"

    # Block known internal hostnames
    blocked_hostnames = {
        "localhost", "localhost.localdomain",
        "metadata.google.internal", "169.254.169.254",
    }
    if hostname.lower() in blocked_hostnames:
        return False, f"Blocked internal hostname: {hostname}"

    # Block obvious internal domain patterns
    lower = hostname.lower()
    if lower.endswith((".local", ".internal", ".corp", ".lan")):
        return False, f"Blocked internal domain: {hostname}"

    # Check if the hostname is an IP literal
    try:
        if not _is_ip_safe(hostname):
            return False, f"Blocked private/reserved IP: {hostname}"
    except ValueError:
        pass  # Not an IP literal, continue to DNS resolution

    # DNS resolution check
    is_safe, error = _resolve_and_check(hostname)
    if not is_safe:
        return False, error

    return True, ""


def _require_api_key(f):
    """Require API key authentication.

    When OUBLIETTE_API_KEY is not set:
    - In development (FLASK_ENV=development): allow unauthenticated access
    - In production: return 401 with helpful error message
    """
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        api_key = os.getenv("OUBLIETTE_API_KEY", "")
        if not api_key:
            flask_env = os.getenv("FLASK_ENV", "production")
            if flask_env == "development":
                return f(*args, **kwargs)
            return jsonify({
                "error": "API key not configured. Set OUBLIETTE_API_KEY environment variable.",
            }), 401
        key = request.headers.get("X-API-Key", "")
        if not key or not hmac.compare_digest(key.encode(), api_key.encode()):
            return jsonify({"error": "Unauthorized"}), 401
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


def _scenario_to_dict(scenario) -> Dict[str, Any]:
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


def _result_to_dict(result) -> Dict[str, Any]:
    """Convert AttackTestResult to API-safe dict."""
    if hasattr(result, '__dict__'):
        d = vars(result) if not hasattr(result, 'to_dict') else result
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
import oubliette_dungeon.api.routes.scenarios  # noqa: E402, F401
import oubliette_dungeon.api.routes.execution  # noqa: E402, F401
import oubliette_dungeon.api.routes.sessions   # noqa: E402, F401
import oubliette_dungeon.api.routes.scheduler  # noqa: E402, F401
import oubliette_dungeon.api.routes.tools      # noqa: E402, F401
import oubliette_dungeon.api.routes.reports      # noqa: E402, F401
import oubliette_dungeon.api.routes.reviews     # noqa: E402, F401
import oubliette_dungeon.api.routes.comparisons # noqa: E402, F401
import oubliette_dungeon.api.routes.osef        # noqa: E402, F401
