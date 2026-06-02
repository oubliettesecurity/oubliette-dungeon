"""
Oubliette Dungeon - Authentication/Authorization Middleware
Flask middleware for API key and Basic auth with tenant/user resolution.
"""

from __future__ import annotations

import base64
import functools
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .rbac import Permission, RBACManager
    from .tenant import TenantManager

log = logging.getLogger(__name__)


def require_auth(
    tenant_manager: TenantManager | None = None,
    rbac_manager: RBACManager | None = None,
    permission: Permission | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Flask decorator that enforces authentication and authorization.

    Supports two auth methods:

    1. **API key** -- ``X-API-Key`` header or ``Authorization: Bearer <key>``.
       Resolves a tenant via *tenant_manager*.
    2. **Basic auth** -- ``Authorization: Basic <base64>``.
       Authenticates a user via *rbac_manager*.

    On success, attaches ``g.tenant`` and/or ``g.user`` to the Flask
    request context.  On failure, returns 401 or 403.

    Usage::

        @app.route("/analyze", methods=["POST"])
        @require_auth(tenant_manager=tm, permission=Permission.ANALYZE)
        def analyze():
            tenant = g.tenant  # may be None
            user = g.user      # may be None
            ...
    """

    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                from flask import g, jsonify, request
            except ImportError as exc:
                raise RuntimeError("Flask is required for auth middleware") from exc

            g.tenant = None
            g.user = None

            auth_header = request.headers.get("Authorization", "")
            api_key_header = request.headers.get("X-API-Key", "")

            authenticated = False

            # Method 1: X-API-Key header
            if api_key_header and tenant_manager is not None:
                tenant = tenant_manager.resolve_by_api_key(api_key_header)
                if tenant is not None:
                    g.tenant = tenant
                    authenticated = True

            # Method 2: Authorization: Bearer <key>
            elif auth_header.startswith("Bearer ") and tenant_manager is not None:
                key = auth_header[7:]
                tenant = tenant_manager.resolve_by_api_key(key)
                if tenant is not None:
                    g.tenant = tenant
                    authenticated = True

            # Method 3: Authorization: Basic <base64>
            elif auth_header.startswith("Basic ") and rbac_manager is not None:
                try:
                    decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                    username, password = decoded.split(":", 1)
                    user = rbac_manager.authenticate(username, password)
                    if user is not None:
                        g.user = user
                        authenticated = True
                        # Resolve tenant for tenant-scoped users
                        if user.tenant_id and tenant_manager is not None:
                            g.tenant = tenant_manager.get_tenant(user.tenant_id)
                except (ValueError, TypeError, UnicodeDecodeError):
                    pass  # Malformed Basic auth header - fall through to 401

            # No managers configured = open access (backward compatible)
            if tenant_manager is None and rbac_manager is None:
                return f(*args, **kwargs)

            if not authenticated:
                return jsonify({"error": "Unauthorized"}), 401

            # Authorization check.
            #
            # HIGH-1 fix (2026-04-22 audit): previously a tenant API-key request
            # that arrived with ``g.user is None`` silently skipped the
            # permission decorator. That made tenant isolation porous -- any
            # valid tenant key reached any endpoint regardless of the
            # permission scope the route expected.
            #
            # New policy: if the route declares a required permission, the
            # caller MUST have an RBAC user. Tenant API keys alone are not
            # enough because they carry no per-action authorization. Routes
            # that want to be reachable with only a tenant key should simply
            # not declare ``permission=`` (or declare a dedicated "tenant"
            # scope that the caller proves via a user mapped to that tenant).
            if permission is not None:
                if rbac_manager is None or g.user is None:
                    log.info(
                        "permission=%s rejected: authenticated via tenant key "
                        "but no RBAC user (tenant=%s)",
                        permission,
                        getattr(g.tenant, "tenant_id", None),
                    )
                    return jsonify({"error": "Forbidden"}), 403
                if not rbac_manager.authorize(g.user, permission):
                    return jsonify({"error": "Forbidden"}), 403

            return f(*args, **kwargs)

        return wrapper

    return decorator
