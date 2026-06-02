"""
Oubliette Dungeon - Multi-Tenancy
Thread-safe tenant management with API key authentication and per-tenant isolation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Tenant:
    """Represents a tenant in the multi-tenant Shield deployment."""

    tenant_id: str
    name: str
    api_key_hash: str = ""
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    config_overrides: dict[str, Any] = field(default_factory=dict)
    rate_limit: int | None = None
    tags: list[str] = field(default_factory=list)


def _hash_key(api_key: str, salt: bytes | None = None) -> str:
    """Hash an API key with PBKDF2-HMAC-SHA256 (600k iterations).

    Returns ``salt_hex:hash_hex``.
    """
    if salt is None:
        salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", api_key.encode("utf-8"), salt, 600_000)
    return salt.hex() + ":" + dk.hex()


def _verify_key(api_key: str, stored: str) -> bool:
    """Timing-safe verification of an API key against a stored hash."""
    try:
        salt_hex, hash_hex = stored.split(":", 1)
    except ValueError:
        # Legacy unsalted SHA-256 hash -- constant-time compare
        legacy_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy_hash, stored)
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", api_key.encode("utf-8"), salt, 600_000)
    return hmac.compare_digest(dk.hex(), hash_hex)


_EPHEMERAL_LOOKUP_PEPPER: bytes | None = None


def _lookup_pepper() -> bytes:
    """Return the deployment-scoped lookup pepper.

    Read from ``SHIELD_TENANT_LOOKUP_PEPPER`` (recommended: 32+ byte hex
    value from ``secrets.token_hex(32)``). If unset, a per-process random
    pepper is generated -- safe but means tenant API keys only resolve
    within the lifetime of this interpreter instance. Persistent
    deployments MUST set the env var.
    """
    env = os.getenv("SHIELD_TENANT_LOOKUP_PEPPER", "")
    if env:
        # Accept hex or raw; decode hex if it parses.
        try:
            return bytes.fromhex(env)
        except ValueError:
            return env.encode("utf-8")
    # Fallback: process-scoped random pepper. See warning in docstring.
    global _EPHEMERAL_LOOKUP_PEPPER
    if _EPHEMERAL_LOOKUP_PEPPER is None:
        _EPHEMERAL_LOOKUP_PEPPER = os.urandom(32)
    return _EPHEMERAL_LOOKUP_PEPPER


def _lookup_hash(api_key: str) -> str:
    """Fast, deterministic, peppered lookup key.

    HIGH-2 fix: authentication previously did O(N) PBKDF2-600k verifications
    over every tenant per request. At 20 bad-key rps with a few hundred
    tenants that is an auth-DoS. The lookup hash is HMAC-SHA256 over the
    peppered api_key -- constant time, ~microseconds -- and lets the
    request touch at most ONE PBKDF2 verify regardless of tenant count.

    The pepper makes the lookup hash non-enumerable from a stolen index
    dump: an attacker who exfiltrates _lookup_index still cannot map hashes
    back to plaintext api_keys without also stealing the pepper.
    """
    return hmac.new(_lookup_pepper(), api_key.encode("utf-8"), "sha256").hexdigest()


# A dummy PBKDF2 hash used on the miss path so that resolve_by_api_key runs
# the same amount of PBKDF2 work whether or not the lookup hash matches a
# tenant. Computed lazily once per process.
_DUMMY_PBKDF2_HASH: str | None = None


def _dummy_hash() -> str:
    global _DUMMY_PBKDF2_HASH
    if _DUMMY_PBKDF2_HASH is None:
        _DUMMY_PBKDF2_HASH = _hash_key("dummy-for-timing-consistency-only")
    return _DUMMY_PBKDF2_HASH


class TenantManager:
    """
    Manages tenants with API key authentication and per-tenant isolation.

    Thread-safe with RLock on all shared state.

    Usage::

        mgr = TenantManager()
        tenant, key = mgr.create_tenant("acme", "Acme Corp")
        resolved = mgr.resolve_by_api_key(key)
        assert resolved.tenant_id == "acme"
    """

    def __init__(self) -> None:
        self._tenants: dict[str, Tenant] = {}
        self._key_index: dict[
            str, str
        ] = {}  # api_key_hash -> tenant_id (legacy; kept for delete/rotate bookkeeping)
        self._lookup_index: dict[str, str] = {}  # HMAC(pepper, key) -> tenant_id (O(1) resolver)
        self._lock = threading.RLock()

    # ---- CRUD ----

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        config_overrides: dict[str, Any] | None = None,
        rate_limit: int | None = None,
        tags: list[str] | None = None,
    ) -> tuple[Tenant, str]:
        """Create a tenant and return (Tenant, plaintext_api_key).

        The plaintext key is returned exactly once.  Only the hash is stored.
        """
        api_key = secrets.token_urlsafe(32)
        key_hash = _hash_key(api_key)

        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            api_key_hash=key_hash,
            config_overrides=config_overrides or {},
            rate_limit=rate_limit,
            tags=tags or [],
        )

        with self._lock:
            if tenant_id in self._tenants:
                raise ValueError(f"Tenant {tenant_id!r} already exists")
            self._tenants[tenant_id] = tenant
            self._key_index[key_hash] = tenant_id
            self._lookup_index[_lookup_hash(api_key)] = tenant_id

        return tenant, api_key

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        """Get a tenant by ID.  Returns None if not found."""
        with self._lock:
            return self._tenants.get(tenant_id)

    def list_tenants(self) -> list[Tenant]:
        """Return a list of all tenants."""
        with self._lock:
            return list(self._tenants.values())

    def update_tenant(self, tenant_id: str, **fields: Any) -> Tenant:
        """Update tenant fields.  Returns the updated tenant."""
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant is None:
                raise KeyError(f"Tenant {tenant_id!r} not found")
            for k, v in fields.items():
                if k == "config_overrides" and isinstance(v, dict):
                    tenant.config_overrides.update(v)
                elif hasattr(tenant, k) and k not in ("tenant_id", "api_key_hash", "created_at"):
                    setattr(tenant, k, v)
            return tenant

    def delete_tenant(self, tenant_id: str) -> bool:
        """Delete a tenant.  Returns True if deleted, False if not found."""
        with self._lock:
            tenant = self._tenants.pop(tenant_id, None)
            if tenant is None:
                return False
            self._key_index.pop(tenant.api_key_hash, None)
            # Remove from lookup_index by reverse scan (api_key not retained).
            dead = [lh for lh, tid in self._lookup_index.items() if tid == tenant_id]
            for lh in dead:
                self._lookup_index.pop(lh, None)
            return True

    # ---- API key operations ----

    def rotate_api_key(self, tenant_id: str) -> str:
        """Generate a new API key for a tenant.  Returns the new plaintext key."""
        new_key = secrets.token_urlsafe(32)
        new_hash = _hash_key(new_key)

        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant is None:
                raise KeyError(f"Tenant {tenant_id!r} not found")
            # Remove old index entries
            self._key_index.pop(tenant.api_key_hash, None)
            dead = [lh for lh, tid in self._lookup_index.items() if tid == tenant_id]
            for lh in dead:
                self._lookup_index.pop(lh, None)
            # Update
            tenant.api_key_hash = new_hash
            self._key_index[new_hash] = tenant_id
            self._lookup_index[_lookup_hash(new_key)] = tenant_id

        return new_key

    def resolve_by_api_key(self, api_key: str) -> Tenant | None:
        """Resolve a tenant from a plaintext API key.

        HIGH-2 fix: O(1) HMAC lookup replaces the prior O(N) PBKDF2 scan
        over every tenant. The request does exactly ONE PBKDF2 verify
        regardless of tenant count (against the matched tenant's hash on
        hit, or against a fixed dummy hash on miss -- the dummy keeps the
        wall-clock on-miss indistinguishable from on-hit so we do not
        trade one timing oracle for another).

        Returns None on miss or if the tenant is disabled.
        """
        lh = _lookup_hash(api_key)
        with self._lock:
            tenant_id = self._lookup_index.get(lh)
            tenant = self._tenants.get(tenant_id) if tenant_id else None
            stored_hash = tenant.api_key_hash if tenant is not None else _dummy_hash()

        # PBKDF2 verify OUTSIDE the lock so one slow auth does not block the
        # whole manager. We still run it on miss to keep timing consistent.
        verified = _verify_key(api_key, stored_hash)
        if not verified or tenant is None or not tenant.enabled:
            return None
        return tenant

    # ---- Per-tenant config ----

    def get_effective_config(self, tenant_id: str, base_config: dict[str, Any]) -> dict[str, Any]:
        """Merge tenant overrides on top of base config.

        Returns a new dict; does not mutate *base_config*.
        """
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant is None:
                return dict(base_config)
            merged = dict(base_config)
            merged.update(tenant.config_overrides)
            if tenant.rate_limit is not None:
                merged["rate_limit"] = tenant.rate_limit
            return merged
