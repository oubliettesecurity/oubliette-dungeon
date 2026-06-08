"""
Oubliette Dungeon - License & Metering Layer
=============================================
Soft enforcement of feature gating and usage metering.

Tiers:
- **free**: analyze(), scan_input(), basic session tracking, pre-filter + ML.
- **pro**: Unlocks scan_output, drift_monitor, webhooks, stix_export,
  agent_policy, mcp_guard, tenant_manager, rbac.
- **enterprise**: Everything, no warnings.

License key is a base64-encoded JSON blob with HMAC-SHA256 signature.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import threading
import time
from typing import Any

log = logging.getLogger(__name__)

# Features that require Pro tier (Dungeon red-team engine)
PRO_FEATURES = frozenset(
    {
        "scheduler",  # continuous / scheduled adversarial runs
        "pdf_reports",  # PDF + NIST RMF report generation
        "multi_provider_compare",  # cross-provider robustness comparison
        "rest_api",  # REST API + dashboard server
        "webhooks",  # run-complete webhook notifications
        "custom_scenarios",  # author/import custom attack scenarios
        "full_scenario_library",  # the complete 57-scenario library
        "rbac",  # role-based access control
        "tenant_manager",  # multi-tenant isolation
    }
)

# Default soft quota for free tier (monthly analyze() calls)
_DEFAULT_MONTHLY_QUOTA = 10_000

# How long to cache a validated license (seconds)
_VALIDATION_CACHE_TTL = 3600  # 1 hour


class LicenseInfo:
    """Parsed and validated license data."""

    __slots__ = ("expires", "features", "issued", "org", "quota", "tier", "valid")

    def __init__(
        self,
        tier: str = "free",
        org: str = "",
        issued: str = "",
        expires: str = "",
        quota: int = 0,
        features: list[str] | None = None,
        valid: bool = True,
    ):
        self.tier = tier
        self.org = org
        self.issued = issued
        self.expires = expires
        self.quota = quota
        self.features = set(features or [])
        self.valid = valid

    def has_feature(self, feature: str) -> bool:
        if self.tier == "enterprise":
            return True
        return feature in self.features

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "org": self.org,
            "issued": self.issued,
            "expires": self.expires,
            "quota": self.quota,
            "features": sorted(self.features),
            "valid": self.valid,
        }


_FREE_LICENSE = LicenseInfo(tier="free", quota=_DEFAULT_MONTHLY_QUOTA)


class LicenseManager:
    """Manages license validation, feature gating, and usage metering.

    Thread-safe with RLock on all shared state.

    Args:
        signing_key: HMAC signing key for license validation. Defaults to
            ``OUBLIETTE_LICENSE_SIGNING_KEY`` env var.
        storage_backend: Optional storage backend for persisting usage data.
    """

    def __init__(self, signing_key: str | None = None, storage_backend: Any = None) -> None:
        self._lock = threading.RLock()
        self._signing_key = signing_key or os.getenv("OUBLIETTE_LICENSE_SIGNING_KEY", "")
        self._storage = storage_backend
        self._license: LicenseInfo | None = None
        self._validated_at: float = 0.0
        self._usage: dict[str, dict[str, Any]] = {}  # {month: {total, by_feature}}
        self._quota = int(os.getenv("OUBLIETTE_MONTHLY_QUOTA", str(_DEFAULT_MONTHLY_QUOTA)))
        self._warned_80 = False
        self._warned_100 = False

        # Auto-load license from env
        raw = os.getenv("OUBLIETTE_LICENSE_KEY", "")
        if raw:
            self._load_license(raw)
        else:
            self._license = _FREE_LICENSE
            log.info("[LICENSE] No license key set -- running in free tier")

    # ------------------------------------------------------------------
    # License validation
    # ------------------------------------------------------------------

    def _load_license(self, raw_key: str) -> None:
        """Parse and validate a base64-encoded license key."""
        try:
            decoded = base64.b64decode(raw_key)
            data = json.loads(decoded)
        except Exception:
            log.warning("[LICENSE] Invalid license key format -- falling back to free tier")
            self._license = _FREE_LICENSE
            return

        sig = data.pop("sig", "")
        # Verify signature if we have a signing key
        if self._signing_key:
            payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
            expected_sig = hmac.new(
                self._signing_key.encode("utf-8"),
                payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                log.warning("[LICENSE] Invalid license signature -- falling back to free tier")
                self._license = _FREE_LICENSE
                return

        # Check expiry
        expires = data.get("expires", "")
        if expires:
            try:
                exp_date = datetime.date.fromisoformat(expires)
                if exp_date < datetime.date.today():
                    log.warning(
                        "[LICENSE] License expired on %s -- falling back to free tier", expires
                    )
                    self._license = _FREE_LICENSE
                    return
            except ValueError:
                pass

        self._license = LicenseInfo(
            tier=data.get("tier", "free"),
            org=data.get("org", ""),
            issued=data.get("issued", ""),
            expires=expires,
            quota=data.get("quota", 0),
            features=data.get("features", []),
        )
        self._validated_at = time.time()
        if self._license.quota:
            self._quota = self._license.quota
        log.info(
            "[LICENSE] Loaded %s license for %s (expires %s)",
            self._license.tier,
            self._license.org,
            self._license.expires,
        )

    @property
    def license(self) -> LicenseInfo:
        """Get current license info, re-validating if cache expired."""
        with self._lock:
            if self._license is None:
                return _FREE_LICENSE
            # Re-validate from env if cache expired
            if time.time() - self._validated_at > _VALIDATION_CACHE_TTL:
                raw = os.getenv("OUBLIETTE_LICENSE_KEY", "")
                if raw:
                    self._load_license(raw)
            return self._license

    # ------------------------------------------------------------------
    # Feature gating (soft enforcement)
    # ------------------------------------------------------------------

    def check_feature(self, feature: str) -> bool:
        """Check if a feature is available. Logs warning if not.

        Returns True if feature is allowed (always True, but logs warning).
        """
        lic = self.license
        if lic.tier == "enterprise":
            return True
        if feature in PRO_FEATURES and not lic.has_feature(feature):
            log.warning("[LICENSE] Feature '%s' requires Pro tier (current: %s)", feature, lic.tier)
            return False
        return True

    # ------------------------------------------------------------------
    # Usage metering
    # ------------------------------------------------------------------

    def _month_key(self) -> str:
        return datetime.date.today().strftime("%Y-%m")

    def record_usage(self, feature: str = "analyze") -> None:
        """Record a usage event. Thread-safe."""
        with self._lock:
            month = self._month_key()
            if month not in self._usage:
                self._usage[month] = {"total": 0, "by_feature": {}}
                self._warned_80 = False
                self._warned_100 = False
            self._usage[month]["total"] += 1
            self._usage[month]["by_feature"][feature] = (
                self._usage[month]["by_feature"].get(feature, 0) + 1
            )

            total = self._usage[month]["total"]
            if self._quota > 0:
                pct = total / self._quota
                if pct >= 1.0 and not self._warned_100:
                    log.warning(
                        "[LICENSE] Monthly quota reached: %d/%d (100%%). "
                        "Usage continues but upgrade recommended.",
                        total,
                        self._quota,
                    )
                    self._warned_100 = True
                elif pct >= 0.8 and not self._warned_80:
                    log.warning(
                        "[LICENSE] Approaching monthly quota: %d/%d (80%%)",
                        total,
                        self._quota,
                    )
                    self._warned_80 = True

    def get_usage(self, month: str | None = None) -> dict[str, Any]:
        """Get usage summary for a given month (default: current)."""
        with self._lock:
            key = month or self._month_key()
            usage = self._usage.get(key, {"total": 0, "by_feature": {}})
            return {
                "month": key,
                "total": usage["total"],
                "by_feature": dict(usage["by_feature"]),
                "quota": self._quota,
                "tier": self.license.tier,
            }

    def get_usage_all(self) -> dict[str, dict[str, Any]]:
        """Get usage for all tracked months."""
        with self._lock:
            return {k: dict(v) for k, v in self._usage.items()}


# ======================================================================
# Feature Gate -- simplified tier-based access control
# ======================================================================


class FeatureGate:
    """Controls access to Pro features based on license key.

    Provides a simple boolean check for whether a feature is available
    under the current license tier.  Integrates with :class:`Shield` via
    the ``feature_gate`` constructor parameter.

    Tiers:
        - **community**: ``analyze``, ``health``, ``basic_session``
        - **pro**: Everything in community plus ``multi_tenant``,
          ``siem_export``, ``webhooks``, ``openc2``, ``rbac``,
          ``advanced_session``, ``threat_intel``

    Usage::

        gate = FeatureGate(license_key="my-key")
        gate.validate()
        if gate.is_allowed("openc2"):
            # enable OpenC2 adapter
            ...

    Args:
        license_key: A license key string.  Defaults to the
            ``OUBLIETTE_LICENSE_KEY`` environment variable.
        license_manager: Optional :class:`LicenseManager` to
            delegate validation to.  When provided, the gate uses
            the manager's tier information after validation.
    """

    COMMUNITY_FEATURES: frozenset[str] = frozenset(
        {
            "analyze",
            "health",
            "basic_session",
        }
    )

    PRO_FEATURES: frozenset[str] = frozenset(
        {
            "multi_tenant",
            "siem_export",
            "webhooks",
            "openc2",
            "rbac",
            "advanced_session",
            "threat_intel",
        }
    )

    ALL_FEATURES: frozenset[str] = COMMUNITY_FEATURES | PRO_FEATURES

    def __init__(
        self,
        license_key: str | None = None,
        license_manager: LicenseManager | None = None,
    ):
        self.license_key = license_key or os.getenv("OUBLIETTE_LICENSE_KEY", "")
        self._license_manager = license_manager
        self._validated = False
        self._tier = "community"

    def validate(self) -> bool:
        """Validate the license key and determine the tier.

        If a ``LicenseManager`` was provided, delegates to its
        validation logic and reads the resulting tier.  Otherwise
        any non-empty key is treated as a Pro license (simple mode).

        Returns:
            ``True`` if a Pro or Enterprise key was validated.
        """
        if self._license_manager is not None:
            lic = self._license_manager.license
            if lic.tier in ("pro", "enterprise"):
                self._tier = lic.tier
                self._validated = True
            else:
                self._tier = "community"
                self._validated = False
            return self._validated

        # Simple mode: any non-empty key = pro
        if self.license_key:
            self._tier = "pro"
            self._validated = True
        else:
            self._tier = "community"
            self._validated = False
        return self._validated

    def is_allowed(self, feature: str) -> bool:
        """Check if *feature* is available under the current tier.

        Community features are always allowed.  Pro features require
        a validated Pro or Enterprise license.

        Args:
            feature: Feature name to check.

        Returns:
            ``True`` if the feature is accessible.
        """
        if feature in self.COMMUNITY_FEATURES:
            return True
        if self._tier in ("pro", "enterprise") and feature in self.PRO_FEATURES:
            return True
        return False

    def require(self, feature: str) -> None:
        """Raise ``PermissionError`` if *feature* is not allowed."""
        if not self.is_allowed(feature):
            raise PermissionError(
                f"Feature '{feature}' requires a Pro license "
                f"(current tier: {self._tier}). "
                "Set OUBLIETTE_LICENSE_KEY or contact sales@oubliettesecurity.com"
            )

    @property
    def tier(self) -> str:
        """Return the current license tier."""
        return self._tier

    @property
    def validated(self) -> bool:
        """Return whether a license has been successfully validated."""
        return self._validated

    def to_dict(self) -> dict[str, Any]:
        """Serialize gate state for API responses."""
        return {
            "tier": self._tier,
            "validated": self._validated,
            "community_features": sorted(self.COMMUNITY_FEATURES),
            "pro_features": sorted(self.PRO_FEATURES),
        }
