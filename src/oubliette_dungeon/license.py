"""
Oubliette Dungeon - License & Metering Layer
=============================================
Soft enforcement of feature gating and usage metering.

Tiers:
- **free**: analyze(), scan_input(), basic session tracking, pre-filter + ML.
- **pro**: Unlocks scan_output, drift_monitor, webhooks, stix_export,
  agent_policy, mcp_guard, tenant_manager, rbac.
- **enterprise**: Everything, no warnings.

Licenses are product-scoped schema v2 tokens signed with Ed25519 (see
:mod:`oubliette_dungeon._license_core`, vendored byte-identical from
``oubliette-commerce``, which is the only issuer). Dungeon accepts a key only
if its signed ``products`` list contains ``"dungeon"``; a Shield- or
Trap-only key gives the free tier here. Every validation failure gives the
free tier. Client-side HMAC verification has been removed.
"""

from __future__ import annotations

import importlib.util
import logging
import os
from collections.abc import Iterable, Mapping
from typing import Any

from . import _license_core
from ._license_core import (
    DEFAULT_MONTHLY_QUOTA,
    FREE_LICENSE,
    KNOWN_PRODUCTS,
    PRODUCTION_KEYRING,
    SCHEMA_VERSION,
    LicenseError,
    LicenseInfo,
    canonical_payload,
    verify_license_token,
)

log = logging.getLogger(__name__)

#: This product's registry name in the signed ``products`` claim.
PRODUCT = "dungeon"

# Features that require Pro tier (Dungeon red-team engine)
PRO_FEATURES = frozenset(
    {
        "scheduler",  # continuous / scheduled adversarial runs
        "pdf_reports",  # PDF + NIST RMF report generation
        "multi_provider_compare",  # cross-provider robustness comparison
        "rest_api",  # REST API + dashboard server
        "webhooks",  # run-complete webhook notifications
        "custom_scenarios",  # author/import custom attack scenarios
        "full_scenario_library",  # full scenario library (default.yaml 57 + crescendo.yaml 15)
        "rbac",  # role-based access control
        "tenant_manager",  # multi-tenant isolation
    }
)

__all__ = [
    "DEFAULT_MONTHLY_QUOTA",
    "FREE_LICENSE",
    "KNOWN_PRODUCTS",
    "PRODUCT",
    "PRODUCTION_KEYRING",
    "PRO_FEATURES",
    "SCHEMA_VERSION",
    "FeatureGate",
    "LicenseError",
    "LicenseInfo",
    "LicenseManager",
    "LicenseRequiredError",
    "canonical_payload",
    "require_feature",
    "verify_license_token",
]


class LicenseManager(_license_core.LicenseManager):
    """Dungeon's license manager: validation, feature gating, usage metering.

    Verifies ``OUBLIETTE_LICENSE_KEY`` for product ``"dungeon"`` against the
    embedded public keyring. Thread-safe.

    Args:
        storage_backend: Optional storage backend for persisting usage data.
        keyring: ``kid -> public key`` override for tests and rotation drills.
            Defaults to the embedded production keyring. There is no
            environment-variable override.
    """

    def __init__(
        self,
        *,
        storage_backend: Any = None,
        keyring: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(
            product=PRODUCT,
            pro_features=PRO_FEATURES,
            storage_backend=storage_backend,
            keyring=keyring,
        )


class FeatureGate(_license_core.FeatureGate):
    """Controls access to Pro features based on license key.

    Provides a simple boolean check for whether a feature is available
    under the current license tier.

    Tiers:
        - **community**: ``analyze``, ``health``, ``basic_session``
        - **pro**: Everything in community plus ``multi_tenant``,
          ``siem_export``, ``webhooks``, ``openc2``, ``rbac``,
          ``advanced_session``, ``threat_intel``

    Usage::

        gate = FeatureGate(license_manager=LicenseManager())
        gate.validate()
        if gate.is_allowed("openc2"):
            # enable OpenC2 adapter
            ...

    Args:
        license_key: A license key string.  Defaults to the
            ``OUBLIETTE_LICENSE_KEY`` environment variable.
        license_manager: Optional :class:`LicenseManager` to
            delegate validation to.  When provided, the gate uses
            the manager's (Dungeon-scoped) tier after validation.  This is
            the only path that verifies the license signature.
        insecure_simple_mode: DEV/TEST ONLY.  Without a manager the key
            cannot be verified, so the gate stays at ``community``.  Set
            this (or ``OUBLIETTE_INSECURE_DEV_FEATURE_GATE=true``) to
            restore the old behaviour of treating any non-empty key as
            Pro.  Default off.
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
        license_manager: _license_core.LicenseManager | None = None,
        *,
        insecure_simple_mode: bool | None = None,
        community_features: Iterable[str] | None = None,
        pro_features: Iterable[str] | None = None,
    ) -> None:
        if insecure_simple_mode is None:
            insecure_simple_mode = os.getenv(
                "OUBLIETTE_INSECURE_DEV_FEATURE_GATE", ""
            ).strip().lower() in ("1", "true", "yes")
        super().__init__(
            license_key,
            license_manager,
            community_features=community_features,
            pro_features=pro_features,
            insecure_simple_mode=insecure_simple_mode,
        )


class LicenseRequiredError(PermissionError):
    """A Dungeon Pro feature was requested without the entitlement for it.

    Raised instead of silently degrading, so a caller that asked for a Pro
    feature (for example the full 72-scenario suite) never receives the free
    behaviour while believing it got the paid one.

    Attributes:
        feature: The missing entitlement (a name in :data:`PRO_FEATURES`).
        tier: The verified tier that was in effect (``free`` when no valid
            Dungeon-scoped key was found).
    """

    def __init__(self, feature: str, tier: str, message: str) -> None:
        super().__init__(message)
        self.feature = feature
        self.tier = tier


def require_feature(
    feature: str,
    *,
    action: str,
    license_manager: _license_core.LicenseManager | None = None,
) -> str:
    """Fail closed unless ``feature`` is licensed for Dungeon.

    Grants when the verified, Dungeon-scoped license is ``enterprise``, or is
    ``pro`` and lists ``feature`` (bare or as ``dungeon:<feature>``). Otherwise the only
    way through is the explicit DEV/TEST opt-in shared with
    :class:`FeatureGate`: ``OUBLIETTE_INSECURE_DEV_FEATURE_GATE=true`` plus a
    non-empty ``OUBLIETTE_LICENSE_KEY``, which logs a warning.

    Args:
        feature: Entitlement name; must be one of :data:`PRO_FEATURES`.
        action: What the caller tried to do, used in the error message.
        license_manager: Manager to consult. Defaults to a new
            :class:`LicenseManager` reading ``OUBLIETTE_LICENSE_KEY``.

    Returns:
        ``"license"`` or ``"insecure-dev-opt-in"``: how access was granted.

    Raises:
        LicenseRequiredError: The entitlement is missing (a ``PermissionError``).
        ValueError: ``feature`` is not a Dungeon Pro feature (a programming error).
    """
    if feature not in PRO_FEATURES:
        raise ValueError(f"{feature!r} is not a Dungeon Pro feature")
    mgr = license_manager if license_manager is not None else LicenseManager()
    lic = mgr.license
    if lic.tier in ("pro", "enterprise") and lic.has_feature(feature):
        return "license"
    # No manager on purpose: this is exactly FeatureGate's documented dev/test
    # opt-in (any non-empty key counts as Pro), off unless explicitly enabled.
    if FeatureGate().validate():
        log.warning(
            "[LICENSE] '%s' granted by OUBLIETTE_INSECURE_DEV_FEATURE_GATE without a "
            "verified license. Do NOT use in production.",
            feature,
        )
        return "insecure-dev-opt-in"
    message = (
        f"{action} requires Dungeon Pro: missing the '{feature}' entitlement "
        f"(current tier: {lic.tier}). Set OUBLIETTE_LICENSE_KEY to a valid Dungeon "
        f"Pro license key (its products must include 'dungeon' and it must grant "
        f"'{feature}' or be enterprise), or contact sales@oubliettesecurity.com."
    )
    if importlib.util.find_spec("cryptography") is None:
        message += (
            " License keys cannot be verified without the 'cryptography' package: "
            "pip install 'oubliette-dungeon[licensing]'."
        )
    raise LicenseRequiredError(feature, lic.tier, message)
