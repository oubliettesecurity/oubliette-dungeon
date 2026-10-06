"""Product-scoped license verification for the Oubliette suite (schema v2).

VENDORED MODULE. The canonical copy is ``src/oubliette_commerce/_license_core.py``
in oubliettesecurity/oubliette-commerce. Byte-identical copies live in:

- oubliette (Shield): ``oubliette_shield/_license_core.py``
- oubliette-trap: ``src/oubliette_trap/_license_core.py``
- oubliette-dungeon: ``src/oubliette_dungeon/_license_core.py``

Change it in commerce first, copy it verbatim into the other repos, and update
``LICENSE_CORE_SHA256`` in each repo's ``test_license_core_vendored.py``.

Token format
------------
``OUBLIETTE_LICENSE_KEY`` is standard base64 of a JSON object::

    {"v": 2, "kid": "...", "lid": "...", "products": ["shield"],
     "tier": "pro", "org": "...", "issued": "YYYY-MM-DD",
     "expires": "YYYY-MM-DD", "quota": 0,
     "features": ["scan_output", "trap:stix_export"],
     "sig_alg": "ed25519", "sig": "<base64 Ed25519 signature>"}

The signature covers the canonical JSON (sorted keys, compact separators,
ASCII) of every field except ``sig``, so ``sig_alg`` is signed too. It is
checked against the Ed25519 public key that the keyring holds for ``kid``.
There is no HMAC path: a verifier never holds a secret that can mint.

A verifier for product ``P`` accepts a token only if every check below passes,
including ``P in products``. Any failure (bad base64/JSON, unknown ``v``,
unknown ``kid``, bad signature, a missing, extra or malformed field, a
product mismatch, or an expired license) yields the free tier.

``features`` entries are either bare (``"webhooks"``: applies to every listed
product) or namespaced (``"trap:stix_export"``: applies only to that product).
``enterprise`` unlocks every feature of the products it lists.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import json
import logging
import os
import re
import threading
import time
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Any, NoReturn

log = logging.getLogger(__name__)

SCHEMA_VERSION = 2
SIG_ALG = "ed25519"

# Product registry. A token's ``products`` entries outside this set are
# ignored by verifiers and refused by the issuer.
KNOWN_PRODUCTS: frozenset[str] = frozenset({"commerce", "dungeon", "shield", "trap"})
KNOWN_TIERS: frozenset[str] = frozenset({"enterprise", "free", "pro"})
PAID_TIERS: frozenset[str] = frozenset({"enterprise", "pro"})

# Production verification keyring: key id -> base64 of the raw 32-byte Ed25519
# PUBLIC key. Public keys can only verify, never mint, so shipping them is safe.
# The matching private keys are never committed to any repository. To rotate,
# add the new kid here (in every repo), start issuing with it, and remove the
# old kid only once no license signed with it is still in use.
PRODUCTION_KEYRING: Mapping[str, str] = MappingProxyType(
    {
        # Production license-signing key, generated 2026-10-06. It replaced
        # kid "oubliette-2026-07", which was removed outright because no
        # license was ever issued under it.
        "oubliette-2026-10": "g2pDYyl9UlVWe3OS9yFKq5gjdkX7vG+NxEVqD/AeT3o=",
    }
)

_CLAIMS = frozenset(
    {
        "expires",
        "features",
        "issued",
        "kid",
        "lid",
        "org",
        "products",
        "quota",
        "sig",
        "sig_alg",
        "tier",
        "v",
    }
)
_MAX_TOKEN_CHARS = 8192
_MAX_ID_CHARS = 128
_DATE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")

# Default soft quota for the free tier (monthly calls).
DEFAULT_MONTHLY_QUOTA = 10_000
# How long to cache a validated license before re-reading the env (seconds).
VALIDATION_CACHE_TTL = 3600


class LicenseError(ValueError):
    """A license token failed verification. The caller falls back to free."""


def _fail(reason: str) -> NoReturn:
    raise LicenseError(reason)


def canonical_payload(claims: Mapping[str, Any]) -> bytes:
    """Return the exact bytes that are signed: every claim except ``sig``."""
    body = {k: v for k, v in claims.items() if k != "sig"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair: ``(private_b64, public_b64)``.

    Both values are base64 of the raw 32-byte key. Keep the private value
    offline/server-side; only the public value goes into a keyring.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_b64 = base64.b64encode(priv_raw).decode("ascii")
    return priv_b64, public_key_for(priv_b64)


def public_key_for(private_b64: str) -> str:
    """Derive the base64 raw public key for a base64 raw Ed25519 private key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64, validate=True))
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(pub_raw).decode("ascii")


def parse_date(value: object, field: str) -> datetime.date:
    """Parse a strict ``YYYY-MM-DD`` date or raise :class:`LicenseError`."""
    if not isinstance(value, str) or not _DATE_RE.match(value):
        _fail(f"'{field}' must be a YYYY-MM-DD date")
    try:
        return datetime.date.fromisoformat(value)
    except ValueError:
        _fail(f"'{field}' is not a valid date")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _id_claim(claims: Mapping[str, Any], field: str) -> str:
    value = claims.get(field)
    if not isinstance(value, str) or not value or len(value) > _MAX_ID_CHARS:
        _fail(f"'{field}' must be a non-empty string")
    return value


def _str_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        _fail(f"'{field}' must be a list of strings")
    return list(value)


def _reject_constant(name: str) -> NoReturn:
    _fail(f"non-finite number {name!r}")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            _fail(f"duplicate claim {key!r}")
        out[key] = value
    return out


def _decode(raw_key: object) -> dict[str, Any]:
    if not isinstance(raw_key, str):
        _fail("license key is not a string")
    raw = raw_key.strip()
    if not raw or len(raw) > _MAX_TOKEN_CHARS:
        _fail("license key is empty or too long")
    try:
        decoded = base64.b64decode(raw, validate=True)
        data = json.loads(
            decoded.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        if isinstance(exc, LicenseError):
            raise
        _fail("license key is not base64-encoded JSON")
    if not isinstance(data, dict):
        _fail("license key is not a JSON object")
    return data


def _verify_signature(public_b64: str, sig_b64: str, payload: bytes) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        _fail("the 'cryptography' package is not installed (install the [licensing] extra)")
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64, validate=True))
        pub.verify(base64.b64decode(sig_b64, validate=True), payload)
    except InvalidSignature:
        _fail("signature verification failed")
    except (binascii.Error, TypeError, ValueError):
        _fail("malformed public key or signature")


class LicenseInfo:
    """Parsed and validated license data."""

    __slots__ = (
        "expires",
        "features",
        "issued",
        "kid",
        "lid",
        "org",
        "products",
        "quota",
        "tier",
        "valid",
    )

    def __init__(
        self,
        tier: str = "free",
        org: str = "",
        issued: str = "",
        expires: str = "",
        quota: int = 0,
        features: Iterable[str] | None = None,
        valid: bool = True,
        *,
        products: Iterable[str] = (),
        lid: str = "",
        kid: str = "",
    ) -> None:
        self.tier = tier
        self.org = org
        self.issued = issued
        self.expires = expires
        self.quota = quota
        self.features = set(features or [])
        self.valid = valid
        self.products = tuple(sorted(set(products)))
        self.lid = lid
        self.kid = kid

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
            "products": list(self.products),
            "lid": self.lid,
            "kid": self.kid,
        }


FREE_LICENSE = LicenseInfo(tier="free", quota=DEFAULT_MONTHLY_QUOTA)


def verify_license_token(
    raw_key: object,
    *,
    product: str,
    keyring: Mapping[str, str] | None = None,
    today: datetime.date | None = None,
) -> LicenseInfo:
    """Verify a v2 license token for ``product``.

    Returns the license as seen by ``product`` (its effective feature set).
    Raises :class:`LicenseError` on any failure; callers fall back to free.
    ``keyring`` defaults to :data:`PRODUCTION_KEYRING`.
    """
    if product not in KNOWN_PRODUCTS:
        raise ValueError(f"unknown product {product!r}")
    ring = PRODUCTION_KEYRING if keyring is None else keyring
    claims = _decode(raw_key)

    unknown = set(claims) - _CLAIMS
    if unknown:
        _fail(f"unknown claims {sorted(unknown)}")
    version = claims.get("v")
    if not _is_int(version) or version != SCHEMA_VERSION:
        _fail(f"unsupported license schema version {version!r}")
    if claims.get("sig_alg") != SIG_ALG:
        _fail("unsupported signature algorithm")
    sig = claims.get("sig")
    if not isinstance(sig, str) or not sig:
        _fail("missing signature")
    kid = _id_claim(claims, "kid")
    public_key = ring.get(kid)
    if not public_key:
        _fail(f"unknown signing key id {kid!r}")
    try:
        payload = canonical_payload(claims)
    except (TypeError, ValueError):
        _fail("license claims cannot be canonicalized")
    _verify_signature(public_key, sig, payload)

    lid = _id_claim(claims, "lid")
    products = _str_list(claims.get("products"), "products")
    if not products:
        _fail("'products' is empty")
    if product not in products:
        _fail(f"license is not valid for product {product!r}")
    tier = claims.get("tier")
    if not isinstance(tier, str) or tier not in KNOWN_TIERS:
        _fail(f"unknown tier {tier!r}")
    org = claims.get("org")
    if not isinstance(org, str):
        _fail("'org' must be a string")
    issued = parse_date(claims.get("issued"), "issued")
    expires = parse_date(claims.get("expires"), "expires")
    if expires < issued:
        _fail("'expires' is before 'issued'")
    if expires < (today or datetime.date.today()):
        _fail(f"license expired on {expires.isoformat()}")
    quota = claims.get("quota")
    if not isinstance(quota, int) or isinstance(quota, bool) or quota < 0:
        _fail("'quota' must be a non-negative integer")

    features: set[str] = set()
    for entry in _str_list(claims.get("features"), "features"):
        scope, sep, name = entry.partition(":")
        if not sep:
            features.add(entry)
        elif scope == product and name:
            features.add(name)

    return LicenseInfo(
        tier=tier,
        org=org,
        issued=issued.isoformat(),
        expires=expires.isoformat(),
        quota=quota,
        features=features,
        products=[p for p in products if p in KNOWN_PRODUCTS],
        lid=lid,
        kid=kid,
    )


class LicenseManager:
    """Product-scoped license validation, soft feature gating and usage metering.

    Reads ``OUBLIETTE_LICENSE_KEY`` and accepts it only if it verifies for
    ``product`` (see :func:`verify_license_token`); otherwise the free tier
    applies. Thread-safe.

    Args:
        product: This product's registry name (``KNOWN_PRODUCTS``). Products
            pass a module constant; it is never read from the environment.
        pro_features: The product's Pro feature names.
        storage_backend: Optional storage backend for persisting usage data.
        keyring: ``kid -> public key`` override for tests and rotation drills.
            Defaults to :data:`PRODUCTION_KEYRING`. There is deliberately no
            environment-variable override.
    """

    def __init__(
        self,
        *,
        product: str,
        pro_features: Iterable[str] = (),
        storage_backend: Any = None,
        keyring: Mapping[str, str] | None = None,
    ) -> None:
        if product not in KNOWN_PRODUCTS:
            raise ValueError(f"unknown product {product!r}")
        self.product = product
        self._keyring: Mapping[str, str] = (
            PRODUCTION_KEYRING if keyring is None else MappingProxyType(dict(keyring))
        )
        self._lock = threading.RLock()
        self._storage = storage_backend
        self._pro_features: frozenset[str] = frozenset(pro_features)
        self._license: LicenseInfo = FREE_LICENSE
        self._validated_at: float = 0.0
        self._usage: dict[str, dict[str, Any]] = {}  # {month: {total, by_feature}}
        self._quota = int(os.getenv("OUBLIETTE_MONTHLY_QUOTA", str(DEFAULT_MONTHLY_QUOTA)))
        self._warned_80 = False
        self._warned_100 = False

        raw = os.getenv("OUBLIETTE_LICENSE_KEY", "")
        if raw:
            self._load_license(raw)
        else:
            self._validated_at = time.time()
            log.info("[LICENSE] No license key set -- running in free tier")

    # ------------------------------------------------------------------
    # License validation
    # ------------------------------------------------------------------

    def _load_license(self, raw_key: str) -> None:
        """Verify ``raw_key`` for this product; fall back to free on any failure."""
        with self._lock:
            self._validated_at = time.time()
            try:
                lic = verify_license_token(raw_key, product=self.product, keyring=self._keyring)
            except LicenseError as exc:
                log.warning("[LICENSE] %s -- falling back to free tier", exc)
                self._license = FREE_LICENSE
                return
            self._license = lic
            if lic.quota:
                self._quota = lic.quota
            log.info(
                "[LICENSE] Loaded %s license %s for %s (products %s, expires %s)",
                lic.tier,
                lic.lid,
                lic.org,
                ",".join(lic.products),
                lic.expires,
            )

    @property
    def license(self) -> LicenseInfo:
        """Current license, re-validated from the env once the cache expires."""
        with self._lock:
            if time.time() - self._validated_at > VALIDATION_CACHE_TTL:
                raw = os.getenv("OUBLIETTE_LICENSE_KEY", "")
                if raw:
                    self._load_license(raw)
                else:
                    self._validated_at = time.time()
            return self._license

    # ------------------------------------------------------------------
    # Feature gating (soft enforcement)
    # ------------------------------------------------------------------

    def check_feature(self, feature: str) -> bool:
        """Return whether ``feature`` is licensed; logs a warning if not."""
        lic = self.license
        if lic.tier == "enterprise":
            return True
        if feature in self._pro_features and not lic.has_feature(feature):
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


class FeatureGate:
    """Tier-based access control for Pro features.

    With a :class:`LicenseManager` the gate uses the manager's verified,
    product-scoped tier. Without one it cannot verify anything, so it stays at
    ``community`` unless ``insecure_simple_mode=True`` (DEV/TEST ONLY), which
    treats any non-empty key as Pro.

    Args:
        license_key: A license key string. Defaults to ``OUBLIETTE_LICENSE_KEY``.
        license_manager: Optional :class:`LicenseManager` to delegate to.
        community_features: Overrides the class ``COMMUNITY_FEATURES``.
        pro_features: Overrides the class ``PRO_FEATURES``.
        insecure_simple_mode: DEV/TEST ONLY opt-in described above.
    """

    COMMUNITY_FEATURES: frozenset[str] = frozenset()
    PRO_FEATURES: frozenset[str] = frozenset()
    ALL_FEATURES: frozenset[str] = frozenset()

    def __init__(
        self,
        license_key: str | None = None,
        license_manager: LicenseManager | None = None,
        *,
        community_features: Iterable[str] | None = None,
        pro_features: Iterable[str] | None = None,
        insecure_simple_mode: bool = False,
    ) -> None:
        self.license_key = license_key or os.getenv("OUBLIETTE_LICENSE_KEY", "")
        self._license_manager = license_manager
        self._insecure_simple_mode = insecure_simple_mode
        self._validated = False
        self._tier = "community"
        if community_features is not None:
            self.COMMUNITY_FEATURES = frozenset(community_features)
        if pro_features is not None:
            self.PRO_FEATURES = frozenset(pro_features)
        self.ALL_FEATURES = self.COMMUNITY_FEATURES | self.PRO_FEATURES

    def validate(self) -> bool:
        """Determine the tier. Returns ``True`` if Pro or Enterprise applies."""
        if self._license_manager is not None:
            lic = self._license_manager.license
            if lic.tier in PAID_TIERS:
                self._tier = lic.tier
                self._validated = True
            else:
                self._tier = "community"
                self._validated = False
            return self._validated

        # FAIL CLOSED: no manager means no signature verification, so an
        # unverified key must not grant Pro unless the dev/test opt-in is set.
        if self._insecure_simple_mode and self.license_key:
            log.warning(
                "[LICENSE] FeatureGate insecure simple mode is enabled -- any "
                "non-empty key grants Pro. Do NOT use in production."
            )
            self._tier = "pro"
            self._validated = True
        else:
            self._tier = "community"
            self._validated = False
        return self._validated

    def is_allowed(self, feature: str) -> bool:
        """Community features are always allowed; Pro needs a paid tier."""
        if feature in self.COMMUNITY_FEATURES:
            return True
        return self._tier in PAID_TIERS and feature in self.PRO_FEATURES

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
