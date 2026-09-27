"""Product-scoped license keys (schema v2) as seen by Dungeon.

Dungeon accepts a key only if it verifies against the embedded keyring
AND its signed ``products`` list contains ``"dungeon"``. Keys for other
products, legacy (pre-v2 / HMAC) keys and every malformed key give the free
tier. Keys here are throwaway Ed25519 keypairs generated at test time and
signed locally (the issuer lives only in oubliette-commerce).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
from typing import Any

import pytest

pytest.importorskip("cryptography")

from oubliette_dungeon import license as lic_mod
from oubliette_dungeon._license_core import (
    FREE_LICENSE,
    KNOWN_PRODUCTS,
    PRODUCTION_KEYRING,
    canonical_payload,
    generate_keypair,
)
from oubliette_dungeon.license import FeatureGate, LicenseManager

PRODUCT = "dungeon"
OTHER_PRODUCTS = sorted(KNOWN_PRODUCTS - {PRODUCT})
PRO_FEATURE = sorted(lic_mod.PRO_FEATURES)[0]
KID = "test-2026"
FAR_FUTURE = (datetime.date.today() + datetime.timedelta(days=365)).isoformat()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "OUBLIETTE_LICENSE_KEY",
        "OUBLIETTE_LICENSE_SIGNING_KEY",
        "OUBLIETTE_LICENSE_PUBLIC_KEY",
        "OUBLIETTE_INSECURE_DEV_FEATURE_GATE",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(scope="module")
def keypair() -> tuple[str, str]:
    return generate_keypair()


@pytest.fixture
def ring(keypair) -> dict[str, str]:
    return {KID: keypair[1]}


def _claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "v": 2,
        "kid": KID,
        "lid": "lid-0001",
        "products": [PRODUCT],
        "tier": "pro",
        "org": "Acme",
        "issued": "2026-01-01",
        "expires": FAR_FUTURE,
        "quota": 0,
        "features": [PRO_FEATURE],
        "sig_alg": "ed25519",
    }
    claims.update(overrides)
    return claims


def _sign(priv_b64: str, claims: dict[str, Any]) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    body = dict(claims)
    signer = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
    body["sig"] = base64.b64encode(signer.sign(canonical_payload(body))).decode()
    return base64.b64encode(json.dumps(body).encode()).decode()


def _mgr(ring: dict[str, str], token: str | None = None) -> LicenseManager:
    mgr = LicenseManager(keyring=ring)
    if token is not None:
        mgr._load_license(token)
    return mgr


# ---------------------------------------------------------------- scoping


def test_manager_is_scoped_to_this_product(ring):
    assert lic_mod.PRODUCT == PRODUCT
    assert _mgr(ring).product == PRODUCT


def test_own_product_key_unlocks_pro(keypair, ring):
    mgr = _mgr(ring, _sign(keypair[0], _claims()))
    assert mgr.license.tier == "pro"
    assert list(mgr.license.products) == [PRODUCT]
    assert mgr.check_feature(PRO_FEATURE) is True


@pytest.mark.parametrize("other", OTHER_PRODUCTS)
@pytest.mark.parametrize("tier", ["pro", "enterprise"])
def test_other_product_key_is_free_here(keypair, ring, other, tier):
    token = _sign(keypair[0], _claims(products=[other], tier=tier))
    mgr = _mgr(ring, token)
    assert mgr.license is FREE_LICENSE
    assert mgr.check_feature(PRO_FEATURE) is False


def test_bundle_including_this_product_unlocks(keypair, ring):
    token = _sign(keypair[0], _claims(products=sorted(KNOWN_PRODUCTS), tier="enterprise"))
    assert _mgr(ring, token).license.tier == "enterprise"


def test_bundle_excluding_this_product_is_free(keypair, ring):
    token = _sign(keypair[0], _claims(products=OTHER_PRODUCTS, tier="enterprise"))
    assert _mgr(ring, token).license.tier == "free"


def test_namespaced_features_apply_only_to_their_product(keypair, ring):
    other = OTHER_PRODUCTS[0]
    theirs = _sign(
        keypair[0],
        _claims(products=[PRODUCT, other], features=[f"{other}:{PRO_FEATURE}"]),
    )
    assert _mgr(ring, theirs).check_feature(PRO_FEATURE) is False
    ours = _sign(
        keypair[0],
        _claims(products=[PRODUCT, other], features=[f"{PRODUCT}:{PRO_FEATURE}"]),
    )
    assert _mgr(ring, ours).check_feature(PRO_FEATURE) is True


def test_env_key_is_read_and_scoped(keypair, ring, monkeypatch):
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", _sign(keypair[0], _claims()))
    assert LicenseManager(keyring=ring).license.tier == "pro"
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", _sign(keypair[0], _claims(products=OTHER_PRODUCTS)))
    assert LicenseManager(keyring=ring).license.tier == "free"


def test_tampered_products_fail_closed(keypair, ring):
    token = _sign(keypair[0], _claims(products=[OTHER_PRODUCTS[0]]))
    claims = json.loads(base64.b64decode(token))
    claims["products"] = [PRODUCT]
    forged = base64.b64encode(json.dumps(claims).encode()).decode()
    assert _mgr(ring, forged).license.tier == "free"


# ---------------------------------------------------------------- fail closed


def test_wrong_key_and_unknown_kid_fail_closed(keypair, ring):
    other_priv, _ = generate_keypair()
    assert _mgr(ring, _sign(other_priv, _claims())).license.tier == "free"
    assert _mgr(ring, _sign(keypair[0], _claims(kid="retired"))).license.tier == "free"


def test_production_keyring_rejects_throwaway_signatures(keypair):
    """The default keyring is the embedded production one; a test key never verifies."""
    kid = next(iter(PRODUCTION_KEYRING))
    mgr = LicenseManager()
    mgr._load_license(_sign(keypair[0], _claims(kid=kid)))
    assert mgr.license is FREE_LICENSE


def test_no_public_key_env_override(keypair, monkeypatch):
    monkeypatch.setenv("OUBLIETTE_LICENSE_PUBLIC_KEY", keypair[1])
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", _sign(keypair[0], _claims()))
    assert LicenseManager().license is FREE_LICENSE


@pytest.mark.parametrize(
    "overrides",
    [
        {"expires": "2020-01-01"},
        {"expires": ""},
        {"expires": "not-a-date"},
        {"expires": "2026-13-45"},
        {"expires": 20991231},
        {"v": 1},
        {"products": []},
        {"products": PRODUCT},
        {"tier": "platinum"},
        {"sig_alg": "hmac"},
    ],
)
def test_malformed_claims_fail_closed(keypair, ring, overrides):
    assert _mgr(ring, _sign(keypair[0], _claims(**overrides))).license.tier == "free"


@pytest.mark.parametrize("field", ["products", "kid", "lid", "v", "expires"])
def test_missing_claims_fail_closed(keypair, ring, field):
    claims = _claims()
    del claims[field]
    assert _mgr(ring, _sign(keypair[0], claims)).license.tier == "free"


def test_legacy_v1_ed25519_key_fails_closed(keypair, ring):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    body = {"tier": "enterprise", "org": "Acme", "issued": "2026-01-01", "expires": "",
            "quota": 0, "features": []}  # fmt: skip
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    signer = Ed25519PrivateKey.from_private_bytes(base64.b64decode(keypair[0]))
    sig = base64.b64encode(signer.sign(payload)).decode()
    token = base64.b64encode(json.dumps({**body, "sig_alg": "ed25519", "sig": sig}).encode())
    assert _mgr(ring, token.decode()).license.tier == "free"


def test_legacy_hmac_key_fails_closed_even_with_signing_key_env(ring, monkeypatch):
    secret = "dummy"
    body = {"tier": "enterprise", "org": "acme", "features": []}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    monkeypatch.setenv("OUBLIETTE_LICENSE_SIGNING_KEY", secret)
    monkeypatch.setenv(
        "OUBLIETTE_LICENSE_KEY",
        base64.b64encode(json.dumps({**body, "sig": sig}).encode()).decode(),
    )
    assert LicenseManager(keyring=ring).license.tier == "free"


def test_signing_key_argument_is_gone():
    with pytest.raises(TypeError):
        LicenseManager(signing_key="dummy")  # type: ignore[call-arg]


@pytest.mark.parametrize("raw", ["", "garbage", base64.b64encode(b"[1]").decode(), "A" * 9000])
def test_garbage_fails_closed(ring, raw):
    assert _mgr(ring, raw).license.tier == "free"


def test_missing_cryptography_fails_closed(keypair, ring, monkeypatch):
    import builtins

    token = _sign(keypair[0], _claims())
    real_import = builtins.__import__

    def no_crypto(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_crypto)
    assert _mgr(ring, token).license.tier == "free"


# ---------------------------------------------------------------- FeatureGate


def test_featuregate_follows_scoped_manager(keypair, ring):
    own = _mgr(ring, _sign(keypair[0], _claims()))
    gate = FeatureGate(license_manager=own)
    assert gate.validate() is True
    assert gate.tier == "pro"

    foreign = _mgr(ring, _sign(keypair[0], _claims(products=OTHER_PRODUCTS, tier="enterprise")))
    gate = FeatureGate(license_manager=foreign)
    assert gate.validate() is False
    assert gate.tier == "community"


def test_featuregate_dev_opt_in_unchanged(monkeypatch):
    assert FeatureGate(license_key="x").validate() is False
    assert FeatureGate(license_key="x", insecure_simple_mode=True).validate() is True
    monkeypatch.setenv("OUBLIETTE_INSECURE_DEV_FEATURE_GATE", "true")
    assert FeatureGate(license_key="x").validate() is True
    assert FeatureGate(license_key="x", insecure_simple_mode=False).validate() is False
