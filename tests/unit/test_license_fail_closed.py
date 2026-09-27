"""License verification must fail CLOSED.

Regression for the Shield 2026-07-02 security review finding (ported to
Dungeon): when no signing key was configured, ``LicenseManager._load_license``
skipped HMAC verification entirely, so any base64 JSON blob claiming
``"tier": "enterprise"`` was trusted. Schema v2 removes HMAC altogether: only
Ed25519 keys signed for product ``"dungeon"`` and verified against the
embedded keyring count.
"""

import base64
import hashlib
import hmac
import json

import pytest

pytest.importorskip("cryptography")

from oubliette_dungeon._license_core import FREE_LICENSE
from oubliette_dungeon.license import LicenseManager


def _forged(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def _tamper(key: str, **changes) -> str:
    data = json.loads(base64.b64decode(key))
    data.update(changes)
    return _forged(data)


def _mgr(license_keypair, token=None):
    mgr = LicenseManager(keyring={"test-2026": license_keypair[1]})
    if token is not None:
        mgr._load_license(token)
    return mgr


def test_forged_unsigned_enterprise_license_rejected(license_keypair):
    mgr = _mgr(license_keypair, _forged({"tier": "enterprise", "org": "Mallory", "features": []}))
    assert mgr.license.tier == "free"
    assert not mgr.license.has_feature("scheduler")


def test_env_autoload_of_forged_license_falls_back_to_free(monkeypatch):
    monkeypatch.setenv(
        "OUBLIETTE_LICENSE_KEY", _forged({"tier": "enterprise", "org": "Mallory", "sig": "x"})
    )
    assert LicenseManager().license.tier == "free"


def test_legacy_hmac_license_rejected_even_with_signing_key_env(monkeypatch, license_keypair):
    body = {"tier": "enterprise", "org": "Acme", "features": []}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(b"dummy", payload.encode(), hashlib.sha256).hexdigest()
    monkeypatch.setenv("OUBLIETTE_LICENSE_SIGNING_KEY", "dummy")
    assert _mgr(license_keypair, _forged({**body, "sig": sig})).license is FREE_LICENSE


def test_valid_signature_accepted(license_keypair, sign_dungeon_license):
    mgr = _mgr(license_keypair, sign_dungeon_license(features=["scheduler"]))
    assert mgr.license.tier == "pro"
    assert mgr.license.org == "Acme"
    assert mgr.license.has_feature("scheduler")


def test_env_license_key_accepted(monkeypatch, trust_test_key, sign_dungeon_license):
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", sign_dungeon_license(tier="enterprise"))
    assert LicenseManager().license.tier == "enterprise"


def test_tampered_tier_rejected(license_keypair, sign_dungeon_license):
    token = _tamper(sign_dungeon_license(), tier="enterprise")
    assert _mgr(license_keypair, token).license.tier == "free"


def test_tampered_features_rejected(license_keypair, sign_dungeon_license):
    token = _tamper(sign_dungeon_license(features=["webhooks"]), features=["webhooks", "scheduler"])
    assert _mgr(license_keypair, token).license.tier == "free"


def test_tampered_products_rejected(license_keypair, sign_dungeon_license):
    token = _tamper(sign_dungeon_license(products=["shield"]), products=["dungeon"])
    assert _mgr(license_keypair, token).license.tier == "free"


def test_missing_signature_rejected(license_keypair, sign_dungeon_license):
    claims = json.loads(base64.b64decode(sign_dungeon_license()))
    del claims["sig"]
    assert _mgr(license_keypair, _forged(claims)).license.tier == "free"


@pytest.mark.parametrize("sig", [12345, None, "", "!!!!"])
def test_bad_signature_types_rejected_without_crashing(license_keypair, sign_dungeon_license, sig):
    token = _tamper(sign_dungeon_license(), sig=sig)
    assert _mgr(license_keypair, token).license.tier == "free"


def test_signing_key_argument_is_gone():
    with pytest.raises(TypeError):
        LicenseManager(signing_key="dummy")  # type: ignore[call-arg]
