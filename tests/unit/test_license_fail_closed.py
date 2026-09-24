"""License verification must fail CLOSED.

Regression for the Shield 2026-07-02 security review finding (ported to
Dungeon): when no signing key was configured, ``LicenseManager._load_license``
skipped HMAC verification entirely, so any base64 JSON blob claiming
``"tier": "enterprise"`` was trusted.
"""

import base64
import json

import pytest

from oubliette_dungeon.license import LicenseManager
from oubliette_dungeon.license_issuer import issue_license

SECRET = "dungeon-test-signing-key"


@pytest.fixture(autouse=True)
def _clean_license_env(monkeypatch):
    for var in ("OUBLIETTE_LICENSE_KEY", "OUBLIETTE_LICENSE_SIGNING_KEY"):
        monkeypatch.delenv(var, raising=False)


def _forged(payload: dict) -> str:
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def _tamper(key: str, **changes) -> str:
    data = json.loads(base64.b64decode(key))
    data.update(changes)
    return _forged(data)


def test_no_signing_key_rejects_validly_signed_license():
    key = issue_license(org="Acme", tier="pro", signing_key=SECRET)
    mgr = LicenseManager(signing_key="")  # misconfigured: no verification key
    mgr._load_license(key)
    assert mgr.license.tier == "free"
    assert mgr.license.org == ""


def test_no_signing_key_rejects_forged_unsigned_enterprise_license():
    forged = _forged({"tier": "enterprise", "org": "Mallory", "features": []})
    mgr = LicenseManager(signing_key="")
    mgr._load_license(forged)
    assert mgr.license.tier == "free"
    assert not mgr.license.has_feature("scheduler")


def test_no_signing_key_env_autoload_falls_back_to_free(monkeypatch):
    monkeypatch.setenv(
        "OUBLIETTE_LICENSE_KEY", _forged({"tier": "enterprise", "org": "Mallory", "sig": "x"})
    )
    mgr = LicenseManager()
    assert mgr.license.tier == "free"


def test_valid_signature_accepted():
    key = issue_license(org="Acme", tier="pro", signing_key=SECRET)
    mgr = LicenseManager(signing_key=SECRET)
    mgr._load_license(key)
    assert mgr.license.tier == "pro"
    assert mgr.license.org == "Acme"
    assert mgr.license.has_feature("scheduler")


def test_signing_key_from_env_accepted(monkeypatch):
    monkeypatch.setenv("OUBLIETTE_LICENSE_SIGNING_KEY", SECRET)
    monkeypatch.setenv(
        "OUBLIETTE_LICENSE_KEY", issue_license(org="Acme", tier="enterprise", signing_key=SECRET)
    )
    mgr = LicenseManager()
    assert mgr.license.tier == "enterprise"


def test_tampered_tier_rejected():
    key = issue_license(org="Acme", tier="pro", signing_key=SECRET)
    mgr = LicenseManager(signing_key=SECRET)
    mgr._load_license(_tamper(key, tier="enterprise"))
    assert mgr.license.tier == "free"


def test_tampered_features_rejected():
    key = issue_license(org="Acme", tier="pro", features=["webhooks"], signing_key=SECRET)
    mgr = LicenseManager(signing_key=SECRET)
    mgr._load_license(_tamper(key, features=["webhooks", "scheduler"]))
    assert mgr.license.tier == "free"


def test_missing_signature_rejected():
    mgr = LicenseManager(signing_key=SECRET)
    mgr._load_license(_forged({"tier": "pro", "org": "Acme"}))
    assert mgr.license.tier == "free"


def test_non_string_signature_rejected_without_crashing():
    mgr = LicenseManager(signing_key=SECRET)
    mgr._load_license(_forged({"tier": "pro", "org": "Acme", "sig": 12345}))
    assert mgr.license.tier == "free"
