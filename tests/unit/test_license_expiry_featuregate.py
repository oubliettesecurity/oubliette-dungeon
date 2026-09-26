"""Fail-closed regression tests for license expiry parsing and FeatureGate.

- A correctly signed license whose ``expires`` cannot be parsed must fall back
  to the free tier (it was previously treated as never expiring).
- ``FeatureGate`` without a ``LicenseManager`` cannot verify a key, so it must
  stay at ``community`` unless the explicit dev/test opt-in is enabled.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json

import pytest

from oubliette_dungeon.license import FeatureGate, LicenseManager

PRO_FEATURE = sorted(FeatureGate.PRO_FEATURES)[0]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "OUBLIETTE_LICENSE_KEY",
        "OUBLIETTE_LICENSE_SIGNING_KEY",
        "OUBLIETTE_LICENSE_PUBLIC_KEY",
        "OUBLIETTE_INSECURE_DEV_FEATURE_GATE",
    ):
        monkeypatch.delenv(var, raising=False)


SIGNING_KEY = "test-signing-key"


@pytest.fixture
def keypair():
    # Dungeon verifies HMAC-SHA256; (signing key, verification key) are equal.
    return SIGNING_KEY, SIGNING_KEY


def _signed(key: str, **overrides) -> str:
    """HMAC-sign an arbitrary payload (lets tests use non-string expiries)."""
    body = {
        "tier": "enterprise",
        "org": "Acme",
        "issued": "2026-01-01",
        "expires": "",
        "quota": 0,
        "features": [],
    }
    body.update(overrides)
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return base64.b64encode(json.dumps({**body, "sig": sig}).encode()).decode()


def _load(key: str, token: str) -> LicenseManager:
    mgr = LicenseManager(signing_key=key)
    mgr._load_license(token)
    return mgr


# ---------------------------------------------------------------- expiry


def test_future_expiry_is_accepted(keypair):
    priv, pub = keypair
    future = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    assert _load(pub, _signed(priv, expires=future)).license.tier == "enterprise"


def test_empty_expiry_is_perpetual(keypair):
    priv, pub = keypair
    assert _load(pub, _signed(priv, expires="")).license.tier == "enterprise"


def test_past_expiry_is_rejected(keypair):
    priv, pub = keypair
    assert _load(pub, _signed(priv, expires="2020-01-01")).license.tier == "free"


@pytest.mark.parametrize("bad", ["not-a-date", "2026-13-45", "31/12/2099", " "])
def test_unparseable_expiry_fails_closed(keypair, bad):
    priv, pub = keypair
    lic = _load(pub, _signed(priv, expires=bad)).license
    assert lic.tier == "free"
    assert not lic.has_feature(PRO_FEATURE)


@pytest.mark.parametrize("bad", [20991231, ["2099-12-31"], {"date": "2099-12-31"}])
def test_non_string_expiry_fails_closed_without_crashing(keypair, bad):
    priv, pub = keypair
    assert _load(pub, _signed(priv, expires=bad)).license.tier == "free"


# ---------------------------------------------------------------- FeatureGate


def test_featuregate_without_manager_rejects_unverified_key():
    gate = FeatureGate(license_key="any-non-empty-string")
    assert gate.validate() is False
    assert gate.tier == "community"
    assert gate.is_allowed(PRO_FEATURE) is False
    with pytest.raises(PermissionError):
        gate.require(PRO_FEATURE)


def test_featuregate_without_manager_reads_env_key_but_stays_community(monkeypatch):
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", "forged")
    gate = FeatureGate()
    assert gate.validate() is False
    assert gate.tier == "community"


def test_featuregate_community_features_still_allowed():
    gate = FeatureGate(license_key="x")
    gate.validate()
    for feature in FeatureGate.COMMUNITY_FEATURES:
        assert gate.is_allowed(feature) is True


def test_featuregate_insecure_simple_mode_kwarg_opt_in():
    gate = FeatureGate(license_key="x", insecure_simple_mode=True)
    assert gate.validate() is True
    assert gate.tier == "pro"
    assert gate.is_allowed(PRO_FEATURE) is True


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes"])
def test_featuregate_insecure_env_opt_in(monkeypatch, value):
    monkeypatch.setenv("OUBLIETTE_INSECURE_DEV_FEATURE_GATE", value)
    gate = FeatureGate(license_key="x")
    assert gate.validate() is True
    assert gate.tier == "pro"


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off"])
def test_featuregate_insecure_env_off_values(monkeypatch, value):
    monkeypatch.setenv("OUBLIETTE_INSECURE_DEV_FEATURE_GATE", value)
    assert FeatureGate(license_key="x").validate() is False


def test_featuregate_kwarg_false_overrides_env(monkeypatch):
    monkeypatch.setenv("OUBLIETTE_INSECURE_DEV_FEATURE_GATE", "true")
    assert FeatureGate(license_key="x", insecure_simple_mode=False).validate() is False


def test_featuregate_insecure_mode_still_needs_a_key():
    assert FeatureGate(license_key="", insecure_simple_mode=True).validate() is False


def test_featuregate_with_manager_still_grants_verified_license(keypair):
    priv, pub = keypair
    mgr = _load(pub, _signed(priv, tier="pro", features=[PRO_FEATURE]))
    gate = FeatureGate(license_manager=mgr)
    assert gate.validate() is True
    assert gate.tier == "pro"


def test_featuregate_with_manager_rejects_forged_license(keypair):
    _priv, pub = keypair
    mgr = _load(pub, _signed("some-other-key", tier="enterprise"))
    gate = FeatureGate(license_manager=mgr)
    assert gate.validate() is False
    assert gate.tier == "community"
