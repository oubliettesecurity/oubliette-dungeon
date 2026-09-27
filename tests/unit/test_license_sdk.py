"""Dungeon's license SDK: Dungeon-specific Pro features and a signed round trip.

Issuing (and the Gumroad/Paddle sale webhook) lives only in
oubliette-commerce; these tests sign schema-v2 keys locally with a throwaway
Ed25519 key (fixtures in tests/conftest.py).
"""

import pytest

pytest.importorskip("cryptography")

from oubliette_dungeon._license_core import generate_keypair
from oubliette_dungeon.license import PRO_FEATURES, LicenseManager


def test_issued_pro_key_validates(license_keypair, sign_dungeon_license):
    mgr = LicenseManager(keyring={"test-2026": license_keypair[1]})
    mgr._load_license(sign_dungeon_license(org="Acme Corp", features=["scheduler"]))
    assert mgr.license.tier == "pro"
    assert mgr.license.org == "Acme Corp"
    assert mgr.check_feature("scheduler") is True
    assert mgr.check_feature("full_scenario_library") is False


def test_pro_features_are_dungeon_specific():
    assert "scheduler" in PRO_FEATURES
    assert "full_scenario_library" in PRO_FEATURES
    assert "scan_output" not in PRO_FEATURES  # that was Shield's, not Dungeon's


def test_wrong_key_falls_back_to_free(sign_dungeon_license):
    _, other_pub = generate_keypair()
    mgr = LicenseManager(keyring={"test-2026": other_pub})
    mgr._load_license(sign_dungeon_license())
    assert mgr.license.tier == "free"


def test_trap_key_falls_back_to_free(license_keypair, sign_dungeon_license):
    mgr = LicenseManager(keyring={"test-2026": license_keypair[1]})
    mgr._load_license(sign_dungeon_license(products=["trap"], tier="enterprise"))
    assert mgr.license.tier == "free"
