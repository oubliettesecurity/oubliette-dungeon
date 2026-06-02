"""Verify the ported revenue SDK works in Dungeon (issuer -> validator round-trip)."""

from oubliette_dungeon.license import LicenseManager, PRO_FEATURES
from oubliette_dungeon.license_issuer import issue_license
from oubliette_dungeon.license_webhook import license_for_sale


def test_issued_pro_key_validates():
    key = issue_license(org="Acme Corp", tier="pro", signing_key="dungeon-secret")
    mgr = LicenseManager(signing_key="dungeon-secret")
    mgr._load_license(key)
    assert mgr.license.tier == "pro"
    assert mgr.license.org == "Acme Corp"


def test_pro_features_are_dungeon_specific():
    assert "scheduler" in PRO_FEATURES
    assert "full_scenario_library" in PRO_FEATURES
    assert "scan_output" not in PRO_FEATURES  # that was Shield's, not Dungeon's


def test_wrong_key_falls_back_to_free():
    key = issue_license(org="Acme", tier="pro", signing_key="right")
    mgr = LicenseManager(signing_key="wrong")
    mgr._load_license(key)
    assert mgr.license.tier == "free"


def test_webhook_issues_validating_key():
    res = license_for_sale(
        {"product_permalink": "oubliette-dungeon-pro", "email": "a@b.com", "full_name": "Acme"},
        {"oubliette-dungeon-pro": {"tier": "pro"}},
        "dungeon-secret",
    )
    assert res is not None and res["tier"] == "pro"
    mgr = LicenseManager(signing_key="dungeon-secret")
    mgr._load_license(res["license_key"])
    assert mgr.license.tier == "pro"
