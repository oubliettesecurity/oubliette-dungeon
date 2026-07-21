"""Tests for the Gumroad sale -> license-key webhook logic.

CRIT-1 (2026-07-19): the webhook minted signed Pro/Enterprise licenses on ANY
POST, validating only the public ``seller_id`` payload field. These tests lock
in the fix: HMAC-SHA256 verification over the raw request body is now MANDATORY
and fail-closed — missing secret, missing signature, or wrong signature must
all reject before any key is minted. The legacy ``seller_id`` check remains as
a secondary, non-authoritative guard.
"""

import hashlib
import hmac as _hmac

import pytest

from oubliette_dungeon.license import LicenseManager
from oubliette_dungeon.license_webhook import license_for_sale, verify_webhook_signature

SECRET = "wh-signing-secret"
WEBHOOK_SECRET = "wh-endpoint-secret"
PRODUCT_MAP = {
    "oubliette-dungeon-pro": {"tier": "pro"},
    "oubliette-dungeon-ent": {"tier": "enterprise"},
}

_BODY = b"seller_id=SELLER123&product_permalink=oubliette-dungeon-pro&email=buyer@acme.com"


def _sign(body: bytes, secret: str = WEBHOOK_SECRET) -> str:
    return _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _pro_sale(**over):
    base = {
        "seller_id": "SELLER123",
        "product_permalink": "oubliette-dungeon-pro",
        "email": "buyer@acme.com",
        "full_name": "Acme Corp",
        "sale_id": "S1",
        "refunded": "false",
        "disputed": "false",
    }
    base.update(over)
    return base


# --- verify_webhook_signature: constant-time HMAC, fail-closed -----------------


def test_verify_signature_accepts_valid():
    assert verify_webhook_signature(_BODY, _sign(_BODY), WEBHOOK_SECRET) is True


def test_verify_signature_accepts_prefixed_and_uppercase():
    assert verify_webhook_signature(_BODY, "sha256=" + _sign(_BODY).upper(), WEBHOOK_SECRET) is True


def test_verify_signature_rejects_wrong():
    assert verify_webhook_signature(_BODY, "deadbeef", WEBHOOK_SECRET) is False


def test_verify_signature_rejects_missing_signature():
    assert verify_webhook_signature(_BODY, None, WEBHOOK_SECRET) is False


def test_verify_signature_rejects_missing_secret():
    # Fail-closed: an unconfigured secret must NOT be treated as "no auth required".
    assert verify_webhook_signature(_BODY, _sign(_BODY), None) is False
    assert verify_webhook_signature(_BODY, None, None) is False


# --- license_for_sale: HMAC gate before any key is minted ----------------------


def test_unsigned_request_rejected_no_key_minted():
    with pytest.raises(PermissionError):
        license_for_sale(
            _pro_sale(), PRODUCT_MAP, SECRET,
            webhook_secret=WEBHOOK_SECRET, raw_body=_BODY, signature=None,
        )


def test_wrong_signature_rejected():
    with pytest.raises(PermissionError):
        license_for_sale(
            _pro_sale(), PRODUCT_MAP, SECRET,
            webhook_secret=WEBHOOK_SECRET, raw_body=_BODY, signature="0" * 64,
        )


def test_missing_secret_fails_closed():
    with pytest.raises(PermissionError):
        license_for_sale(
            _pro_sale(), PRODUCT_MAP, SECRET,
            webhook_secret=None, raw_body=_BODY, signature=_sign(_BODY),
        )


def test_valid_signature_mints_as_before():
    res = license_for_sale(
        _pro_sale(), PRODUCT_MAP, SECRET,
        webhook_secret=WEBHOOK_SECRET, raw_body=_BODY, signature=_sign(_BODY),
    )
    assert res is not None and res["tier"] == "pro"
    mgr = LicenseManager(signing_key=SECRET)
    mgr._load_license(res["license_key"])
    assert mgr.license.tier == "pro"
    assert mgr.license.org == "Acme Corp"


def test_unknown_product_returns_none_when_signed():
    res = license_for_sale(
        _pro_sale(product_permalink="something-else"), PRODUCT_MAP, SECRET,
        webhook_secret=WEBHOOK_SECRET, raw_body=_BODY, signature=_sign(_BODY),
    )
    assert res is None


def test_refunded_sale_issues_nothing_when_signed():
    res = license_for_sale(
        _pro_sale(refunded="true"), PRODUCT_MAP, SECRET,
        webhook_secret=WEBHOOK_SECRET, raw_body=_BODY, signature=_sign(_BODY),
    )
    assert res is None


def test_seller_id_mismatch_still_rejected_as_secondary_guard():
    with pytest.raises(PermissionError):
        license_for_sale(
            _pro_sale(seller_id="EVIL"), PRODUCT_MAP, SECRET, seller_id="SELLER123",
            webhook_secret=WEBHOOK_SECRET, raw_body=_BODY, signature=_sign(_BODY),
        )
