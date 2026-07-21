"""
Oubliette Dungeon - Gumroad/Paddle sale -> license-key webhook.

On a sale, the merchant-of-record (Gumroad/Paddle) POSTs a "ping" to our
endpoint. We map the purchased product to a tier, mint a signed Oubliette
license key (``license_issuer.issue_license``), and return it for delivery
(email / receipt). Subscriptions re-ping on renewal, refreshing the key's
expiry.

The signing key (``OUBLIETTE_LICENSE_SIGNING_KEY``) and product map live
server-side. Deploy ``create_license_webhook_blueprint`` behind the existing
Flask app or a tiny standalone service.
"""

import hashlib
import hmac
import os
from collections.abc import Mapping
from typing import Any

from .license_issuer import issue_license

_TRUTHY = {"true", "1", "yes", True}


def _is_true(v: Any) -> bool:
    return v in _TRUTHY or (isinstance(v, str) and v.strip().lower() == "true")


def verify_webhook_signature(raw_body: bytes, signature: str | None, secret: str | None) -> bool:
    """Constant-time HMAC-SHA256 verification of a webhook body.

    Fail-closed: this endpoint mints signed Pro/Enterprise license keys, so
    authentication is NOT optional. A missing/unconfigured ``secret``, a
    missing ``signature``, or a signature that does not match the exact raw
    request body all return ``False``.

    Accepts an optional ``sha256=`` prefix and is case-insensitive on the hex
    digest, matching how merchant-of-record providers format signature headers.
    """
    if not secret:
        return False
    if not signature:
        return False
    expected = hmac.new(secret.encode(), raw_body or b"", hashlib.sha256).hexdigest()
    provided = signature.split("=", 1)[-1].strip().lower()
    return hmac.compare_digest(expected, provided)


def license_for_sale(
    payload: Mapping[str, Any],
    product_map: Mapping[str, Mapping[str, Any]],
    signing_key: str,
    seller_id: str | None = None,
    *,
    webhook_secret: str | None = None,
    raw_body: bytes | None = None,
    signature: str | None = None,
) -> dict[str, Any] | None:
    """Turn a Gumroad/Paddle sale payload into an issued license, or None.

    Returns None for ignorable events (unknown product, refund/dispute/cancel).

    Authentication (fail-closed, mandatory): a valid HMAC-SHA256 ``signature``
    over ``raw_body``, verified against ``webhook_secret``, is REQUIRED before
    any license is minted — this is the cryptographic gate (CRIT-1) that stops
    a forged sale POST from minting a real license. An unset/unconfigured
    ``webhook_secret`` is rejected, not treated as "no auth required". The
    legacy ``seller_id`` equality check is retained as a secondary,
    non-authoritative guard.
    Raises PermissionError on an invalid/missing signature, a missing/unset
    webhook secret, or a ``seller_id`` mismatch.
    """
    if not verify_webhook_signature(raw_body or b"", signature, webhook_secret):
        raise PermissionError("invalid or missing webhook signature")
    if seller_id and payload.get("seller_id") != seller_id:
        raise PermissionError("seller_id mismatch")

    # Ignore reversals / cancellations.
    if any(_is_true(payload.get(k)) for k in ("refunded", "disputed", "cancelled", "chargedback")):
        return None

    permalink = (
        payload.get("product_permalink")
        or payload.get("permalink")
        or payload.get("short_product_id")
        or payload.get("product_id")
        or ""
    )
    cfg = product_map.get(permalink)
    if not cfg:
        return None

    email = str(payload.get("email", ""))
    org = str(payload.get("full_name") or payload.get("organization") or email)

    key = issue_license(
        org=org,
        tier=cfg["tier"],
        features=cfg.get("features"),
        quota=int(cfg.get("quota", 0)),
        expires=str(cfg.get("expires", "")),
        signing_key=signing_key,
    )
    return {"email": email, "org": org, "tier": cfg["tier"], "license_key": key}


def create_license_webhook_blueprint(
    product_map: Mapping[str, Mapping[str, Any]],
    signing_key: str,
    seller_id: str | None = None,
    deliver=None,
    webhook_secret: str | None = None,
):  # pragma: no cover - thin Flask glue; logic is tested via license_for_sale
    """Flask blueprint exposing POST /webhooks/gumroad.

    ``deliver(result)`` is an optional callback to email/store the key; if omitted
    the key is only logged (wire an email sender in production).

    ``webhook_secret`` gates minting behind a mandatory, fail-closed HMAC-SHA256
    signature over the raw body. Defaults to ``$OUBLIETTE_WEBHOOK_SECRET``; if
    left unconfigured, EVERY request is rejected (401) rather than falling back
    to unauthenticated minting.
    """
    from flask import Blueprint, jsonify, request

    secret = (
        webhook_secret if webhook_secret is not None else os.environ.get("OUBLIETTE_WEBHOOK_SECRET")
    )
    bp = Blueprint("license_webhook", __name__)

    @bp.route("/webhooks/gumroad", methods=["POST"])
    def gumroad():
        raw_body = request.get_data()  # exact bytes the signature was computed over
        signature = (
            request.headers.get("X-Signature")
            or request.headers.get("Paddle-Signature")
            or request.headers.get("X-Gumroad-Signature")
        )
        payload = request.form.to_dict() or (request.get_json(silent=True) or {})
        try:
            result = license_for_sale(
                payload,
                product_map,
                signing_key,
                seller_id,
                webhook_secret=secret,
                raw_body=raw_body,
                signature=signature,
            )
        except PermissionError:
            return jsonify({"error": "unauthorized"}), 401
        if result is None:
            return jsonify({"status": "ignored"}), 200
        if deliver is not None:
            deliver(result)
        return jsonify({"status": "issued", "email": result["email"], "tier": result["tier"]}), 200

    return bp
