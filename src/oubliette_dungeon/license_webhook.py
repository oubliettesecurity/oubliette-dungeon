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

from collections.abc import Mapping
from typing import Any

from .license_issuer import issue_license

_TRUTHY = {"true", "1", "yes", True}


def _is_true(v: Any) -> bool:
    return v in _TRUTHY or (isinstance(v, str) and v.strip().lower() == "true")


def license_for_sale(
    payload: Mapping[str, Any],
    product_map: Mapping[str, Mapping[str, Any]],
    signing_key: str,
    seller_id: str | None = None,
) -> dict[str, Any] | None:
    """Turn a Gumroad/Paddle sale payload into an issued license, or None.

    Returns None for ignorable events (unknown product, refund/dispute/cancel).
    Raises PermissionError if ``seller_id`` is set and does not match the payload.
    """
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
):  # pragma: no cover - thin Flask glue; logic is tested via license_for_sale
    """Flask blueprint exposing POST /webhooks/gumroad.

    ``deliver(result)`` is an optional callback to email/store the key; if omitted
    the key is only logged (wire an email sender in production).
    """
    from flask import Blueprint, jsonify, request

    bp = Blueprint("license_webhook", __name__)

    @bp.route("/webhooks/gumroad", methods=["POST"])
    def gumroad():
        payload = request.form.to_dict() or (request.get_json(silent=True) or {})
        try:
            result = license_for_sale(payload, product_map, signing_key, seller_id)
        except PermissionError:
            return jsonify({"error": "unauthorized"}), 403
        if result is None:
            return jsonify({"status": "ignored"}), 200
        if deliver is not None:
            deliver(result)
        return jsonify({"status": "issued", "email": result["email"], "tier": result["tier"]}), 200

    return bp
