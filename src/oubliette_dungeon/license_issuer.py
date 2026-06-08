"""
Oubliette Dungeon - License Issuer (server-side)

Mints signed license keys that ``license.LicenseManager`` accepts. This is the
counterpart to the client-side validator in ``license.py``: it signs the same
JSON payload with the shared HMAC signing key and base64-encodes it.

Keep the signing key (``OUBLIETTE_LICENSE_SIGNING_KEY``) SERVER-SIDE ONLY — it
is the secret that authorizes Pro/Enterprise tiers. The same module powers the
Gumroad/Paddle webhook handler (``license_webhook.py``).

Usage:
    from oubliette_dungeon.license_issuer import issue_license
    key = issue_license(org="Acme", tier="pro", features=[...], signing_key=SECRET)
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
from collections.abc import Sequence

from .license import PRO_FEATURES


def issue_license(
    org: str,
    tier: str = "pro",
    *,
    expires: str = "",
    features: Sequence[str] | None = None,
    quota: int = 0,
    issued: str | None = None,
    signing_key: str | None = None,
) -> str:
    """Mint a base64 license key validated by ``LicenseManager``.

    Args:
        org: Customer / organization name (appears in the license).
        tier: "free", "pro", or "enterprise".
        expires: ISO date "YYYY-MM-DD" or "" for perpetual.
        features: Pro feature names to grant. Defaults to all PRO_FEATURES for
            the "pro" tier; ignored for "enterprise" (which unlocks everything).
        quota: Monthly quota override (0 = tier default).
        issued: ISO issue date; defaults to today.
        signing_key: HMAC signing secret; falls back to
            ``OUBLIETTE_LICENSE_SIGNING_KEY``. Required.

    Returns:
        A base64-encoded, signed license key string.
    """
    signing_key = signing_key or os.getenv("OUBLIETTE_LICENSE_SIGNING_KEY", "")
    if not signing_key:
        raise ValueError("signing_key is required to issue a license")

    if features is None:
        features = sorted(PRO_FEATURES) if tier == "pro" else []

    data = {
        "tier": tier,
        "org": org,
        "issued": issued or datetime.date.today().isoformat(),
        "expires": expires,
        "quota": quota,
        "features": list(features),
    }

    # Sign the EXACT serialization the validator reconstructs (sorted + compact).
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(
        signing_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    full = dict(data)
    full["sig"] = sig
    return base64.b64encode(json.dumps(full).encode("utf-8")).decode("ascii")


if __name__ == "__main__":  # pragma: no cover - CLI convenience
    import argparse

    ap = argparse.ArgumentParser(description="Mint an Oubliette Dungeon license key")
    ap.add_argument("--org", required=True)
    ap.add_argument("--tier", default="pro", choices=["free", "pro", "enterprise"])
    ap.add_argument("--expires", default="", help="YYYY-MM-DD or empty for perpetual")
    ap.add_argument("--quota", type=int, default=0)
    ap.add_argument("--features", nargs="*", default=None)
    args = ap.parse_args()
    print(
        issue_license(
            org=args.org,
            tier=args.tier,
            expires=args.expires,
            quota=args.quota,
            features=args.features,
        )
    )
