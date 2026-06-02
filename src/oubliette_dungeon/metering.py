"""
Oubliette Dungeon - Usage Metering & Cost Tracking
==================================================
Extends the license layer with fine-grained usage tracking,
token metering, persistent storage, hard quota enforcement,
and cost calculation for Pro/Enterprise tiers.

Integrates with LicenseManager for tier-aware enforcement.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger(__name__)


# ======================================================================
# Tier pricing (per-unit costs in USD)
# ======================================================================

TIER_PRICING: dict[str, dict[str, float]] = {
    "free": {
        "api_call": 0.0,
        "input_token": 0.0,
        "output_token": 0.0,
        "detection": 0.0,
        "export": 0.0,
    },
    "pro": {
        "api_call": 0.001,
        "input_token": 0.00003,
        "output_token": 0.00006,
        "detection": 0.0005,
        "export": 0.10,
    },
    "enterprise": {
        "api_call": 0.0008,
        "input_token": 0.000025,
        "output_token": 0.00005,
        "detection": 0.0004,
        "export": 0.05,
    },
}

# Default monthly quotas per tier
TIER_QUOTAS: dict[str, dict[str, int]] = {
    "free": {"api_calls": 10_000, "tokens": 0, "exports": 0},
    "pro": {"api_calls": 1_000_000, "tokens": 50_000_000, "exports": 1000},
    "enterprise": {"api_calls": 0, "tokens": 0, "exports": 0},  # 0 = unlimited
}


@dataclass
class UsageEvent:
    """A single metered usage event."""

    timestamp: str
    event_type: str  # api_call, input_token, output_token, detection, export
    feature: str  # analyze, scan_output, spectre, etc.
    quantity: int = 1
    org_id: str = ""
    api_key_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    # HIGH-3 fix: when soft-enforce lets an over-quota event through, the
    # event is still recorded but tagged so billing systems can flag
    # overage. Previously over-quota events were indistinguishable from
    # within-quota events, producing a billing leak.
    over_quota: bool = False


@dataclass
class UsageSummary:
    """Aggregated usage for a time period."""

    month: str
    org_id: str
    api_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    detections: int = 0
    exports: int = 0
    estimated_cost: float = 0.0
    by_feature: dict[str, int] = field(default_factory=dict)


class QuotaExceeded(Exception):
    """Raised when a hard quota limit is hit."""


class UsageTracker:
    """Fine-grained usage tracking with optional SQLite persistence.

    Works standalone or integrated with LicenseManager for tier-aware
    quota enforcement and cost calculation.

    Args:
        tier: License tier ("free", "pro", "enterprise").
        org_id: Organization identifier.
        db_path: Path to SQLite DB for persistence. None = in-memory only.
        hard_enforce: If True, raise QuotaExceeded when limits are hit.
    """

    def __init__(
        self,
        tier: str = "free",
        org_id: str = "",
        db_path: str | None = None,
        hard_enforce: bool = False,
    ):
        self.tier = tier
        self.org_id = org_id
        self.hard_enforce = hard_enforce
        self._lock = threading.RLock()

        # In-memory counters: {month: UsageSummary}
        self._summaries: dict[str, UsageSummary] = {}

        # SQLite persistence
        self._db: sqlite3.Connection | None = None
        if db_path:
            self._init_db(db_path)

    def _init_db(self, db_path: str) -> None:
        """Initialize SQLite tables for usage persistence."""
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS usage_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                feature TEXT NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 1,
                org_id TEXT NOT NULL DEFAULT '',
                api_key_hash TEXT NOT NULL DEFAULT '',
                metadata TEXT NOT NULL DEFAULT '{}'
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS monthly_summaries (
                month TEXT NOT NULL,
                org_id TEXT NOT NULL DEFAULT '',
                api_calls INTEGER NOT NULL DEFAULT 0,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                detections INTEGER NOT NULL DEFAULT 0,
                exports INTEGER NOT NULL DEFAULT 0,
                estimated_cost REAL NOT NULL DEFAULT 0.0,
                PRIMARY KEY (month, org_id)
            )
        """)
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_month ON usage_events (timestamp, org_id)"
        )
        self._db.commit()

    # ------------------------------------------------------------------
    # Month key helper
    # ------------------------------------------------------------------

    @staticmethod
    def _month_key() -> str:
        return datetime.now(UTC).strftime("%Y-%m")

    # ------------------------------------------------------------------
    # Quota checking
    # ------------------------------------------------------------------

    def _get_quota(self, quota_type: str) -> int:
        """Get the quota limit for the current tier. 0 = unlimited."""
        return TIER_QUOTAS.get(self.tier, TIER_QUOTAS["free"]).get(quota_type, 0)

    def check_quota(self, event_type: str, quantity: int = 1) -> bool:
        """Check if the event would exceed quota. Optionally raises."""
        month = self._month_key()
        summary = self._get_or_create_summary(month)

        quota_map = {
            "api_call": ("api_calls", summary.api_calls),
            "input_token": ("tokens", summary.input_tokens + summary.output_tokens),
            "output_token": ("tokens", summary.input_tokens + summary.output_tokens),
            "detection": ("api_calls", summary.api_calls),
            "export": ("exports", summary.exports),
        }

        quota_type, current = quota_map.get(event_type, ("api_calls", 0))
        limit = self._get_quota(quota_type)

        if limit > 0 and current + quantity > limit:
            msg = (
                f"Quota exceeded: {quota_type} {current + quantity}/{limit} for tier '{self.tier}'"
            )
            if self.hard_enforce:
                raise QuotaExceeded(msg)
            log.warning("[METERING] %s", msg)
            return False
        return True

    # ------------------------------------------------------------------
    # Recording usage
    # ------------------------------------------------------------------

    def record(
        self,
        event_type: str,
        feature: str = "analyze",
        quantity: int = 1,
        api_key_hash: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Record a usage event. Thread-safe.

        Returns ``True`` if the event was within quota, ``False`` if it
        exceeded quota on a soft-enforce deployment (the event is still
        recorded but tagged ``over_quota=True`` so billing systems can
        flag the overage). On ``hard_enforce=True`` an over-quota event
        raises :class:`QuotaExceeded` instead of returning.

        HIGH-3 fix (2026-04-22 audit): the previous implementation
        discarded the ``check_quota()`` return value on soft-enforce, so
        callers could not distinguish an over-quota record from a normal
        one. That made Pro-tier billing unable to separate paid usage
        from overage usage.
        """
        within_quota = self.check_quota(event_type, quantity)

        event = UsageEvent(
            timestamp=datetime.now(UTC).isoformat(),
            event_type=event_type,
            feature=feature,
            quantity=quantity,
            org_id=self.org_id,
            api_key_hash=api_key_hash,
            metadata=metadata or {},
            over_quota=not within_quota,
        )

        with self._lock:
            month = self._month_key()
            summary = self._get_or_create_summary(month)

            # Update in-memory counters
            if event_type == "api_call":
                summary.api_calls += quantity
            elif event_type == "input_token":
                summary.input_tokens += quantity
            elif event_type == "output_token":
                summary.output_tokens += quantity
            elif event_type == "detection":
                summary.detections += quantity
            elif event_type == "export":
                summary.exports += quantity

            summary.by_feature[feature] = summary.by_feature.get(feature, 0) + quantity

            # Recalculate cost
            summary.estimated_cost = self._calculate_cost(summary)

            # Persist if DB available
            if self._db is not None:
                self._persist_event(event)
                self._persist_summary(summary)

        return within_quota

    def record_llm_usage(
        self,
        feature: str,
        input_tokens: int,
        output_tokens: int,
        api_key_hash: str = "",
    ) -> None:
        """Convenience method for recording LLM token usage."""
        self.record("api_call", feature, 1, api_key_hash)
        if input_tokens > 0:
            self.record("input_token", feature, input_tokens, api_key_hash)
        if output_tokens > 0:
            self.record("output_token", feature, output_tokens, api_key_hash)

    # ------------------------------------------------------------------
    # Cost calculation
    # ------------------------------------------------------------------

    def _calculate_cost(self, summary: UsageSummary) -> float:
        """Calculate estimated cost based on tier pricing."""
        pricing = TIER_PRICING.get(self.tier, TIER_PRICING["free"])
        cost = (
            summary.api_calls * pricing["api_call"]
            + summary.input_tokens * pricing["input_token"]
            + summary.output_tokens * pricing["output_token"]
            + summary.detections * pricing["detection"]
            + summary.exports * pricing["export"]
        )
        return round(cost, 4)

    def get_current_cost(self) -> float:
        """Get estimated cost for the current month."""
        with self._lock:
            summary = self._get_or_create_summary(self._month_key())
            return summary.estimated_cost

    # ------------------------------------------------------------------
    # Query usage
    # ------------------------------------------------------------------

    def _get_or_create_summary(self, month: str) -> UsageSummary:
        """Get or create a monthly summary. Caller must hold _lock or call within locked context."""
        if month not in self._summaries:
            self._summaries[month] = UsageSummary(
                month=month,
                org_id=self.org_id,
            )
        return self._summaries[month]

    def get_summary(self, month: str | None = None) -> UsageSummary:
        """Get usage summary for a month (default: current)."""
        with self._lock:
            key = month or self._month_key()
            return self._get_or_create_summary(key)

    def get_summary_dict(self, month: str | None = None) -> dict[str, Any]:
        """Get usage summary as a dict (for API responses)."""
        summary = self.get_summary(month)
        quota_info = {k: self._get_quota(k) for k in ("api_calls", "tokens", "exports")}
        return {
            "month": summary.month,
            "org_id": summary.org_id,
            "tier": self.tier,
            "api_calls": summary.api_calls,
            "input_tokens": summary.input_tokens,
            "output_tokens": summary.output_tokens,
            "detections": summary.detections,
            "exports": summary.exports,
            "estimated_cost_usd": summary.estimated_cost,
            "by_feature": dict(summary.by_feature),
            "quotas": quota_info,
        }

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _persist_event(self, event: UsageEvent) -> None:
        """Write a usage event to SQLite."""
        import json

        if self._db is None:
            return
        self._db.execute(
            "INSERT INTO usage_events "
            "(timestamp, event_type, feature, quantity, org_id, api_key_hash, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event.timestamp,
                event.event_type,
                event.feature,
                event.quantity,
                event.org_id,
                event.api_key_hash,
                json.dumps(event.metadata),
            ),
        )
        self._db.commit()

    def _persist_summary(self, summary: UsageSummary) -> None:
        """Upsert the monthly summary to SQLite."""
        if self._db is None:
            return
        self._db.execute(
            "INSERT INTO monthly_summaries "
            "(month, org_id, api_calls, input_tokens, output_tokens, "
            "detections, exports, estimated_cost) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(month, org_id) DO UPDATE SET "
            "api_calls=excluded.api_calls, input_tokens=excluded.input_tokens, "
            "output_tokens=excluded.output_tokens, detections=excluded.detections, "
            "exports=excluded.exports, estimated_cost=excluded.estimated_cost",
            (
                summary.month,
                summary.org_id,
                summary.api_calls,
                summary.input_tokens,
                summary.output_tokens,
                summary.detections,
                summary.exports,
                summary.estimated_cost,
            ),
        )
        self._db.commit()

    def load_summary_from_db(self, month: str | None = None) -> UsageSummary | None:
        """Load a monthly summary from SQLite."""
        if self._db is None:
            return None
        key = month or self._month_key()
        row = self._db.execute(
            "SELECT month, org_id, api_calls, input_tokens, output_tokens, "
            "detections, exports, estimated_cost "
            "FROM monthly_summaries WHERE month = ? AND org_id = ?",
            (key, self.org_id),
        ).fetchone()
        if not row:
            return None
        return UsageSummary(
            month=row[0],
            org_id=row[1],
            api_calls=row[2],
            input_tokens=row[3],
            output_tokens=row[4],
            detections=row[5],
            exports=row[6],
            estimated_cost=row[7],
        )

    def close(self) -> None:
        """Close the SQLite connection if open."""
        if self._db is not None:
            self._db.close()
            self._db = None
