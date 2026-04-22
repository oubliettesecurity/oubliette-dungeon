"""
Human-in-the-Loop (HITL) review module for Oubliette Dungeon.

Enables subject-matter experts to review, override, and annotate automated
evaluation results. Tracks reviewer decisions with justifications and computes
inter-rater reliability metrics.

Usage::

    from oubliette_dungeon.core.hitl import ReviewQueue

    queue = ReviewQueue.from_results(results)

    # Flag ambiguous results for review
    queue.flag_for_review(confidence_threshold=0.75)

    # SME submits a review
    queue.submit_review(
        scenario_id="ATK-005",
        reviewer="analyst_1",
        override_result="detected",
        override_confidence=0.90,
        justification="Model refused but used hedging language. Classify as detected.",
    )

    # Export reviewed results
    queue.save("reviewed_results.json")
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from oubliette_dungeon.core.models import AttackTestResult

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Review:
    """A single human review decision."""

    scenario_id: str
    reviewer: str
    override_result: str
    override_confidence: float
    justification: str
    timestamp: str = ""
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class ReviewableResult:
    """An evaluation result that can be reviewed by a human."""

    scenario_id: str
    scenario_name: str
    category: str
    difficulty: str
    automated_result: str
    automated_confidence: float
    response_snippet: str
    bypass_indicators_found: List[str]
    safe_indicators_found: List[str]
    needs_review: bool = False
    review_reason: str = ""
    reviews: List[Review] = field(default_factory=list)

    @property
    def is_reviewed(self) -> bool:
        return len(self.reviews) > 0

    @property
    def final_result(self) -> str:
        """Return the latest review override, or the automated result."""
        if self.reviews:
            return self.reviews[-1].override_result
        return self.automated_result

    @property
    def final_confidence(self) -> float:
        """Return the latest review confidence, or the automated one."""
        if self.reviews:
            return self.reviews[-1].override_confidence
        return self.automated_confidence


# ---------------------------------------------------------------------------
# ReviewQueue
# ---------------------------------------------------------------------------


class ReviewQueue:
    """Manages a queue of results for human review."""

    def __init__(self) -> None:
        self._items: Dict[str, ReviewableResult] = {}

    @classmethod
    def from_results(cls, results: List[AttackTestResult]) -> "ReviewQueue":
        """Create a review queue from evaluation results."""
        queue = cls()
        for r in results:
            item = ReviewableResult(
                scenario_id=r.scenario_id,
                scenario_name=r.scenario_name,
                category=r.category,
                difficulty=r.difficulty,
                automated_result=r.result,
                automated_confidence=r.confidence,
                response_snippet=r.response[:500] if r.response else "",
                bypass_indicators_found=r.bypass_indicators_found,
                safe_indicators_found=r.safe_indicators_found,
            )
            queue._items[r.scenario_id] = item
        return queue

    def flag_for_review(
        self,
        confidence_threshold: float = 0.75,
        flag_partial: bool = True,
        flag_categories: Optional[List[str]] = None,
    ) -> int:
        """Flag results that need human review.

        Args:
            confidence_threshold: Flag results with confidence below this value.
            flag_partial: Always flag PARTIAL results.
            flag_categories: Always flag results in these categories.

        Returns:
            Number of items flagged.
        """
        flagged = 0
        for item in self._items.values():
            reasons = []

            if item.automated_confidence < confidence_threshold:
                reasons.append(
                    f"Low confidence ({item.automated_confidence:.2f} < {confidence_threshold})"
                )

            if flag_partial and item.automated_result == "partial":
                reasons.append("Partial/ambiguous result")

            if flag_categories and item.category in flag_categories:
                reasons.append(f"Priority category: {item.category}")

            if reasons:
                item.needs_review = True
                item.review_reason = "; ".join(reasons)
                flagged += 1

        return flagged

    def submit_review(
        self,
        scenario_id: str,
        reviewer: str,
        override_result: str,
        override_confidence: float,
        justification: str,
        tags: Optional[List[str]] = None,
    ) -> bool:
        """Submit a human review for a scenario.

        Args:
            scenario_id: The scenario to review.
            reviewer: Reviewer identifier.
            override_result: New result classification (detected/bypass/partial).
            override_confidence: Reviewer's confidence in the override (0.0-1.0).
            justification: Free-text justification for the override.
            tags: Optional tags for categorizing the review.

        Returns:
            True if the review was recorded, False if scenario not found.
        """
        item = self._items.get(scenario_id)
        if item is None:
            return False

        review = Review(
            scenario_id=scenario_id,
            reviewer=reviewer,
            override_result=override_result,
            override_confidence=max(0.0, min(1.0, override_confidence)),
            justification=justification,
            tags=tags or [],
        )
        item.reviews.append(review)
        return True

    @property
    def total(self) -> int:
        return len(self._items)

    @property
    def pending_review(self) -> List[ReviewableResult]:
        """Items flagged for review but not yet reviewed."""
        return [
            item for item in self._items.values()
            if item.needs_review and not item.is_reviewed
        ]

    @property
    def reviewed(self) -> List[ReviewableResult]:
        """Items that have been reviewed."""
        return [item for item in self._items.values() if item.is_reviewed]

    @property
    def all_items(self) -> List[ReviewableResult]:
        return list(self._items.values())

    def get_item(self, scenario_id: str) -> Optional[ReviewableResult]:
        return self._items.get(scenario_id)

    def agreement_rate(self) -> Optional[float]:
        """Fraction of reviewed items where human agrees with automation."""
        reviewed = self.reviewed
        if not reviewed:
            return None
        agreed = sum(
            1 for item in reviewed
            if item.automated_result == item.final_result
        )
        return agreed / len(reviewed)

    def override_rate(self) -> Optional[float]:
        """Fraction of reviewed items where human overrode the automated result."""
        reviewed = self.reviewed
        if not reviewed:
            return None
        overridden = sum(
            1 for item in reviewed
            if item.automated_result != item.final_result
        )
        return overridden / len(reviewed)

    def inter_rater_reliability(self) -> Optional[float]:
        """Simple agreement rate between multiple reviewers on the same items.

        Returns the fraction of items with multiple reviews where all reviewers
        agree on the result. Returns None if no items have multiple reviews.
        """
        multi_reviewed = [
            item for item in self._items.values()
            if len(item.reviews) >= 2
        ]
        if not multi_reviewed:
            return None

        agreed = 0
        for item in multi_reviewed:
            results = set(r.override_result for r in item.reviews)
            if len(results) == 1:
                agreed += 1

        return agreed / len(multi_reviewed)

    def summary(self) -> Dict[str, Any]:
        """Generate review summary statistics."""
        reviewed = self.reviewed
        pending = self.pending_review
        all_items = self.all_items

        flagged = sum(1 for item in all_items if item.needs_review)
        total_reviews = sum(len(item.reviews) for item in all_items)
        unique_reviewers = set()
        for item in all_items:
            for review in item.reviews:
                unique_reviewers.add(review.reviewer)

        return {
            "total_scenarios": self.total,
            "flagged_for_review": flagged,
            "pending_review": len(pending),
            "reviewed": len(reviewed),
            "total_reviews": total_reviews,
            "unique_reviewers": len(unique_reviewers),
            "reviewer_names": sorted(unique_reviewers),
            "agreement_rate": self.agreement_rate(),
            "override_rate": self.override_rate(),
            "inter_rater_reliability": self.inter_rater_reliability(),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Export the full review queue as a dict."""
        return {
            "schema_version": "1.0",
            "tool": "oubliette-dungeon",
            "report_type": "hitl_review",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": self.summary(),
            "items": [asdict(item) for item in self._items.values()],
        }

    def save(self, path: str) -> None:
        """Save the review queue to JSON."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    @classmethod
    def load(cls, path: str) -> "ReviewQueue":
        """Load a review queue from JSON."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        queue = cls()
        for item_data in data.get("items", []):
            reviews = [
                Review(**r) for r in item_data.pop("reviews", [])
            ]
            item = ReviewableResult(**item_data)
            item.reviews = reviews
            queue._items[item.scenario_id] = item

        return queue
