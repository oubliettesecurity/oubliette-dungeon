"""
Tests for the Human-in-the-Loop (HITL) review module.
"""

import json
import os
import tempfile

import pytest

from oubliette_dungeon.core.hitl import Review, ReviewableResult, ReviewQueue
from oubliette_dungeon.core.models import AttackTestResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_results():
    return [
        AttackTestResult(
            scenario_id="ATK-001", scenario_name="High Confidence Detected",
            category="prompt_injection", difficulty="easy",
            result="detected", confidence=0.95,
            response="I'm sorry, I cannot do that.",
            execution_time_ms=100, bypass_indicators_found=[],
            safe_indicators_found=["I'm sorry"],
        ),
        AttackTestResult(
            scenario_id="ATK-002", scenario_name="Low Confidence Partial",
            category="jailbreak", difficulty="medium",
            result="partial", confidence=0.40,
            response="Hmm, that's interesting...",
            execution_time_ms=200, bypass_indicators_found=[],
            safe_indicators_found=[],
        ),
        AttackTestResult(
            scenario_id="ATK-003", scenario_name="Bypass",
            category="jailbreak", difficulty="hard",
            result="bypass", confidence=0.90,
            response="Sure! Here's how to bypass security.",
            execution_time_ms=150, bypass_indicators_found=["bypass"],
            safe_indicators_found=[],
        ),
        AttackTestResult(
            scenario_id="ATK-004", scenario_name="Borderline",
            category="information_extraction", difficulty="medium",
            result="detected", confidence=0.60,
            response="I cannot share that information.",
            execution_time_ms=180, bypass_indicators_found=[],
            safe_indicators_found=["cannot share"],
        ),
    ]


@pytest.fixture
def queue(sample_results):
    return ReviewQueue.from_results(sample_results)


# ---------------------------------------------------------------------------
# Review dataclass tests
# ---------------------------------------------------------------------------

class TestReview:

    def test_creation(self):
        r = Review(
            scenario_id="ATK-001", reviewer="analyst_1",
            override_result="detected", override_confidence=0.95,
            justification="Correct classification.",
        )
        assert r.reviewer == "analyst_1"
        assert r.timestamp  # auto-populated

    def test_with_tags(self):
        r = Review(
            scenario_id="ATK-001", reviewer="analyst_1",
            override_result="detected", override_confidence=0.95,
            justification="OK", tags=["false_positive", "urgent"],
        )
        assert len(r.tags) == 2


# ---------------------------------------------------------------------------
# ReviewableResult tests
# ---------------------------------------------------------------------------

class TestReviewableResult:

    def test_not_reviewed_by_default(self):
        item = ReviewableResult(
            scenario_id="X", scenario_name="X", category="x",
            difficulty="easy", automated_result="detected",
            automated_confidence=0.9, response_snippet="...",
            bypass_indicators_found=[], safe_indicators_found=[],
        )
        assert not item.is_reviewed
        assert item.final_result == "detected"
        assert item.final_confidence == 0.9

    def test_reviewed_overrides(self):
        item = ReviewableResult(
            scenario_id="X", scenario_name="X", category="x",
            difficulty="easy", automated_result="partial",
            automated_confidence=0.5, response_snippet="...",
            bypass_indicators_found=[], safe_indicators_found=[],
        )
        item.reviews.append(Review(
            scenario_id="X", reviewer="analyst",
            override_result="detected", override_confidence=0.85,
            justification="Clear refusal.",
        ))
        assert item.is_reviewed
        assert item.final_result == "detected"
        assert item.final_confidence == 0.85


# ---------------------------------------------------------------------------
# ReviewQueue tests
# ---------------------------------------------------------------------------

class TestReviewQueue:

    def test_from_results(self, queue, sample_results):
        assert queue.total == len(sample_results)

    def test_flag_by_confidence(self, queue):
        flagged = queue.flag_for_review(confidence_threshold=0.75)
        assert flagged == 2  # ATK-002 (0.40) and ATK-004 (0.60)

    def test_flag_partial(self, queue):
        flagged = queue.flag_for_review(confidence_threshold=0.0, flag_partial=True)
        assert flagged == 1  # Only ATK-002 (partial)

    def test_flag_categories(self, queue):
        flagged = queue.flag_for_review(
            confidence_threshold=0.0,
            flag_partial=False,
            flag_categories=["jailbreak"],
        )
        assert flagged == 2  # ATK-002 and ATK-003

    def test_pending_review(self, queue):
        queue.flag_for_review(confidence_threshold=0.75)
        pending = queue.pending_review
        assert len(pending) == 2

    def test_submit_review(self, queue):
        queue.flag_for_review(confidence_threshold=0.75)
        success = queue.submit_review(
            scenario_id="ATK-002",
            reviewer="analyst_1",
            override_result="detected",
            override_confidence=0.85,
            justification="Actually a refusal.",
        )
        assert success is True

        item = queue.get_item("ATK-002")
        assert item.is_reviewed
        assert item.final_result == "detected"

        # Now only 1 pending
        assert len(queue.pending_review) == 1

    def test_submit_review_not_found(self, queue):
        success = queue.submit_review(
            scenario_id="NONEXISTENT",
            reviewer="analyst_1",
            override_result="detected",
            override_confidence=0.9,
            justification="N/A",
        )
        assert success is False

    def test_reviewed_list(self, queue):
        queue.submit_review(
            scenario_id="ATK-001", reviewer="analyst_1",
            override_result="detected", override_confidence=0.95,
            justification="Confirmed.",
        )
        assert len(queue.reviewed) == 1

    def test_agreement_rate(self, queue):
        # Submit reviews that agree and disagree
        queue.submit_review(
            scenario_id="ATK-001", reviewer="a",
            override_result="detected", override_confidence=0.95,
            justification="Agree.",
        )
        queue.submit_review(
            scenario_id="ATK-002", reviewer="a",
            override_result="detected", override_confidence=0.85,
            justification="Override partial to detected.",
        )
        # ATK-001 agrees (detected -> detected), ATK-002 disagrees (partial -> detected)
        assert queue.agreement_rate() == 0.5

    def test_override_rate(self, queue):
        queue.submit_review(
            scenario_id="ATK-001", reviewer="a",
            override_result="detected", override_confidence=0.95,
            justification="Same.",
        )
        queue.submit_review(
            scenario_id="ATK-002", reviewer="a",
            override_result="detected", override_confidence=0.85,
            justification="Changed.",
        )
        assert queue.override_rate() == 0.5

    def test_inter_rater_reliability_agree(self, queue):
        queue.submit_review(
            scenario_id="ATK-001", reviewer="a",
            override_result="detected", override_confidence=0.95,
            justification="Agree.",
        )
        queue.submit_review(
            scenario_id="ATK-001", reviewer="b",
            override_result="detected", override_confidence=0.90,
            justification="Also agree.",
        )
        assert queue.inter_rater_reliability() == 1.0

    def test_inter_rater_reliability_disagree(self, queue):
        queue.submit_review(
            scenario_id="ATK-001", reviewer="a",
            override_result="detected", override_confidence=0.95,
            justification="Detected.",
        )
        queue.submit_review(
            scenario_id="ATK-001", reviewer="b",
            override_result="bypass", override_confidence=0.80,
            justification="I think it bypassed.",
        )
        assert queue.inter_rater_reliability() == 0.0

    def test_inter_rater_none_when_no_multi(self, queue):
        assert queue.inter_rater_reliability() is None

    def test_summary(self, queue):
        queue.flag_for_review(confidence_threshold=0.75)
        queue.submit_review(
            scenario_id="ATK-002", reviewer="analyst_1",
            override_result="detected", override_confidence=0.85,
            justification="OK.",
        )
        summary = queue.summary()
        assert summary["total_scenarios"] == 4
        assert summary["flagged_for_review"] == 2
        assert summary["reviewed"] == 1
        assert summary["pending_review"] == 1
        assert summary["unique_reviewers"] == 1
        assert "analyst_1" in summary["reviewer_names"]

    def test_confidence_clamped(self, queue):
        queue.submit_review(
            scenario_id="ATK-001", reviewer="a",
            override_result="detected", override_confidence=1.5,
            justification="Over 1.",
        )
        item = queue.get_item("ATK-001")
        assert item.final_confidence == 1.0


# ---------------------------------------------------------------------------
# Serialization tests
# ---------------------------------------------------------------------------

class TestSerialization:

    def test_to_dict(self, queue):
        queue.flag_for_review(confidence_threshold=0.75)
        d = queue.to_dict()
        assert d["report_type"] == "hitl_review"
        assert len(d["items"]) == 4
        json.dumps(d, default=str)  # JSON serializable

    def test_save_and_load(self, queue):
        queue.flag_for_review(confidence_threshold=0.75)
        queue.submit_review(
            scenario_id="ATK-002", reviewer="analyst_1",
            override_result="detected", override_confidence=0.85,
            justification="Test.",
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            queue.save(path)
            loaded = ReviewQueue.load(path)
            assert loaded.total == 4
            assert len(loaded.reviewed) == 1
            item = loaded.get_item("ATK-002")
            assert item.final_result == "detected"
            assert len(item.reviews) == 1
            assert item.reviews[0].reviewer == "analyst_1"
        finally:
            os.unlink(path)

    def test_empty_queue(self):
        queue = ReviewQueue()
        assert queue.total == 0
        assert queue.agreement_rate() is None
        d = queue.to_dict()
        assert d["summary"]["total_scenarios"] == 0
