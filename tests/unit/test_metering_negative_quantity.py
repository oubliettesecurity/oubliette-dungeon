"""Security regression tests — CRIT-1 (2026-07-19 scan).

``UsageTracker.record`` / ``check_quota`` accepted a negative ``quantity``,
letting a caller (e.g. ``record_llm_usage(input_tokens=-10_000_000)``) drive
usage counters below zero and silently free Pro/Enterprise usage
indefinitely, without ever tripping the soft-enforce billing flag.

Fail-closed fix (mirrored from oubliette-commerce): negative quantities are
rejected with ``ValueError`` at the public entry points. Zero remains legal
(a zero-usage record is legitimate).
"""

import pytest

from oubliette_dungeon.metering import UsageTracker


def test_record_rejects_negative_quantity():
    t = UsageTracker(tier="pro")
    with pytest.raises(ValueError):
        t.record("input_token", quantity=-10_000_000)
    # Counter must be untouched, not just "not decremented past zero".
    assert t.get_summary().input_tokens == 0


def test_check_quota_rejects_negative_quantity():
    t = UsageTracker(tier="pro")
    with pytest.raises(ValueError):
        t.check_quota("input_token", quantity=-1)


def test_record_allows_zero_quantity():
    t = UsageTracker(tier="pro")
    assert t.record("input_token", quantity=0) is True
    assert t.get_summary().input_tokens == 0


def test_record_allows_positive_quantity():
    t = UsageTracker(tier="pro")
    assert t.record("input_token", quantity=100) is True
    assert t.get_summary().input_tokens == 100


def test_record_llm_usage_rejects_negative_input_tokens():
    t = UsageTracker(tier="pro")
    before = t.get_summary().input_tokens
    with pytest.raises(ValueError):
        t.record_llm_usage("analyze", input_tokens=-10_000_000, output_tokens=10)
    # No partial recording: api_call/output_token must not have been
    # committed either, and input_tokens must not have gone negative.
    summary = t.get_summary()
    assert summary.input_tokens == before
    assert summary.input_tokens >= 0


def test_record_llm_usage_rejects_negative_output_tokens():
    t = UsageTracker(tier="pro")
    with pytest.raises(ValueError):
        t.record_llm_usage("analyze", input_tokens=10, output_tokens=-5)


def test_record_llm_usage_records_normally_for_positive_values():
    t = UsageTracker(tier="pro")
    t.record_llm_usage("analyze", input_tokens=100, output_tokens=50)
    summary = t.get_summary()
    assert summary.input_tokens == 100
    assert summary.output_tokens == 50
    assert summary.api_calls == 1
