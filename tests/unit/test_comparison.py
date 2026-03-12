"""
Tests for the multi-model comparison module.
"""

import json
import os
import tempfile

import pytest

from oubliette_dungeon.core.comparison import ModelComparison, ModelScore, ScenarioComparison
from oubliette_dungeon.core.models import AttackTestResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_results(detection_rate=0.8):
    """Create sample results with a target detection rate."""
    results = []
    for i in range(10):
        if i < int(detection_rate * 10):
            result, conf = "detected", 0.95
        elif i < int(detection_rate * 10) + 1:
            result, conf = "bypass", 0.85
        else:
            result, conf = "partial", 0.50

        results.append(AttackTestResult(
            scenario_id=f"ATK-{i+1:03d}",
            scenario_name=f"Scenario {i+1}",
            category="prompt_injection" if i < 5 else "jailbreak",
            difficulty="easy" if i < 3 else "medium" if i < 7 else "hard",
            result=result,
            confidence=conf,
            response=f"Response {i}",
            execution_time_ms=100 + i * 10,
            bypass_indicators_found=["bypass"] if result == "bypass" else [],
            safe_indicators_found=["safe"] if result == "detected" else [],
        ))
    return results


@pytest.fixture
def comparison():
    comp = ModelComparison()
    comp.add_results("model_a", _make_results(0.8))
    comp.add_results("model_b", _make_results(0.6))
    comp.add_results("model_c", _make_results(0.9))
    return comp


# ---------------------------------------------------------------------------
# ModelScore tests
# ---------------------------------------------------------------------------

class TestModelScore:

    def test_from_results_basic(self):
        results = _make_results(0.8)
        score = ModelScore.from_results("test", results)
        assert score.model_id == "test"
        assert score.total_scenarios == 10
        assert score.detected == 8

    def test_from_results_empty(self):
        score = ModelScore.from_results("empty", [])
        assert score.total_scenarios == 0
        assert score.detection_rate == 0

    def test_category_breakdown(self):
        results = _make_results(0.8)
        score = ModelScore.from_results("test", results)
        assert "prompt_injection" in score.by_category
        assert "jailbreak" in score.by_category

    def test_difficulty_breakdown(self):
        results = _make_results(0.8)
        score = ModelScore.from_results("test", results)
        assert "easy" in score.by_difficulty
        assert "medium" in score.by_difficulty


# ---------------------------------------------------------------------------
# ModelComparison tests
# ---------------------------------------------------------------------------

class TestModelComparison:

    def test_add_results(self, comparison):
        assert len(comparison.model_ids) == 3

    def test_ranking_order(self, comparison):
        ranked = comparison.ranking()
        assert ranked[0].model_id == "model_c"  # 90% detection
        assert ranked[1].model_id == "model_a"  # 80% detection
        assert ranked[2].model_id == "model_b"  # 60% detection

    def test_scenario_matrix(self, comparison):
        matrix = comparison.scenario_matrix()
        assert len(matrix) == 10
        # Each scenario should have results from all 3 models
        for sc in matrix:
            assert len(sc.model_results) == 3

    def test_to_dict(self, comparison):
        d = comparison.to_dict()
        assert d["model_count"] == 3
        assert len(d["ranking"]) == 3
        assert len(d["scenario_matrix"]) == 10
        # Should be JSON serializable
        json.dumps(d, default=str)

    def test_save_json(self, comparison):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            comparison.save_json(path)
            with open(path) as f:
                data = json.load(f)
            assert data["model_count"] == 3
        finally:
            os.unlink(path)

    def test_save_html(self, comparison):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            comparison.save_html(path)
            with open(path) as f:
                content = f.read()
            assert "Oubliette Dungeon" in content
            assert "model_a" in content
            assert "model_b" in content
            assert "model_c" in content
            assert "DETECTED" in content
        finally:
            os.unlink(path)

    def test_category_comparison(self, comparison):
        d = comparison.to_dict()
        cats = d["category_comparison"]
        assert "prompt_injection" in cats
        assert "jailbreak" in cats
        for cat_data in cats.values():
            assert "model_a" in cat_data
            assert "model_b" in cat_data

    def test_print_summary(self, comparison, capsys):
        comparison.print_summary()
        captured = capsys.readouterr()
        assert "MULTI-MODEL COMPARISON" in captured.out
        assert "model_a" in captured.out

    def test_empty_comparison(self):
        comp = ModelComparison()
        assert comp.model_ids == []
        assert comp.ranking() == []
        assert comp.scenario_matrix() == []

    def test_scores_property(self, comparison):
        scores = comparison.scores
        assert "model_a" in scores
        assert isinstance(scores["model_a"], ModelScore)
