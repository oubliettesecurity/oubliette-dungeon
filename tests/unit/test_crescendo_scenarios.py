"""
Tests for the multi-turn crescendo attack scenarios.
"""

import os
import pytest
import yaml

from oubliette_dungeon.core import ScenarioLoader
from oubliette_dungeon.core.models import AttackScenario


# ========================================================================
# Fixtures
# ========================================================================

@pytest.fixture
def crescendo_yaml_path():
    """Path to the crescendo scenario file."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(
        here, "..", "..", "src", "oubliette_dungeon", "scenarios", "crescendo.yaml"
    )
    return os.path.normpath(path)


@pytest.fixture
def crescendo_scenarios(crescendo_yaml_path):
    """Load crescendo scenarios via ScenarioLoader."""
    loader = ScenarioLoader(crescendo_yaml_path)
    return loader.get_all_scenarios()


@pytest.fixture
def crescendo_raw(crescendo_yaml_path):
    """Load raw YAML data."""
    with open(crescendo_yaml_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ========================================================================
# Tests: File structure
# ========================================================================

class TestCrescendoFile:
    def test_file_exists(self, crescendo_yaml_path):
        assert os.path.isfile(crescendo_yaml_path)

    def test_yaml_valid(self, crescendo_raw):
        assert isinstance(crescendo_raw, list)
        assert len(crescendo_raw) > 0

    def test_exact_scenario_count(self, crescendo_raw):
        assert len(crescendo_raw) == 15


# ========================================================================
# Tests: Scenario structure
# ========================================================================

class TestCrescendoStructure:
    def test_all_have_required_fields(self, crescendo_raw):
        required = {"id", "name", "category", "difficulty", "description"}
        for scenario in crescendo_raw:
            for field in required:
                assert field in scenario, f"Scenario {scenario.get('id', '?')} missing {field}"

    def test_all_have_multi_turn(self, crescendo_raw):
        for scenario in crescendo_raw:
            assert "multi_turn_sequence" in scenario, \
                f"Scenario {scenario['id']} missing multi_turn_sequence"
            assert len(scenario["multi_turn_sequence"]) >= 5, \
                f"Scenario {scenario['id']} has < 5 turns"

    def test_id_range(self, crescendo_raw):
        ids = [s["id"] for s in crescendo_raw]
        assert ids[0] == "ATK-058"
        assert ids[-1] == "ATK-072"

    def test_ids_are_sequential(self, crescendo_raw):
        for i, s in enumerate(crescendo_raw):
            expected = f"ATK-{58 + i:03d}"
            assert s["id"] == expected, f"Expected {expected}, got {s['id']}"

    def test_all_have_bypass_indicators(self, crescendo_raw):
        for s in crescendo_raw:
            assert "bypass_indicators" in s, f"Scenario {s['id']} missing bypass_indicators"
            assert len(s["bypass_indicators"]) > 0

    def test_all_have_tags(self, crescendo_raw):
        for s in crescendo_raw:
            assert "tags" in s, f"Scenario {s['id']} missing tags"
            assert "multi_turn" in s["tags"], \
                f"Scenario {s['id']} missing 'multi_turn' tag"

    def test_all_have_owasp_mapping(self, crescendo_raw):
        for s in crescendo_raw:
            assert "owasp_mapping" in s, f"Scenario {s['id']} missing owasp_mapping"
            assert len(s["owasp_mapping"]) > 0


# ========================================================================
# Tests: Scenario categories
# ========================================================================

class TestCrescendoCategories:
    def test_all_multi_turn_attack(self, crescendo_raw):
        for s in crescendo_raw:
            assert s["category"] == "multi_turn_attack"

    def test_difficulty_distribution(self, crescendo_raw):
        difficulties = [s["difficulty"] for s in crescendo_raw]
        assert "advanced" in difficulties
        assert "hard" in difficulties

    def test_gradual_poisoning_count(self, crescendo_raw):
        """First 5 scenarios should cover gradual context poisoning."""
        ids = [s["id"] for s in crescendo_raw[:5]]
        assert ids == ["ATK-058", "ATK-059", "ATK-060", "ATK-061", "ATK-062"]

    def test_authority_escalation_count(self, crescendo_raw):
        """Scenarios 6-7 should cover authority escalation."""
        ids = [s["id"] for s in crescendo_raw[5:7]]
        assert ids == ["ATK-063", "ATK-064"]

    def test_semantic_misdirection_count(self, crescendo_raw):
        """Scenarios 8-10 should cover semantic misdirection."""
        ids = [s["id"] for s in crescendo_raw[7:10]]
        assert ids == ["ATK-065", "ATK-066", "ATK-067"]

    def test_multi_vector_count(self, crescendo_raw):
        """Scenarios 11-13 should cover multi-vector attacks."""
        ids = [s["id"] for s in crescendo_raw[10:13]]
        assert ids == ["ATK-068", "ATK-069", "ATK-070"]

    def test_session_persistence_count(self, crescendo_raw):
        """Scenarios 14-15 should cover session persistence."""
        ids = [s["id"] for s in crescendo_raw[13:15]]
        assert ids == ["ATK-071", "ATK-072"]


# ========================================================================
# Tests: Loading via ScenarioLoader
# ========================================================================

class TestCrescendoLoading:
    def test_loader_parses_all(self, crescendo_scenarios):
        assert len(crescendo_scenarios) == 15

    def test_loader_creates_attack_scenarios(self, crescendo_scenarios):
        for sc in crescendo_scenarios:
            assert isinstance(sc, AttackScenario)

    def test_loader_multi_turn_prompts(self, crescendo_scenarios):
        """All scenarios should have multi_turn_prompts populated."""
        for sc in crescendo_scenarios:
            assert sc.multi_turn_prompts is not None, \
                f"Scenario {sc.id} has no multi_turn_prompts"
            assert len(sc.multi_turn_prompts) >= 5, \
                f"Scenario {sc.id} has < 5 multi_turn_prompts"

    def test_loader_statistics(self, crescendo_yaml_path):
        loader = ScenarioLoader(crescendo_yaml_path)
        stats = loader.get_statistics()
        assert stats["total"] == 15
        assert stats["multi_turn_count"] == 15
        assert "multi_turn_attack" in stats["by_category"]

    def test_filter_by_category(self, crescendo_yaml_path):
        loader = ScenarioLoader(crescendo_yaml_path)
        filtered = loader.get_by_category("multi_turn_attack")
        assert len(filtered) == 15

    def test_get_by_id(self, crescendo_yaml_path):
        loader = ScenarioLoader(crescendo_yaml_path)
        sc = loader.get_by_id("ATK-065")
        assert sc is not None
        assert sc.name == "Metaphor Bridge Attack"


# ========================================================================
# Tests: Turn content quality
# ========================================================================

class TestTurnContent:
    def test_turns_have_prompts(self, crescendo_raw):
        for s in crescendo_raw:
            for turn in s["multi_turn_sequence"]:
                assert "prompt" in turn, \
                    f"Scenario {s['id']} turn {turn.get('turn', '?')} missing prompt"
                assert len(turn["prompt"]) > 10, \
                    f"Scenario {s['id']} turn {turn['turn']} has very short prompt"

    def test_turns_have_expected(self, crescendo_raw):
        for s in crescendo_raw:
            for turn in s["multi_turn_sequence"]:
                assert "expected" in turn, \
                    f"Scenario {s['id']} turn {turn.get('turn', '?')} missing expected"

    def test_turns_numbered_sequentially(self, crescendo_raw):
        for s in crescendo_raw:
            turns = [t["turn"] for t in s["multi_turn_sequence"]]
            assert turns == list(range(1, len(turns) + 1)), \
                f"Scenario {s['id']} has non-sequential turns: {turns}"
