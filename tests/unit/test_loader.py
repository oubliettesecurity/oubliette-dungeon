"""
Tests for ScenarioLoader.
Migrated from oubliette_redteam/tests/test_engine.py
"""

import pytest
import yaml

from oubliette_dungeon.core import ScenarioLoader


class TestScenarioLoader:
    """Test ScenarioLoader class"""

    def test_load_scenarios_success(self, mock_yaml_file):
        """Test successful scenario loading"""
        loader = ScenarioLoader(mock_yaml_file)
        loader.load_scenarios()

        assert len(loader.scenarios) == 2
        assert loader.scenarios[0].id == 'ATK-001'
        assert loader.scenarios[1].id == 'ATK-002'

    def test_load_scenarios_file_not_found(self):
        """Test loading from non-existent file"""
        with pytest.raises(FileNotFoundError):
            ScenarioLoader('nonexistent.yaml')

    def test_load_scenarios_invalid_yaml(self, tmp_path):
        """Test loading invalid YAML"""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("{ invalid yaml content [")

        with pytest.raises(yaml.YAMLError):
            ScenarioLoader(str(bad_yaml))

    def test_get_by_category(self, mock_yaml_file):
        """Test filtering by category"""
        loader = ScenarioLoader(mock_yaml_file)
        loader.load_scenarios()

        injection_scenarios = loader.get_by_category('prompt_injection')
        assert len(injection_scenarios) == 1
        assert injection_scenarios[0].category == 'prompt_injection'

    def test_get_by_difficulty(self, mock_yaml_file):
        """Test filtering by difficulty"""
        loader = ScenarioLoader(mock_yaml_file)
        loader.load_scenarios()

        easy_scenarios = loader.get_by_difficulty('easy')
        assert len(easy_scenarios) == 1
        assert easy_scenarios[0].difficulty == 'easy'

    def test_get_by_id(self, mock_yaml_file):
        """Test getting scenario by ID"""
        loader = ScenarioLoader(mock_yaml_file)
        loader.load_scenarios()

        scenario = loader.get_by_id('ATK-001')
        assert scenario is not None
        assert scenario.id == 'ATK-001'

        # Test non-existent ID
        assert loader.get_by_id('ATK-999') is None

    def test_list_all(self, mock_yaml_file):
        """Test listing all scenarios"""
        loader = ScenarioLoader(mock_yaml_file)
        loader.load_scenarios()

        all_scenarios = loader.list_all()
        assert len(all_scenarios) == 2


class TestEdgeCasesLoader:
    """Test edge cases for scenario loading"""

    def test_empty_scenario_file(self, tmp_path):
        """Test loading empty YAML file"""
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")

        loader = ScenarioLoader(str(empty_file))
        loader.load_scenarios()

        assert len(loader.scenarios) == 0

    def test_scenario_missing_required_fields(self, tmp_path):
        """Test scenario with missing required fields"""
        bad_data = [{'id': 'ATK-001'}]  # Missing required fields

        yaml_file = tmp_path / "bad.yaml"
        with open(yaml_file, 'w') as f:
            yaml.dump(bad_data, f)

        with pytest.raises(KeyError):
            ScenarioLoader(str(yaml_file))


class TestPerformanceLoader:
    """Test loader performance"""

    def test_scenario_loading_performance(self, mock_yaml_file):
        """Test scenario loading is reasonably fast"""
        import time

        start = time.time()
        loader = ScenarioLoader(mock_yaml_file)
        loader.load_scenarios()
        elapsed = time.time() - start

        assert elapsed < 1.0  # Should load in under 1 second
