"""
Tests for core data models (AttackScenario, TestResult, AttackResult, enums).
Migrated from oubliette_redteam/tests/test_engine.py
"""

import pytest
from dataclasses import asdict

from oubliette_dungeon.core import (
    AttackScenario,
    TestResult,
    AttackResult,
)


class TestDataClasses:
    """Test data class structures"""

    def test_attack_scenario_creation(self):
        """Test AttackScenario dataclass"""
        scenario = AttackScenario(
            id='TEST-001',
            name='Test',
            category='test_cat',
            difficulty='medium',
            description='Test scenario',
            owasp_mapping=['LLM01'],
            mitre_mapping=['T0030'],
            prompt='test prompt'
        )

        assert scenario.id == 'TEST-001'
        assert scenario.bypass_indicators == []
        assert scenario.safe_indicators == []

    def test_attack_scenario_with_optional_fields(self):
        """Test AttackScenario with all fields"""
        scenario = AttackScenario(
            id='TEST-001',
            name='Test',
            category='test_cat',
            difficulty='medium',
            description='Test scenario',
            owasp_mapping=['LLM01'],
            mitre_mapping=['T0030'],
            prompt='test prompt',
            multi_turn_prompts=['Turn 1', 'Turn 2'],
            bypass_indicators=['bad'],
            safe_indicators=['good']
        )

        assert len(scenario.multi_turn_prompts) == 2
        assert len(scenario.bypass_indicators) == 1

    def test_test_result_creation(self):
        """Test TestResult dataclass"""
        result = TestResult(
            scenario_id='ATK-001',
            scenario_name='Test',
            category='test',
            difficulty='easy',
            result=AttackResult.SUCCESS_BYPASS.value,
            confidence=0.95,
            execution_time_ms=1500.0,
            response='test response',
            bypass_indicators_found=['indicator1'],
            safe_indicators_found=[]
        )

        assert result.result == AttackResult.SUCCESS_BYPASS.value
        assert result.confidence == 0.95
        assert isinstance(result.timestamp, str)

    def test_attack_result_enum(self):
        """Test AttackResult enum values"""
        assert AttackResult.SUCCESS_BYPASS.value == 'bypass'
        assert AttackResult.SUCCESS_DETECTED.value == 'detected'
        assert AttackResult.PARTIAL.value == 'partial'
        assert AttackResult.ERROR.value == 'error'

    def test_scenario_to_dict_conversion(self, sample_scenario):
        """Test converting scenario to dict for serialization"""
        scenario_dict = asdict(sample_scenario)

        assert scenario_dict['id'] == sample_scenario.id
        assert scenario_dict['name'] == sample_scenario.name
        assert isinstance(scenario_dict, dict)

    def test_result_to_dict_conversion(self):
        """Test converting result to dict for serialization"""
        result = TestResult(
            scenario_id='ATK-001',
            scenario_name='Test',
            category='test',
            difficulty='easy',
            result=AttackResult.SUCCESS_BYPASS.value,
            confidence=0.95,
            execution_time_ms=1500.0,
            response='test',
            bypass_indicators_found=['test'],
            safe_indicators_found=[]
        )

        result_dict = asdict(result)
        assert result_dict['scenario_id'] == 'ATK-001'
        assert result_dict['result'] == 'bypass'
