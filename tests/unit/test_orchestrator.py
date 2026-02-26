"""
Tests for RedTeamOrchestrator and metrics functions.
Migrated from oubliette_redteam/tests/test_engine.py
"""

import pytest
from unittest.mock import Mock, patch

from oubliette_dungeon.core import (
    AttackResult,
    TestResult,
    RedTeamOrchestrator,
)


class TestRedTeamOrchestrator:
    """Test RedTeamOrchestrator class"""

    @pytest.fixture
    def orchestrator(self, mock_yaml_file):
        """Create orchestrator with test data"""
        return RedTeamOrchestrator(
            scenario_file=mock_yaml_file,
            target_url='http://test.local/api/chat'
        )

    def test_init_loads_scenarios(self, orchestrator):
        """Test orchestrator initializes and loads scenarios"""
        assert orchestrator.loader is not None
        assert len(orchestrator.loader.scenarios) > 0

    def test_run_single_scenario_success(self, orchestrator):
        """Test running a single scenario"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'I cannot help with that'}

        with patch.object(orchestrator.executor.session, 'post', return_value=mock_response):
            result = orchestrator.run_single_scenario('ATK-001')

        assert result.scenario_id == 'ATK-001'
        assert result.result == AttackResult.SUCCESS_DETECTED.value
        assert result.execution_time_ms > 0

    def test_run_single_scenario_not_found(self, orchestrator):
        """Test running non-existent scenario"""
        with pytest.raises(ValueError, match='Scenario.*not found'):
            orchestrator.run_single_scenario('ATK-999')

    def test_run_category(self, orchestrator):
        """Test running all scenarios in a category"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'refused'}

        with patch.object(orchestrator.executor.session, 'post', return_value=mock_response):
            results = orchestrator.run_category('prompt_injection')

        assert len(results) > 0
        assert all(r.category == 'prompt_injection' for r in results)

    def test_run_all_scenarios(self, orchestrator):
        """Test running all scenarios"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'test'}

        with patch.object(orchestrator.executor.session, 'post', return_value=mock_response), \
             patch('time.sleep'):
            results = orchestrator.run_all_scenarios()

        assert len(results) == 2

    def test_generate_summary_empty_results(self, orchestrator):
        """Test summary generation with no results"""
        summary = orchestrator.generate_summary([])

        assert 'error' in summary

    def test_generate_summary_with_results(self, orchestrator, sample_scenario):
        """Test summary generation with results"""
        results = [
            TestResult(
                scenario_id='ATK-001',
                scenario_name='Test 1',
                category='prompt_injection',
                difficulty='easy',
                result=AttackResult.SUCCESS_BYPASS.value,
                confidence=0.95,
                execution_time_ms=1500.0,
                response='bypass response',
                bypass_indicators_found=['password'],
                safe_indicators_found=[]
            ),
            TestResult(
                scenario_id='ATK-002',
                scenario_name='Test 2',
                category='jailbreak',
                difficulty='hard',
                result=AttackResult.SUCCESS_DETECTED.value,
                confidence=0.90,
                execution_time_ms=2000.0,
                response='refused',
                bypass_indicators_found=[],
                safe_indicators_found=['cannot']
            )
        ]

        summary = orchestrator.generate_summary(results)

        assert summary['total_tests'] == 2
        assert summary['by_result']['bypass'] == 1
        assert summary['by_result']['detected'] == 1
        assert summary['by_category']['prompt_injection'] == 1
        assert summary['by_difficulty']['easy'] == 1
        assert summary['avg_execution_time_ms'] == 1750.0
        assert summary['avg_confidence'] == 0.925
        assert summary['bypass_rate'] == 50.0

    def test_session_id_generation(self, orchestrator):
        """Test session ID is generated"""
        assert orchestrator.current_session_id is not None
        assert len(orchestrator.current_session_id) > 8

    def test_concurrent_execution_safety(self, mock_yaml_file):
        """Test that orchestrator has unique session per instance"""
        import time
        orchestrator = RedTeamOrchestrator(
            scenario_file=mock_yaml_file,
            target_url='http://test.local/api'
        )

        session1 = orchestrator.current_session_id
        time.sleep(1.1)
        orchestrator2 = RedTeamOrchestrator(
            scenario_file=mock_yaml_file,
            target_url='http://test.local/api'
        )
        session2 = orchestrator2.current_session_id

        assert session1 != session2


class TestIntegration:
    """End-to-end integration tests"""

    def test_full_workflow_single_scenario(self, mock_yaml_file):
        """Test complete workflow for single scenario"""
        orchestrator = RedTeamOrchestrator(
            scenario_file=mock_yaml_file,
            target_url='http://test.local/api'
        )

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'I cannot help with that'}

        with patch.object(orchestrator.executor.session, 'post', return_value=mock_response):
            result = orchestrator.run_single_scenario('ATK-001')

        assert result.scenario_id == 'ATK-001'
        assert result.result == AttackResult.SUCCESS_DETECTED.value
        assert 'cannot' in result.safe_indicators_found
        assert result.execution_time_ms > 0

    def test_full_workflow_category_run(self, mock_yaml_file):
        """Test complete workflow for category"""
        orchestrator = RedTeamOrchestrator(
            scenario_file=mock_yaml_file,
            target_url='http://test.local/api'
        )

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'refused'}

        with patch.object(orchestrator.executor.session, 'post', return_value=mock_response):
            results = orchestrator.run_category('prompt_injection')
            summary = orchestrator.generate_summary(results)

        assert len(results) > 0
        assert summary['total_tests'] == len(results)
