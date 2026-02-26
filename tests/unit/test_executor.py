"""
Tests for AttackExecutor.
Migrated from oubliette_redteam/tests/test_engine.py
"""

import json
import pytest
from unittest.mock import Mock, patch

from oubliette_dungeon.core import AttackExecutor


class TestAttackExecutor:
    """Test AttackExecutor class"""

    def test_execute_single_turn_success(self, sample_scenario):
        """Test successful single-turn execution"""
        executor = AttackExecutor(target_url='http://test.local/api/chat')

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'I cannot help with that'}

        with patch.object(executor.session, 'post', return_value=mock_response):
            response, exec_time = executor.execute_single_turn(sample_scenario)

        assert response == 'I cannot help with that'
        assert exec_time > 0

    def test_execute_single_turn_http_error(self, sample_scenario):
        """Test handling of HTTP errors"""
        executor = AttackExecutor(target_url='http://test.local/api/chat')

        with patch.object(executor.session, 'post', side_effect=Exception('Connection failed')):
            response, exec_time = executor.execute_single_turn(sample_scenario)

        assert 'ERROR' in response
        assert 'Connection failed' in response

    def test_execute_single_turn_non_200(self, sample_scenario):
        """Test handling of non-200 HTTP status"""
        executor = AttackExecutor(target_url='http://test.local/api/chat')

        mock_response = Mock()
        mock_response.status_code = 500

        with patch.object(executor.session, 'post', return_value=mock_response):
            response, _ = executor.execute_single_turn(sample_scenario)

        assert 'ERROR' in response
        assert '500' in response

    def test_execute_multi_turn(self, multi_turn_scenario):
        """Test multi-turn attack execution"""
        executor = AttackExecutor(target_url='http://test.local/api/chat')

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'response': 'test response'}

        with patch.object(executor.session, 'post', return_value=mock_response), \
             patch('time.sleep'):
            responses, total_time = executor.execute_multi_turn(multi_turn_scenario)

        assert len(responses) == 3
        assert all(r == 'test response' for r in responses)

    def test_execute_multi_turn_partial_failure(self, multi_turn_scenario):
        """Test multi-turn with partial failure"""
        executor = AttackExecutor(target_url='http://test.local/api/chat')

        mock_success = Mock()
        mock_success.status_code = 200
        mock_success.json.return_value = {'response': 'ok'}

        with patch.object(executor.session, 'post', side_effect=[
            mock_success,
            Exception('Network error'),
            mock_success
        ]), patch('time.sleep'):
            responses, _ = executor.execute_multi_turn(multi_turn_scenario)

        assert len(responses) == 3
        assert 'ERROR' in responses[1]


class TestEdgeCasesExecutor:
    """Test edge cases for executor"""

    def test_http_timeout(self, sample_scenario):
        """Test handling of HTTP timeout"""
        executor = AttackExecutor(target_url='http://test.local/api')

        with patch.object(executor.session, 'post', side_effect=Exception('Timeout')):
            response, exec_time = executor.execute_single_turn(sample_scenario)

        assert 'ERROR' in response
        assert 'Timeout' in response

    def test_invalid_json_response(self, sample_scenario):
        """Test handling of invalid JSON response"""
        executor = AttackExecutor(target_url='http://test.local/api')

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError('Invalid', '', 0)

        with patch.object(executor.session, 'post', return_value=mock_response):
            response, _ = executor.execute_single_turn(sample_scenario)

        assert 'ERROR' in response
