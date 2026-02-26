"""
Tests for RedTeamResultsDB (JSON file storage).
Migrated from oubliette_redteam/tests/test_results_db.py
"""

import pytest
import json
import csv
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch

from oubliette_dungeon.storage import RedTeamResultsDB


@pytest.fixture
def populated_db(temp_db_dir, sample_result):
    """Database with some test data"""
    db = RedTeamResultsDB(temp_db_dir)

    for i in range(5):
        result = sample_result.copy()
        result['scenario_id'] = f'ATK-00{i+1}'
        db.save_result(result, 'session_001')

    for i in range(3):
        result = sample_result.copy()
        result['scenario_id'] = f'ATK-10{i+1}'
        result['category'] = 'jailbreak'
        result['result'] = 'detected'
        db.save_result(result, 'session_002')

    return db


class TestDatabaseInit:
    """Test database initialization"""

    def test_init_creates_directory(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        assert Path(temp_db_dir).exists()
        assert Path(temp_db_dir).is_dir()

    def test_init_creates_index_file(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        index_file = Path(temp_db_dir) / "index.json"
        assert index_file.exists()

    def test_init_loads_existing_index(self, temp_db_dir):
        db1 = RedTeamResultsDB(temp_db_dir)
        db1.index['sessions']['test'] = {'file': 'test.json'}
        db1._save_index()

        db2 = RedTeamResultsDB(temp_db_dir)
        assert 'test' in db2.index['sessions']

    def test_init_default_directory(self):
        db = RedTeamResultsDB()
        assert db.db_dir.name == "redteam_results"


class TestSaveLoadResults:
    """Test saving and loading results"""

    def test_save_result_creates_session_file(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)
        db.save_result(sample_result, 'test_session')

        session_file = Path(temp_db_dir) / "test_session.json"
        assert session_file.exists()

    def test_save_result_updates_index(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)
        db.save_result(sample_result, 'test_session')

        assert 'test_session' in db.index['sessions']
        assert db.index['sessions']['test_session']['total_tests'] == 1

    def test_save_multiple_results_same_session(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)

        for i in range(3):
            result = sample_result.copy()
            result['scenario_id'] = f'ATK-00{i+1}'
            db.save_result(result, 'test_session')

        session_data = db.get_session('test_session')
        assert len(session_data['results']) == 3
        assert session_data['total_tests'] == 3

    def test_save_result_with_dataclass(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)

        mock_result = Mock()
        mock_result.__dict__ = {
            'scenario_id': 'ATK-001',
            'result': 'bypass',
            'confidence': 0.90
        }

        db.save_result(mock_result, 'test_session')
        session_data = db.get_session('test_session')

        assert session_data is not None
        assert len(session_data['results']) == 1

    def test_get_session_not_found(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        result = db.get_session('nonexistent')
        assert result is None

    def test_save_result_preserves_timestamps(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)
        db.save_result(sample_result, 'test_session')

        session_data = db.get_session('test_session')
        assert 'started_at' in session_data
        assert 'updated_at' in session_data


class TestSessionManagement:
    """Test session listing and management"""

    def test_list_sessions_empty(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        sessions = db.list_sessions()
        assert sessions == []

    def test_list_sessions_sorted(self, populated_db):
        sessions = populated_db.list_sessions()
        assert len(sessions) == 2
        assert sessions[0]['session_id'] == 'session_002'

    def test_get_latest_session(self, populated_db):
        latest = populated_db.get_latest_session()
        assert latest is not None
        assert latest['session_id'] == 'session_002'

    def test_get_latest_session_empty_db(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        latest = db.get_latest_session()
        assert latest is None

    def test_delete_session_success(self, populated_db):
        result = populated_db.delete_session('session_001')
        assert result is True
        assert 'session_001' not in populated_db.index['sessions']
        assert populated_db.get_session('session_001') is None

    def test_delete_session_not_found(self, populated_db):
        with patch('builtins.print'):
            result = populated_db.delete_session('nonexistent')
        assert result is False

    def test_cleanup_old_sessions(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)

        for i in range(15):
            result = sample_result.copy()
            db.save_result(result, f'session_{i:03d}')

        with patch('builtins.print'):
            deleted = db.cleanup_old_sessions(keep_latest=10)

        assert deleted == 5
        assert len(db.list_sessions()) == 10

    def test_cleanup_fewer_than_threshold(self, populated_db):
        with patch('builtins.print'):
            deleted = populated_db.cleanup_old_sessions(keep_latest=10)
        assert deleted == 0


class TestQueryFunctions:
    """Test result querying functions"""

    def test_query_by_category(self, populated_db):
        results = populated_db.query_by_category('jailbreak')
        assert len(results) == 3
        assert all(r['category'] == 'jailbreak' for r in results)

    def test_query_by_category_specific_session(self, populated_db):
        results = populated_db.query_by_category('jailbreak', 'session_002')
        assert len(results) == 3
        assert all(r['category'] == 'jailbreak' for r in results)

    def test_query_by_category_not_found(self, populated_db):
        results = populated_db.query_by_category('nonexistent')
        assert results == []

    def test_query_by_result(self, populated_db):
        detected_results = populated_db.query_by_result('detected')
        assert len(detected_results) == 3
        assert all(r['result'] == 'detected' for r in detected_results)

    def test_query_by_result_specific_session(self, populated_db):
        detected_results = populated_db.query_by_result('detected', 'session_002')
        assert len(detected_results) == 3
        assert all(r['result'] == 'detected' for r in detected_results)

    def test_query_by_difficulty(self, populated_db):
        easy_results = populated_db.query_by_difficulty('easy')
        assert len(easy_results) == 3
        assert all(r['difficulty'] == 'easy' for r in easy_results)

    def test_query_by_difficulty_case_insensitive(self, populated_db):
        results1 = populated_db.query_by_difficulty('EASY')
        results2 = populated_db.query_by_difficulty('easy')
        assert len(results1) == len(results2)


class TestStatistics:
    """Test statistics generation"""

    def test_get_statistics_basic(self, populated_db):
        stats = populated_db.get_statistics('session_001')
        assert stats['total_tests'] == 5
        assert 'by_result' in stats
        assert 'by_category' in stats
        assert 'by_difficulty' in stats
        assert 'avg_execution_time_ms' in stats

    def test_get_statistics_empty_session(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        stats = db.get_statistics('nonexistent')
        assert 'error' in stats

    def test_statistics_calculations(self, populated_db):
        stats = populated_db.get_statistics('session_001')
        assert stats['by_result']['bypass'] == 5
        assert stats['avg_confidence'] == 0.95
        assert stats['bypass_rate'] == 100.0
        assert stats['detection_rate'] == 0.0

    def test_statistics_high_confidence_tests(self, populated_db):
        stats = populated_db.get_statistics('session_001')
        assert stats['high_confidence_tests'] == 5

    def test_statistics_mixed_results(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)

        for i in range(3):
            result = sample_result.copy()
            result['result'] = 'bypass'
            db.save_result(result, 'test_session')

        for i in range(2):
            result = sample_result.copy()
            result['result'] = 'detected'
            db.save_result(result, 'test_session')

        stats = db.get_statistics('test_session')
        assert stats['by_result']['bypass'] == 3
        assert stats['by_result']['detected'] == 2
        assert stats['bypass_rate'] == 60.0
        assert stats['detection_rate'] == 40.0


class TestExportFunctions:
    """Test export functionality"""

    def test_export_to_json(self, populated_db, temp_db_dir):
        output_file = Path(temp_db_dir) / "export.json"
        with patch('builtins.print'):
            populated_db.export_to_json(str(output_file), 'session_001')

        assert output_file.exists()
        with open(output_file, 'r') as f:
            data = json.load(f)
        assert data['session_id'] == 'session_001'
        assert len(data['results']) == 5

    def test_export_to_json_no_session(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        output_file = Path(temp_db_dir) / "export.json"
        with patch('builtins.print'):
            db.export_to_json(str(output_file))
        assert not output_file.exists()

    def test_export_to_csv(self, populated_db, temp_db_dir):
        output_file = Path(temp_db_dir) / "export.csv"
        with patch('builtins.print'):
            populated_db.export_to_csv(str(output_file), 'session_001')

        assert output_file.exists()
        with open(output_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 5
        assert 'scenario_id' in rows[0]

    def test_export_to_csv_empty_results(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        output_file = Path(temp_db_dir) / "export.csv"
        with patch('builtins.print'):
            db.export_to_csv(str(output_file))
        assert not output_file.exists()


class TestReportGeneration:
    """Test report generation"""

    def test_generate_report_basic(self, populated_db):
        report = populated_db.generate_report('session_001')
        assert '# Red Team Test Report' in report
        assert 'session_001' in report
        assert 'Total Tests' in report
        assert 'Detection Rate' in report

    def test_generate_report_has_sections(self, populated_db):
        report = populated_db.generate_report('session_001')
        assert '## Summary' in report
        assert '## Results by Type' in report
        assert '## Results by Category' in report
        assert '## Results by Difficulty' in report

    def test_generate_report_no_session(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        report = db.generate_report()
        assert '# Error' in report

    def test_save_report(self, populated_db, temp_db_dir):
        output_file = Path(temp_db_dir) / "report.md"
        with patch('builtins.print'):
            populated_db.save_report(str(output_file), 'session_001')
        assert output_file.exists()
        content = output_file.read_text()
        assert '# Red Team Test Report' in content

    def test_report_formatting(self, populated_db):
        report = populated_db.generate_report('session_001')
        assert report.startswith('# ')
        assert '**' in report
        assert '-' in report


class TestErrorHandling:
    """Test error conditions"""

    def test_save_result_invalid_data(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        invalid_result = None
        try:
            db.save_result(invalid_result, 'test')
        except Exception as e:
            assert isinstance(e, (AttributeError, TypeError))

    def test_corrupted_index_file(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        index_file = Path(temp_db_dir) / "index.json"
        index_file.write_text("{ invalid json [")
        try:
            db2 = RedTeamResultsDB(temp_db_dir)
        except json.JSONDecodeError:
            pass

    def test_missing_result_fields(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        minimal_result = {
            'scenario_id': 'ATK-001',
            'result': 'bypass'
        }
        db.save_result(minimal_result, 'test_session')
        session = db.get_session('test_session')
        assert session is not None
        assert len(session['results']) == 1

    def test_export_permission_error(self, populated_db, temp_db_dir):
        output_file = Path(temp_db_dir) / "readonly.json"
        with patch('builtins.open', side_effect=PermissionError("Access denied")):
            with pytest.raises(PermissionError):
                populated_db.export_to_json(str(output_file))


class TestEdgeCases:
    """Test edge cases"""

    def test_unicode_in_results(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)
        result = sample_result.copy()
        result['response'] = "Response with Unicode: test"
        db.save_result(result, 'test_session')
        session = db.get_session('test_session')
        assert session is not None

    def test_very_large_result(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)
        result = sample_result.copy()
        result['response'] = 'x' * 1000000
        db.save_result(result, 'test_session')
        session = db.get_session('test_session')
        assert session is not None

    def test_special_characters_in_session_id(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)
        session_id = "session-test_123"
        db.save_result(sample_result, session_id)
        session = db.get_session(session_id)
        assert session is not None

    def test_empty_results_list(self, temp_db_dir):
        db = RedTeamResultsDB(temp_db_dir)
        session_data = {
            'session_id': 'empty_session',
            'started_at': datetime.now().isoformat(),
            'results': []
        }
        session_file = Path(temp_db_dir) / "empty_session.json"
        with open(session_file, 'w') as f:
            json.dump(session_data, f)

        db.index['sessions']['empty_session'] = {
            'file': str(session_file),
            'started_at': session_data['started_at'],
            'total_tests': 0
        }

        stats = db.get_statistics('empty_session')
        assert 'error' in stats

    def test_concurrent_writes_different_sessions(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)
        db.save_result(sample_result, 'session_001')
        db.save_result(sample_result, 'session_002')

        assert db.get_session('session_001') is not None
        assert db.get_session('session_002') is not None


class TestStorageIntegration:
    """End-to-end integration tests"""

    def test_full_workflow(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)

        for i in range(5):
            result = sample_result.copy()
            result['scenario_id'] = f'ATK-{i:03d}'
            db.save_result(result, 'integration_test')

        results = db.query_by_category('prompt_injection', 'integration_test')
        assert len(results) == 5

        stats = db.get_statistics('integration_test')
        assert stats['total_tests'] == 5

        report = db.generate_report('integration_test')
        assert 'integration_test' in report

        json_file = Path(temp_db_dir) / "export.json"
        with patch('builtins.print'):
            db.export_to_json(str(json_file), 'integration_test')
        assert json_file.exists()

        csv_file = Path(temp_db_dir) / "export.csv"
        with patch('builtins.print'):
            db.export_to_csv(str(csv_file), 'integration_test')
        assert csv_file.exists()

    def test_multi_session_workflow(self, temp_db_dir, sample_result):
        db = RedTeamResultsDB(temp_db_dir)

        for session_num in range(3):
            for result_num in range(5):
                result = sample_result.copy()
                result['scenario_id'] = f'ATK-{result_num:03d}'
                db.save_result(result, f'session_{session_num:03d}')

        sessions = db.list_sessions()
        assert len(sessions) == 3

        latest = db.get_latest_session()
        assert latest['session_id'] == 'session_002'

        with patch('builtins.print'):
            deleted = db.cleanup_old_sessions(keep_latest=2)
        assert deleted == 1
