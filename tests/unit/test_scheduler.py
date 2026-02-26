"""
Tests for Red Team Scheduler.
Migrated from oubliette_redteam/tests/test_scheduler.py
"""

import pytest
from datetime import datetime, timedelta

from oubliette_dungeon.scheduler import CronExpression, RedTeamScheduler


class TestCronExpression:
    def test_parse_star(self):
        cron = CronExpression("* * * * *")
        assert len(cron.minute) == 60
        assert len(cron.hour) == 24

    def test_parse_exact(self):
        cron = CronExpression("30 2 * * *")
        assert cron.minute == {30}
        assert cron.hour == {2}

    def test_parse_step(self):
        cron = CronExpression("*/15 * * * *")
        assert cron.minute == {0, 15, 30, 45}

    def test_parse_range(self):
        cron = CronExpression("0 9-17 * * *")
        assert cron.hour == set(range(9, 18))

    def test_parse_list(self):
        cron = CronExpression("0 8,12,18 * * *")
        assert cron.hour == {8, 12, 18}

    def test_invalid_expression(self):
        with pytest.raises(ValueError, match="Invalid cron expression"):
            CronExpression("* * *")

    def test_matches_exact(self):
        cron = CronExpression("30 14 * * *")
        dt = datetime(2026, 2, 7, 14, 30)
        assert cron.matches(dt) is True

    def test_no_match(self):
        cron = CronExpression("30 14 * * *")
        dt = datetime(2026, 2, 7, 14, 31)
        assert cron.matches(dt) is False

    def test_next_run(self):
        cron = CronExpression("0 0 * * *")
        after = datetime(2026, 2, 7, 12, 0)
        next_run = cron.next_run(after=after)
        assert next_run is not None
        assert next_run.hour == 0
        assert next_run.minute == 0
        assert next_run.day == 8

    def test_next_run_same_day(self):
        cron = CronExpression("30 14 * * *")
        after = datetime(2026, 2, 7, 10, 0)
        next_run = cron.next_run(after=after)
        assert next_run is not None
        assert next_run.hour == 14
        assert next_run.minute == 30
        assert next_run.day == 7

    def test_weekday(self):
        cron = CronExpression("0 9 * * 0")
        dt = datetime(2026, 2, 9, 9, 0)
        assert cron.matches(dt) is True
        dt2 = datetime(2026, 2, 10, 9, 0)
        assert cron.matches(dt2) is False


class TestRedTeamScheduler:
    @pytest.fixture
    def scheduler(self, tmp_path):
        sched_file = str(tmp_path / "schedules.json")
        hist_file = str(tmp_path / "history.json")
        return RedTeamScheduler(
            schedules_file=sched_file,
            history_file=hist_file,
        )

    def test_schedule_run(self, scheduler):
        job_id = scheduler.schedule_run(
            name="Test Job",
            cron="0 2 * * *",
            target_url="http://localhost:5000/api/chat",
        )
        assert job_id is not None
        assert len(job_id) == 8

    def test_list_jobs(self, scheduler):
        scheduler.schedule_run(name="Job 1", cron="0 1 * * *")
        scheduler.schedule_run(name="Job 2", cron="0 2 * * *")
        jobs = scheduler.list_jobs()
        assert len(jobs) == 2

    def test_get_job(self, scheduler):
        job_id = scheduler.schedule_run(name="Test", cron="0 3 * * *")
        job = scheduler.get_job(job_id)
        assert job is not None
        assert job["name"] == "Test"
        assert job["cron"] == "0 3 * * *"

    def test_get_nonexistent_job(self, scheduler):
        assert scheduler.get_job("nonexistent") is None

    def test_cancel_job(self, scheduler):
        job_id = scheduler.schedule_run(name="Cancel Me", cron="0 4 * * *")
        assert scheduler.cancel_job(job_id) is True
        assert scheduler.get_job(job_id) is None

    def test_cancel_nonexistent(self, scheduler):
        assert scheduler.cancel_job("nonexistent") is False

    def test_update_job(self, scheduler):
        job_id = scheduler.schedule_run(name="Original", cron="0 5 * * *")
        updated = scheduler.update_job(job_id, name="Updated", enabled=False)
        assert updated is not None
        assert updated["name"] == "Updated"
        assert updated["enabled"] is False

    def test_update_nonexistent(self, scheduler):
        assert scheduler.update_job("nonexistent", name="X") is None

    def test_update_cron_recalculates_next_run(self, scheduler):
        job_id = scheduler.schedule_run(name="Test", cron="0 1 * * *")
        original_next = scheduler.get_job(job_id)["next_run"]
        scheduler.update_job(job_id, cron="0 23 * * *")
        new_next = scheduler.get_job(job_id)["next_run"]
        assert new_next is not None

    def test_invalid_cron_rejected(self, scheduler):
        with pytest.raises(ValueError):
            scheduler.schedule_run(name="Bad", cron="invalid")

    def test_job_persistence(self, tmp_path):
        sched_file = str(tmp_path / "schedules.json")
        hist_file = str(tmp_path / "history.json")

        s1 = RedTeamScheduler(schedules_file=sched_file, history_file=hist_file)
        job_id = s1.schedule_run(name="Persistent", cron="0 6 * * *")

        s2 = RedTeamScheduler(schedules_file=sched_file, history_file=hist_file)
        job = s2.get_job(job_id)
        assert job is not None
        assert job["name"] == "Persistent"

    def test_schedule_one_time(self, scheduler):
        when = datetime.now() + timedelta(hours=1)
        job_id = scheduler.schedule_one_time(when=when, name="One Shot")
        job = scheduler.get_job(job_id)
        assert job is not None
        assert job.get("one_time") is True

    def test_history_starts_empty(self, scheduler):
        history = scheduler.get_history()
        assert history == []

    def test_job_default_values(self, scheduler):
        job_id = scheduler.schedule_run(name="Defaults", cron="0 0 * * *")
        job = scheduler.get_job(job_id)
        assert job["categories"] == ["all"]
        assert job["difficulty"] == ["all"]
        assert job["scenarios"] == []
        assert job["notification"] == {"type": "log"}
        assert job["enabled"] is True
        assert job["timeout"] == 30

    def test_job_custom_categories(self, scheduler):
        job_id = scheduler.schedule_run(
            name="Focused",
            cron="0 0 * * *",
            categories=["CAT-01", "CAT-03"],
            difficulty=["Medium", "Hard"],
        )
        job = scheduler.get_job(job_id)
        assert job["categories"] == ["CAT-01", "CAT-03"]
        assert job["difficulty"] == ["Medium", "Hard"]

    def test_job_webhook_notification(self, scheduler):
        job_id = scheduler.schedule_run(
            name="Webhook",
            cron="0 0 * * *",
            notification={"type": "webhook", "url": "https://hooks.example.com/notify"},
        )
        job = scheduler.get_job(job_id)
        assert job["notification"]["type"] == "webhook"
        assert "example.com" in job["notification"]["url"]

    def test_start_stop(self, scheduler):
        scheduler.start()
        assert scheduler._running is True
        scheduler.stop()
        assert scheduler._running is False
