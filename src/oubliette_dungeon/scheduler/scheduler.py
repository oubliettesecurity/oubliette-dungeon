"""
Red Team Scheduler - Continuous Red Teaming Engine
===================================================
Cron-like scheduler for automated red team testing with job persistence,
webhook notifications, and run history tracking.

Usage:
    from oubliette_dungeon.scheduler import RedTeamScheduler

    scheduler = RedTeamScheduler()
    scheduler.start()

    scheduler.schedule_run(
        name="Nightly Full Scan",
        cron="0 2 * * *",
        target_url="http://localhost:5000/api/chat",
    )

    scheduler.run_now(target_url="http://localhost:5000/api/chat")
"""

import json
import stat
import sys
import uuid
import time
import threading
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List

from oubliette_dungeon.core.models import DEFAULT_TARGET_URL


CRON_ALIASES = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}


class CronExpression:
    """Minimal cron expression parser."""

    def __init__(self, expr):
        self.raw = expr.strip()
        if self.raw in CRON_ALIASES:
            self.raw = CRON_ALIASES[self.raw]
        parts = self.raw.split()
        if len(parts) != 5:
            raise ValueError(
                f"Invalid cron expression: '{expr}'. "
                "Expected 5 fields: minute hour day month weekday"
            )
        self.minute = self._parse_field(parts[0], 0, 59)
        self.hour = self._parse_field(parts[1], 0, 23)
        self.day = self._parse_field(parts[2], 1, 31)
        self.month = self._parse_field(parts[3], 1, 12)
        self.weekday = self._parse_field(parts[4], 0, 6)

    @staticmethod
    def _parse_field(field, min_val, max_val):
        values = set()
        for part in field.split(","):
            if part == "*":
                values.update(range(min_val, max_val + 1))
            elif part.startswith("*/"):
                step = int(part[2:])
                if step <= 0:
                    raise ValueError(f"Invalid step: {part}")
                values.update(range(min_val, max_val + 1, step))
            elif "-" in part:
                lo, hi = part.split("-", 1)
                lo, hi = int(lo), int(hi)
                values.update(range(lo, hi + 1))
            else:
                values.add(int(part))
        return values

    def matches(self, dt):
        return (
            dt.minute in self.minute
            and dt.hour in self.hour
            and dt.day in self.day
            and dt.month in self.month
            and dt.weekday() in self.weekday
        )

    def next_run(self, after=None):
        if after is None:
            after = datetime.now()
        candidate = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        limit = after + timedelta(days=366)
        while candidate < limit:
            if self.matches(candidate):
                return candidate
            candidate += timedelta(minutes=1)
        return None


SCHEDULES_FILE = os.getenv(
    "DUNGEON_SCHEDULES_FILE",
    str(Path(__file__).parent / "dungeon_schedules.json"),
)

HISTORY_FILE = os.getenv(
    "DUNGEON_HISTORY_FILE",
    str(Path(__file__).parent / "dungeon_history.json"),
)

MAX_HISTORY = 200


class RedTeamScheduler:
    """Continuous red teaming scheduler with cron-like job scheduling."""

    def __init__(self, schedules_file=None, history_file=None):
        self.schedules_file = schedules_file or SCHEDULES_FILE
        self.history_file = history_file or HISTORY_FILE
        self._lock = threading.RLock()
        self._running = False
        self._thread = None
        self._jobs = self._load_jobs()
        self._history = self._load_history()

    def _load_jobs(self):
        try:
            with open(self.schedules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("jobs", {})
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_jobs(self):
        with open(self.schedules_file, "w", encoding="utf-8") as f:
            json.dump({"jobs": self._jobs}, f, indent=2)
        self._restrict_file(self.schedules_file)

    def _load_history(self):
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("runs", [])
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save_history(self):
        self._history = self._history[-MAX_HISTORY:]
        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump({"runs": self._history}, f, indent=2)
        self._restrict_file(self.history_file)

    @staticmethod
    def _restrict_file(path):
        if sys.platform != "win32":
            try:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass

    def schedule_run(self, name, cron, target_url=None, categories=None,
                     difficulty=None, scenarios=None, notification=None,
                     timeout=30, enabled=True):
        CronExpression(cron)
        job_id = str(uuid.uuid4())[:8]
        cron_obj = CronExpression(cron)
        next_run = cron_obj.next_run()

        job = {
            "job_id": job_id,
            "name": name,
            "cron": cron,
            "target_url": target_url or os.getenv("DUNGEON_TARGET_URL", DEFAULT_TARGET_URL),
            "categories": categories or ["all"],
            "difficulty": difficulty or ["all"],
            "scenarios": scenarios or [],
            "notification": notification or {"type": "log"},
            "timeout": timeout,
            "enabled": enabled,
            "created_at": datetime.now().isoformat(),
            "last_run": None,
            "next_run": next_run.isoformat() if next_run else None,
        }

        with self._lock:
            self._jobs[job_id] = job
            self._save_jobs()

        print(f"[SCHEDULER] Job created: {job_id} ({name}) - next run: {next_run}")
        return job_id

    def schedule_one_time(self, when, name=None, **kwargs):
        if isinstance(when, str):
            when = datetime.fromisoformat(when)
        cron = f"{when.minute} {when.hour} {when.day} {when.month} *"
        job_id = self.schedule_run(
            name=name or f"One-time run at {when.isoformat()}",
            cron=cron,
            **kwargs,
        )
        with self._lock:
            self._jobs[job_id]["one_time"] = True
            self._jobs[job_id]["next_run"] = when.isoformat()
            self._save_jobs()
        return job_id

    def list_jobs(self):
        with self._lock:
            return list(self._jobs.values())

    def get_job(self, job_id):
        with self._lock:
            return self._jobs.get(job_id)

    def update_job(self, job_id, **updates):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            allowed_fields = {
                "name", "cron", "target_url", "categories", "difficulty",
                "scenarios", "notification", "timeout", "enabled",
            }
            for key, value in updates.items():
                if key in allowed_fields:
                    job[key] = value
            if "cron" in updates:
                cron_obj = CronExpression(updates["cron"])
                next_run = cron_obj.next_run()
                job["next_run"] = next_run.isoformat() if next_run else None
            self._save_jobs()
            return job

    def cancel_job(self, job_id):
        with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                self._save_jobs()
                print(f"[SCHEDULER] Job cancelled: {job_id}")
                return True
            return False

    def get_history(self, limit=50):
        with self._lock:
            return list(reversed(self._history[-limit:]))

    def run_now(self, job_id=None, target_url=None, categories=None,
                scenarios=None, timeout=30):
        run_config = {
            "target_url": target_url or os.getenv("DUNGEON_TARGET_URL", DEFAULT_TARGET_URL),
            "categories": categories or ["all"],
            "scenarios": scenarios or [],
            "timeout": timeout,
        }
        if job_id:
            with self._lock:
                job = self._jobs.get(job_id)
                if job:
                    run_config.update({
                        "target_url": target_url or job["target_url"],
                        "categories": categories or job["categories"],
                        "scenarios": scenarios or job["scenarios"],
                        "timeout": timeout or job.get("timeout", 30),
                    })
        run_id = str(uuid.uuid4())[:8]
        t = threading.Thread(
            target=self._execute_run,
            args=(run_id, run_config, job_id),
            daemon=True,
        )
        t.start()
        return run_id

    def _execute_run(self, run_id, config, job_id=None):
        started_at = datetime.now().isoformat()
        result = {
            "run_id": run_id,
            "job_id": job_id,
            "started_at": started_at,
            "status": "running",
            "config": config,
        }
        try:
            from oubliette_dungeon.core import RedTeamOrchestrator, _default_scenarios_path
            from oubliette_dungeon.storage import RedTeamResultsDB

            scenarios_file = _default_scenarios_path()
            results_db = RedTeamResultsDB(
                os.getenv("DUNGEON_DB_DIR", "redteam_results")
            )
            orchestrator = RedTeamOrchestrator(
                scenario_file=scenarios_file,
                target_url=config["target_url"],
                results_db=results_db,
                timeout=config.get("timeout", 30),
            )
            session_id = orchestrator.current_session_id

            categories = config.get("categories", ["all"])
            scenarios = config.get("scenarios", [])

            if scenarios:
                for scenario_id in scenarios:
                    try:
                        orchestrator.run_single_scenario(scenario_id)
                    except Exception as e:
                        print(f"[SCHEDULER] Scenario {scenario_id} error: {e}")
            elif categories and "all" not in categories:
                for cat in categories:
                    try:
                        orchestrator.run_by_category(cat)
                    except Exception as e:
                        print(f"[SCHEDULER] Category {cat} error: {e}")
            else:
                orchestrator.run_all_scenarios()

            stats = results_db.get_statistics(session_id)
            result.update({
                "status": "completed",
                "completed_at": datetime.now().isoformat(),
                "session_id": session_id,
                "total_tests": stats.get("total_tests", 0),
                "detection_rate": stats.get("detection_rate", 0),
                "bypass_rate": stats.get("bypass_rate", 0),
            })
        except ImportError as e:
            result.update({
                "status": "error",
                "completed_at": datetime.now().isoformat(),
                "error": f"Missing dependency: {e}",
            })
        except Exception as e:
            result.update({
                "status": "error",
                "completed_at": datetime.now().isoformat(),
                "error": str(e),
            })

        with self._lock:
            self._history.append(result)
            self._save_history()
            if job_id and job_id in self._jobs:
                self._jobs[job_id]["last_run"] = result.get("completed_at", started_at)
                try:
                    cron_obj = CronExpression(self._jobs[job_id]["cron"])
                    next_run = cron_obj.next_run()
                    self._jobs[job_id]["next_run"] = next_run.isoformat() if next_run else None
                except ValueError:
                    pass
                if self._jobs[job_id].get("one_time"):
                    self._jobs[job_id]["enabled"] = False
                self._save_jobs()

        if job_id:
            with self._lock:
                job = self._jobs.get(job_id, {})
            notification = job.get("notification", {"type": "log"})
        else:
            notification = {"type": "log"}
        self._send_notification(notification, result)
        print(f"[SCHEDULER] Run {run_id} completed: status={result['status']}")

    def _send_notification(self, notification, result):
        ntype = notification.get("type", "log")
        if ntype == "log":
            status = result.get("status", "unknown")
            run_id = result.get("run_id", "?")
            detection = result.get("detection_rate", "N/A")
            print(f"[SCHEDULER-NOTIFY] Run {run_id}: {status} (detection: {detection}%)")
        elif ntype == "webhook":
            url = notification.get("url", "")
            if url:
                if not self._is_safe_webhook_url(url):
                    print(f"[SCHEDULER-NOTIFY] Webhook URL blocked (SSRF protection): {url}")
                    return
                try:
                    import requests
                    payload = {
                        "text": (
                            f"Red Team Run {result.get('run_id', '?')}: "
                            f"{result.get('status', 'unknown')}\n"
                            f"Tests: {result.get('total_tests', 0)} | "
                            f"Detection: {result.get('detection_rate', 0):.1f}% | "
                            f"Bypass: {result.get('bypass_rate', 0):.1f}%"
                        ),
                        "result": result,
                    }
                    requests.post(url, json=payload, timeout=10)
                except Exception as e:
                    print(f"[SCHEDULER-NOTIFY] Webhook error: {e}")
        elif ntype == "file":
            filepath = notification.get("path", "dungeon_notification.json")
            try:
                with open(filepath, "a", encoding="utf-8") as f:
                    f.write(json.dumps(result) + "\n")
            except Exception as e:
                print(f"[SCHEDULER-NOTIFY] File write error: {e}")

    @staticmethod
    def _is_safe_webhook_url(url: str) -> bool:
        import ipaddress
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        blocked = {"localhost", "localhost.localdomain", "metadata.google.internal", "169.254.169.254"}
        if hostname.lower() in blocked:
            return False
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return False
        except ValueError:
            lower = hostname.lower()
            if lower.endswith((".local", ".internal", ".corp", ".lan")):
                return False
        return True

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._thread.start()
        print("[SCHEDULER] Started")

    def stop(self):
        self._running = False
        print("[SCHEDULER] Stopped")

    def _scheduler_loop(self):
        while self._running:
            try:
                now = datetime.now()
                with self._lock:
                    for job_id, job in list(self._jobs.items()):
                        if not job.get("enabled", True):
                            continue
                        next_run_str = job.get("next_run")
                        if not next_run_str:
                            continue
                        try:
                            next_run = datetime.fromisoformat(next_run_str)
                        except ValueError:
                            continue
                        if now >= next_run:
                            print(f"[SCHEDULER] Triggering job: {job_id} ({job['name']})")
                            run_id = str(uuid.uuid4())[:8]
                            config = {
                                "target_url": job["target_url"],
                                "categories": job.get("categories", ["all"]),
                                "scenarios": job.get("scenarios", []),
                                "timeout": job.get("timeout", 30),
                            }
                            t = threading.Thread(
                                target=self._execute_run,
                                args=(run_id, config, job_id),
                                daemon=True,
                            )
                            t.start()
                            try:
                                cron_obj = CronExpression(job["cron"])
                                next_next = cron_obj.next_run(after=now)
                                job["next_run"] = next_next.isoformat() if next_next else None
                            except ValueError:
                                job["next_run"] = None
                            self._save_jobs()
            except Exception as e:
                print(f"[SCHEDULER] Loop error: {e}")
            for _ in range(30):
                if not self._running:
                    return
                time.sleep(1)


_scheduler = None
_scheduler_lock = threading.Lock()


def get_scheduler():
    global _scheduler
    if _scheduler is None:
        with _scheduler_lock:
            if _scheduler is None:
                _scheduler = RedTeamScheduler()
    return _scheduler
