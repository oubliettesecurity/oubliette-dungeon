"""
JSON-based storage for red team test results.

Features:
- Save and load test results
- Query by session, category, difficulty, result type
- Generate reports and statistics
- Export to various formats (JSON, CSV)
"""

import csv
import json
import re
import stat
import sys
from datetime import datetime
from pathlib import Path

_SAFE_SESSION_ID = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")


def is_valid_session_id(session_id: str) -> bool:
    """Canonical session_id validator shared by storage and HTTP routes.

    HIGH fix (2026-04-22 audit): route-level validators used
    ``session_id.replace("_", "").isalnum()``, which rejected dashes, while
    storage accepted dashes via the regex above. An attacker could thus
    create a session via an alternate ingress and have it be unreadable
    through the main API -- or worse, storage could accept inputs that
    routes thought they had sanitized. Collapse to a single definition.
    """
    return isinstance(session_id, str) and bool(_SAFE_SESSION_ID.match(session_id))


def _validate_session_id(session_id: str) -> None:
    """Reject session IDs that could cause path traversal."""
    if not is_valid_session_id(session_id):
        raise ValueError("Invalid session_id: must be alphanumeric/dash/underscore, 1-128 chars")


def _restrict_permissions(path: Path) -> None:
    """Set restrictive file permissions (0600) on non-Windows systems."""
    if sys.platform != "win32":
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


class RedTeamResultsDB:
    """JSON-based database for storing red team test results."""

    def __init__(self, db_dir: str = "redteam_results"):
        self.db_dir = Path(db_dir)
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.db_dir / "index.json"
        self.index = self._load_index()

    def _load_index(self) -> dict:
        if self.index_file.exists():
            with open(self.index_file) as f:
                return json.load(f)
        default = {"sessions": {}}
        with open(self.index_file, "w") as f:
            json.dump(default, f, indent=2)
        _restrict_permissions(self.index_file)
        return default

    def _save_index(self) -> None:
        with open(self.index_file, "w") as f:
            json.dump(self.index, f, indent=2)
        _restrict_permissions(self.index_file)

    def save_result(
        self,
        result,
        session_id: str,
        caller_key_hint: str | None = None,
    ) -> None:
        """Save a single attack result.

        MED-11 fix (2026-04-22 audit): when the caller's API-key hint is
        supplied we persist it on the session record at first save, so
        subsequent reads can be scoped to the creating key. The hint is
        never changed after initial write -- key rotation produces a new
        session. None (dev-mode, unauthenticated) is recorded as the
        sentinel ``"__anon__"`` so anonymous reads don't leak authed
        sessions.
        """
        _validate_session_id(session_id)
        if hasattr(result, "__dict__"):
            result_dict = vars(result)
        else:
            result_dict = result

        session_file = self.db_dir / f"{session_id}.json"
        if session_file.exists():
            with open(session_file) as f:
                session_data = json.load(f)
        else:
            session_data = {
                "session_id": session_id,
                "started_at": datetime.now().isoformat(),
                "results": [],
                "created_by_key_hint": caller_key_hint or "__anon__",
            }

        # Only stamp the hint on first write; never overwrite a prior value.
        session_data.setdefault("created_by_key_hint", caller_key_hint or "__anon__")

        session_data["results"].append(result_dict)
        session_data["updated_at"] = datetime.now().isoformat()
        session_data["total_tests"] = len(session_data["results"])

        with open(session_file, "w") as f:
            json.dump(session_data, f, indent=2)
        _restrict_permissions(session_file)

        if session_id not in self.index["sessions"]:
            self.index["sessions"][session_id] = {
                "file": str(session_file),
                "started_at": session_data["started_at"],
                "total_tests": 0,
                "created_by_key_hint": session_data["created_by_key_hint"],
            }

        self.index["sessions"][session_id]["updated_at"] = session_data["updated_at"]
        self.index["sessions"][session_id]["total_tests"] = session_data["total_tests"]
        # Backfill the hint on the index for records that pre-date MED-11.
        self.index["sessions"][session_id].setdefault(
            "created_by_key_hint", session_data["created_by_key_hint"]
        )
        self._save_index()

    # ------------------------------------------------------------------
    # Read helpers -- accept an optional caller_key_hint for scoping.
    # ``None`` preserves the pre-MED-11 behaviour (return everything); a
    # concrete hint restricts reads to sessions authored by that key.
    # ------------------------------------------------------------------

    @staticmethod
    def _owned_by(session_data: dict, caller_key_hint: str | None) -> bool:
        if caller_key_hint is None:
            return True
        return session_data.get("created_by_key_hint") == caller_key_hint

    def get_session(
        self, session_id: str, caller_key_hint: str | None = None
    ) -> dict | None:
        _validate_session_id(session_id)
        session_file = self.db_dir / f"{session_id}.json"
        if not session_file.exists():
            return None
        with open(session_file) as f:
            session_data = json.load(f)
        if not self._owned_by(session_data, caller_key_hint):
            return None
        return session_data

    def list_sessions(self, caller_key_hint: str | None = None) -> list[dict]:
        sessions = []
        for session_id, meta in self.index["sessions"].items():
            if caller_key_hint is not None and meta.get("created_by_key_hint") != caller_key_hint:
                continue
            sessions.append({"session_id": session_id, **meta})
        return sorted(sessions, key=lambda x: x["started_at"], reverse=True)

    def get_latest_session(self, caller_key_hint: str | None = None) -> dict | None:
        sessions = self.list_sessions(caller_key_hint=caller_key_hint)
        if sessions:
            return self.get_session(
                sessions[0]["session_id"], caller_key_hint=caller_key_hint
            )
        return None

    def query_by_category(self, category: str, session_id: str | None = None) -> list[dict]:
        session_data = self.get_session(session_id) if session_id else self.get_latest_session()
        if not session_data:
            return []
        return [r for r in session_data["results"] if r["category"] == category]

    def query_by_result(self, result_type: str, session_id: str | None = None) -> list[dict]:
        session_data = self.get_session(session_id) if session_id else self.get_latest_session()
        if not session_data:
            return []
        return [r for r in session_data["results"] if r["result"] == result_type]

    def query_by_difficulty(self, difficulty: str, session_id: str | None = None) -> list[dict]:
        session_data = self.get_session(session_id) if session_id else self.get_latest_session()
        if not session_data:
            return []
        return [r for r in session_data["results"] if r["difficulty"].lower() == difficulty.lower()]

    def get_statistics(self, session_id: str | None = None) -> dict:
        session_data = self.get_session(session_id) if session_id else self.get_latest_session()
        if not session_data or not session_data["results"]:
            return {"error": "No results found"}

        results = session_data["results"]

        stats = {
            "session_id": session_data["session_id"],
            "total_tests": len(results),
            "started_at": session_data["started_at"],
            "updated_at": session_data.get("updated_at", ""),
            "by_result": {},
            "by_category": {},
            "by_difficulty": {},
            "avg_execution_time_ms": 0,
            "avg_confidence": 0,
            "detection_rate": 0,
            "bypass_rate": 0,
            "high_confidence_tests": 0,
        }

        total_time = 0
        total_confidence = 0
        detected = 0
        bypassed = 0
        high_conf = 0

        for result in results:
            result_type = result["result"]
            stats["by_result"][result_type] = stats["by_result"].get(result_type, 0) + 1
            category = result["category"]
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            difficulty = result["difficulty"]
            stats["by_difficulty"][difficulty] = stats["by_difficulty"].get(difficulty, 0) + 1

            total_time += result.get("execution_time_ms", 0)
            total_confidence += result.get("confidence", 0)

            if result_type == "detected":
                detected += 1
            elif result_type == "bypass":
                bypassed += 1

            if result.get("confidence", 0) >= 0.85:
                high_conf += 1

        stats["avg_execution_time_ms"] = total_time / len(results)
        stats["avg_confidence"] = total_confidence / len(results)
        stats["detection_rate"] = (detected / len(results)) * 100
        stats["bypass_rate"] = (bypassed / len(results)) * 100
        stats["high_confidence_tests"] = high_conf

        return stats

    def export_to_csv(self, output_file: str, session_id: str | None = None) -> None:
        session_data = self.get_session(session_id) if session_id else self.get_latest_session()
        if not session_data:
            print("No results to export")
            return
        results = session_data["results"]
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        print(f"Exported {len(results)} results to {output_file}")

    def export_to_json(self, output_file: str, session_id: str | None = None) -> None:
        session_data = self.get_session(session_id) if session_id else self.get_latest_session()
        if not session_data:
            print("No results to export")
            return
        with open(output_file, "w") as f:
            json.dump(session_data, f, indent=2)
        print(f"Exported session to {output_file}")

    def generate_report(self, session_id: str | None = None) -> str:
        stats = self.get_statistics(session_id)
        if "error" in stats:
            return f"# Error\n\n{stats['error']}"

        report = []
        report.append("# Red Team Test Report")
        report.append(f"\n**Session ID**: {stats['session_id']}")
        report.append(f"**Started**: {stats['started_at']}")
        report.append(f"**Completed**: {stats.get('updated_at', 'In progress')}")
        report.append("\n## Summary\n")
        report.append(f"- **Total Tests**: {stats['total_tests']}")
        report.append(f"- **Detection Rate**: {stats['detection_rate']:.1f}%")
        report.append(f"- **Bypass Rate**: {stats['bypass_rate']:.1f}%")
        report.append(f"- **Average Confidence**: {stats['avg_confidence']:.2%}")
        report.append(f"- **Average Execution Time**: {stats['avg_execution_time_ms']:.2f}ms")
        report.append(f"- **High Confidence Tests**: {stats['high_confidence_tests']}")

        report.append("\n## Results by Type\n")
        for result_type, count in stats["by_result"].items():
            percentage = (count / stats["total_tests"]) * 100
            report.append(f"- **{result_type}**: {count} ({percentage:.1f}%)")

        report.append("\n## Results by Category\n")
        for category, count in sorted(stats["by_category"].items()):
            percentage = (count / stats["total_tests"]) * 100
            report.append(f"- **{category}**: {count} ({percentage:.1f}%)")

        report.append("\n## Results by Difficulty\n")
        for difficulty, count in sorted(stats["by_difficulty"].items()):
            percentage = (count / stats["total_tests"]) * 100
            report.append(f"- **{difficulty}**: {count} ({percentage:.1f}%)")

        return "\n".join(report)

    def save_report(self, output_file: str, session_id: str | None = None) -> None:
        report = self.generate_report(session_id)
        with open(output_file, "w") as f:
            f.write(report)
        print(f"Report saved to {output_file}")

    def delete_session(self, session_id: str) -> bool:
        _validate_session_id(session_id)
        session_file = self.db_dir / f"{session_id}.json"
        if session_file.exists():
            session_file.unlink()
            if session_id in self.index["sessions"]:
                del self.index["sessions"][session_id]
                self._save_index()
            print(f"Deleted session: {session_id}")
            return True
        print(f"Session not found: {session_id}")
        return False

    def cleanup_old_sessions(self, keep_latest: int = 10) -> int:
        sessions = self.list_sessions()
        if len(sessions) <= keep_latest:
            print(f"Only {len(sessions)} sessions, nothing to clean up")
            return 0
        to_delete = sessions[keep_latest:]
        deleted_count = 0
        for session in to_delete:
            if self.delete_session(session["session_id"]):
                deleted_count += 1
        print(f"Cleaned up {deleted_count} old sessions")
        return deleted_count
