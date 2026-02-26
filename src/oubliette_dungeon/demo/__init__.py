"""
oubliette_dungeon.demo - Demo mode with fixture data and mock target.
"""

import json
import os

from oubliette_dungeon.storage import RedTeamResultsDB


def load_fixtures(db_dir: str = "redteam_results") -> None:
    """Load pre-computed fixture data into the results database."""
    fixtures_path = os.path.join(os.path.dirname(__file__), "fixtures.json")
    if not os.path.exists(fixtures_path):
        print("No fixtures file found.")
        return

    with open(fixtures_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    db = RedTeamResultsDB(db_dir)
    session_id = data.get("session_id", "demo_session")

    for result in data.get("results", []):
        db.save_result(result, session_id)

    print(f"Loaded {len(data.get('results', []))} fixture results into session {session_id}")


__all__ = ["load_fixtures"]
