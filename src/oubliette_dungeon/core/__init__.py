"""
oubliette_dungeon.core - Core red team engine components.
"""

from oubliette_dungeon.core.evaluator import ResultEvaluator
from oubliette_dungeon.core.executor import AttackExecutor
from oubliette_dungeon.core.loader import ScenarioLoader
from oubliette_dungeon.core.metrics import avg_risk_density, avg_turns_to_jailbreak, pass_at_k
from oubliette_dungeon.core.models import (
    DEFAULT_TARGET_URL,
    AttackCategory,
    AttackResult,
    AttackScenario,
    AttackTestResult,
    DifficultyLevel,
    TestResult,
)
from oubliette_dungeon.core.offline import OfflineExecutor
from oubliette_dungeon.core.orchestrator import RedTeamOrchestrator
from oubliette_dungeon.core.osef import OSEFReport


def _default_scenarios_path() -> str:
    """Resolve the path to the bundled default scenarios YAML."""
    from importlib.resources import files

    return str(files("oubliette_dungeon") / "scenarios" / "default.yaml")


__all__ = [
    "DEFAULT_TARGET_URL",
    "AttackCategory",
    "AttackResult",
    "AttackScenario",
    "AttackTestResult",
    "DifficultyLevel",
    "TestResult",
    "ScenarioLoader",
    "AttackExecutor",
    "ResultEvaluator",
    "RedTeamOrchestrator",
    "pass_at_k",
    "avg_turns_to_jailbreak",
    "avg_risk_density",
    "OfflineExecutor",
    "OSEFReport",
    "_default_scenarios_path",
]
