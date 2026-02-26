"""
oubliette_dungeon.core - Core red team engine components.
"""

import sys

from oubliette_dungeon.core.models import (
    DEFAULT_TARGET_URL,
    AttackCategory,
    AttackResult,
    AttackScenario,
    AttackTestResult,
    DifficultyLevel,
    TestResult,
)
from oubliette_dungeon.core.loader import ScenarioLoader
from oubliette_dungeon.core.executor import AttackExecutor
from oubliette_dungeon.core.evaluator import ResultEvaluator
from oubliette_dungeon.core.orchestrator import RedTeamOrchestrator
from oubliette_dungeon.core.metrics import pass_at_k, avg_turns_to_jailbreak, avg_risk_density


def _default_scenarios_path() -> str:
    """Resolve the path to the bundled default scenarios YAML."""
    if sys.version_info >= (3, 9):
        from importlib.resources import files
        return str(files("oubliette_dungeon") / "scenarios" / "default.yaml")
    import importlib.resources as _res
    with _res.path("oubliette_dungeon.scenarios", "default.yaml") as p:
        return str(p)


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
    "_default_scenarios_path",
]
