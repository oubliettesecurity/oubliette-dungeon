"""
oubliette-dungeon -- AI Red Team Engine
========================================
Standalone adversarial testing for LLM applications.

Quick start::

    from oubliette_dungeon import RedTeamOrchestrator, RedTeamResultsDB

    db = RedTeamResultsDB("./results")
    orch = RedTeamOrchestrator(
        scenario_file="scenarios.yaml",
        target_url="http://localhost:8000/api/chat",
        results_db=db,
    )
    results = orch.run_all_scenarios()
    orch.print_summary(results)
"""

__version__ = "1.0.1"

# --- Eager imports (core, always available) ---
from oubliette_dungeon.core import (  # noqa: F401
    AttackCategory,
    AttackResult,
    AttackScenario,
    AttackTestResult,
    DifficultyLevel,
    TestResult,
    DEFAULT_TARGET_URL,
    ScenarioLoader,
    AttackExecutor,
    ResultEvaluator,
    RedTeamOrchestrator,
    pass_at_k,
    avg_turns_to_jailbreak,
    avg_risk_density,
)
from oubliette_dungeon.storage import RedTeamResultsDB  # noqa: F401

# --- Lazy imports (optional deps) ---
_LAZY_MODULES = {
    "RedTeamScheduler": "oubliette_dungeon.scheduler",
    "CronExpression": "oubliette_dungeon.scheduler",
    "get_scheduler": "oubliette_dungeon.scheduler",
    "dungeon_bp": "oubliette_dungeon.api",
    "create_app": "oubliette_dungeon.api",
    "set_unified_storage": "oubliette_dungeon.api",
    "ReportGenerator": "oubliette_dungeon.report",
    "OubliettePDF": "oubliette_dungeon.report",
    "RedTeamToolAdapter": "oubliette_dungeon.tools.base",
    "ToolManager": "oubliette_dungeon.tools.tool_manager",
}


def __getattr__(name):
    module_path = _LAZY_MODULES.get(name)
    if module_path is not None:
        import importlib
        mod = importlib.import_module(module_path)
        return getattr(mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Version
    "__version__",
    # Core (eager)
    "AttackCategory",
    "AttackResult",
    "AttackScenario",
    "DifficultyLevel",
    "AttackTestResult",
    "TestResult",
    "DEFAULT_TARGET_URL",
    "ScenarioLoader",
    "AttackExecutor",
    "ResultEvaluator",
    "RedTeamOrchestrator",
    "RedTeamResultsDB",
    "pass_at_k",
    "avg_turns_to_jailbreak",
    "avg_risk_density",
    # Lazy
    "RedTeamScheduler",
    "CronExpression",
    "get_scheduler",
    "dungeon_bp",
    "create_app",
    "set_unified_storage",
    "ReportGenerator",
    "OubliettePDF",
    "RedTeamToolAdapter",
    "ToolManager",
]
