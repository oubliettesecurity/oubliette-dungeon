"""
Unified tool manager for third-party red team tool integrations.

Discovers available adapters, provides a single interface for the API
layer to list, select, and run tools, and optionally persists results
to the existing RedTeamResultsDB.
"""

import threading
from datetime import datetime
from typing import Dict, List, Optional

from oubliette_dungeon.core.models import AttackScenario, TestResult
from oubliette_dungeon.tools.base import RedTeamToolAdapter


class ToolManager:
    """Registry and dispatcher for all red team tool adapters."""

    def __init__(self, results_db=None):
        """
        Args:
            results_db: Optional RedTeamResultsDB instance for persisting
                       results.  If None, results are returned but not saved.
        """
        self._adapters: Dict[str, RedTeamToolAdapter] = {}
        self._results_db = results_db
        self._lock = threading.Lock()
        self._discover_tools()

    # -- Discovery -----------------------------------------------------------

    def _discover_tools(self) -> None:
        """Try importing each adapter and register it if importable."""
        adapter_specs = [
            ("pyrit", "oubliette_dungeon.tools.pyrit_adapter", "PyRITAdapter"),
            ("deepteam", "oubliette_dungeon.tools.deepteam_adapter", "DeepTeamAdapter"),
            ("aix", "oubliette_dungeon.tools.aix_adapter", "AixAdapter"),
        ]

        for name, module_path, class_name in adapter_specs:
            try:
                mod = __import__(module_path, fromlist=[class_name])
                cls = getattr(mod, class_name)
                adapter = cls()
                self._adapters[name] = adapter
            except Exception:
                pass  # Adapter module itself has issues; skip

    # -- Public API ----------------------------------------------------------

    def list_tools(self) -> List[Dict]:
        """Return metadata for every discovered adapter.

        Returns:
            List of dicts with name, version, available, capabilities.
        """
        tools = []
        for name, adapter in self._adapters.items():
            tools.append(adapter.info())

        # Always include garak importer (it's not an adapter but a utility)
        try:
            from oubliette_dungeon.tools.garak_importer import GarakImporter
            tools.append({
                "name": "garak",
                "version": "importer",
                "available": True,
                "capabilities": {
                    "name": "garak",
                    "version": "importer",
                    "multi_turn": False,
                    "converters": False,
                    "vulnerability_scan": False,
                    "probe_import": True,
                },
            })
        except Exception:
            pass

        return tools

    def get_tool(self, name: str) -> Optional[RedTeamToolAdapter]:
        """Get a specific adapter by name.

        Args:
            name: Adapter name (e.g. "pyrit", "deepteam").

        Returns:
            The adapter instance, or None if not found.
        """
        return self._adapters.get(name)

    def run_with_tool(
        self,
        tool_name: str,
        scenarios: List[AttackScenario],
        target_url: str,
        **kwargs,
    ) -> List[TestResult]:
        """Run a batch of scenarios through a specific tool.

        Args:
            tool_name: Name of the tool adapter.
            scenarios: AttackScenarios to execute.
            target_url: Target endpoint URL.
            **kwargs: Passed through to the adapter.

        Returns:
            List of TestResult objects.

        Raises:
            ValueError: If tool not found.
            RuntimeError: If tool is not available (deps missing).
        """
        adapter = self._adapters.get(tool_name)
        if adapter is None:
            raise ValueError(f"Unknown tool: {tool_name}")
        if not adapter.is_available():
            raise RuntimeError(
                f"Tool '{tool_name}' dependencies are not installed. "
                f"Install with: pip install oubliette-dungeon[{tool_name}]"
            )

        results = adapter.run_campaign(scenarios, target_url, **kwargs)
        self._persist(results, tool_name)
        return results

    def run_all_tools(
        self,
        scenarios: List[AttackScenario],
        target_url: str,
    ) -> Dict[str, List[TestResult]]:
        """Run the same scenarios through every available tool.

        Only tools whose ``is_available()`` returns True are used.

        Args:
            scenarios: AttackScenarios to execute.
            target_url: Target endpoint URL.

        Returns:
            Dict mapping tool name -> list of TestResult.
        """
        all_results: Dict[str, List[TestResult]] = {}

        for name, adapter in self._adapters.items():
            if not adapter.is_available():
                continue
            try:
                results = adapter.run_campaign(scenarios, target_url)
                self._persist(results, name)
                all_results[name] = results
            except Exception as exc:
                all_results[name] = [TestResult(
                    scenario_id=f"{name.upper()}-ERR",
                    scenario_name=f"{name} campaign error",
                    category="prompt_injection",
                    difficulty="medium",
                    result="error",
                    confidence=1.0,
                    response=f"ERROR: {exc}",
                    execution_time_ms=0,
                    bypass_indicators_found=[],
                    safe_indicators_found=[],
                    notes=f"tool={name} campaign error: {exc}",
                )]

        return all_results

    def compare_results(
        self,
        all_results: Dict[str, List[TestResult]],
    ) -> Dict:
        """Generate a comparison summary across tools.

        Args:
            all_results: Output from run_all_tools().

        Returns:
            Dict with per-tool stats and overall comparison.
        """
        comparison: Dict = {"tools": {}, "summary": {}}

        for tool_name, results in all_results.items():
            total = len(results)
            detected = sum(1 for r in results if r.result == "detected")
            bypassed = sum(1 for r in results if r.result == "bypass")
            errors = sum(1 for r in results if r.result == "error")
            avg_conf = (
                sum(r.confidence for r in results) / total
                if total > 0
                else 0
            )
            avg_time = (
                sum(r.execution_time_ms for r in results) / total
                if total > 0
                else 0
            )

            comparison["tools"][tool_name] = {
                "total": total,
                "detected": detected,
                "bypassed": bypassed,
                "errors": errors,
                "detection_rate": (detected / total * 100) if total else 0,
                "bypass_rate": (bypassed / total * 100) if total else 0,
                "avg_confidence": round(avg_conf, 3),
                "avg_execution_time_ms": round(avg_time, 1),
            }

        # Summary: which tool has the best detection rate?
        if comparison["tools"]:
            best = max(
                comparison["tools"].items(),
                key=lambda x: x[1]["detection_rate"],
            )
            comparison["summary"]["best_detection_tool"] = best[0]
            comparison["summary"]["best_detection_rate"] = best[1]["detection_rate"]
            comparison["summary"]["tool_count"] = len(comparison["tools"])

        return comparison

    # -- Internal helpers ----------------------------------------------------

    def _persist(self, results: List[TestResult], tool_name: str) -> None:
        """Save results to the database if one is configured."""
        if self._results_db is None:
            return

        session_id = f"{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        for r in results:
            try:
                self._results_db.save_result(r, session_id)
            except Exception:
                pass  # Best-effort persistence
