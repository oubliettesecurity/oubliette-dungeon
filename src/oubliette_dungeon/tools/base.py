"""
Abstract base class for red team tool adapters.

All third-party red team tool integrations (PyRIT, DeepTeam, Garak, etc.)
must implement RedTeamToolAdapter to ensure a consistent interface for the
ToolManager and API layer.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from oubliette_dungeon.core.models import AttackScenario, TestResult


class RedTeamToolAdapter(ABC):
    """Abstract base class for red team tool integrations."""

    name: str = ""
    version: str = "0.0.0"

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the tool's dependencies are installed and usable.

        Returns:
            True if the tool can be used, False otherwise.
        """

    @abstractmethod
    def run_attack(
        self,
        prompt: str,
        target_url: str,
        **kwargs,
    ) -> TestResult:
        """Run a single attack prompt against the target.

        Args:
            prompt: Attack prompt text.
            target_url: URL of the target endpoint.
            **kwargs: Tool-specific options.

        Returns:
            TestResult populated with tool-specific metadata.
        """

    @abstractmethod
    def run_campaign(
        self,
        scenarios: List[AttackScenario],
        target_url: str,
        **kwargs,
    ) -> List[TestResult]:
        """Run a batch of attack scenarios.

        Args:
            scenarios: List of AttackScenario to execute.
            target_url: URL of the target endpoint.
            **kwargs: Tool-specific options.

        Returns:
            List of TestResult, one per scenario.
        """

    def get_capabilities(self) -> Dict:
        """Return a dictionary describing the tool's capabilities.

        Override in subclasses to advertise features like multi-turn support,
        converter pipelines, built-in vulnerability scanners, etc.
        """
        return {
            "name": self.name,
            "version": self.version,
            "multi_turn": False,
            "converters": False,
            "vulnerability_scan": False,
            "probe_import": False,
        }

    def info(self) -> Dict:
        """Convenience wrapper returning availability + capabilities."""
        return {
            "name": self.name,
            "version": self.version,
            "available": self.is_available(),
            "capabilities": self.get_capabilities(),
        }
