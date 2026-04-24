"""
Scenario loader for Oubliette Dungeon.

Loads attack scenarios from YAML files with filtering capabilities.
"""
from typing import Any


import hashlib
import logging
import os
from pathlib import Path

import yaml

from oubliette_dungeon.core.models import AttackScenario

log = logging.getLogger(__name__)


class ScenarioLoader:
    """
    Loads attack scenarios from YAML files.
    Supports filtering by category, difficulty, and compliance requirements.
    """

    def __init__(self, scenario_file: str | None = None):
        if scenario_file is None:
            from oubliette_dungeon.core import _default_scenarios_path

            scenario_file = _default_scenarios_path()
        self.scenario_file = scenario_file
        self.scenarios: list[AttackScenario] = []
        # MED-7 fix (2026-04-22 audit): scenario YAML is trusted input but
        # was previously loaded from any path via --scenarios / the
        # ``/api/dungeon/tools/garak/import`` merge flow. A malicious
        # scenarios file turns Dungeon into a weaponised request generator
        # aimed at any target_url the user provides (SSRF probes, credential
        # stuffing, prompt-injection exfil). Gate non-bundled YAML behind an
        # explicit opt-in env var and log the SHA-256 hash on load so an
        # operator post-incident can tell which scenario file was used.
        self._enforce_custom_scenario_gate(scenario_file)
        self.load_scenarios()

    @staticmethod
    def _enforce_custom_scenario_gate(scenario_file: str) -> None:
        """Refuse to load non-bundled scenario YAML unless the operator
        has explicitly set ``DUNGEON_ALLOW_CUSTOM_SCENARIOS=true``.

        The bundled scenario file ships inside the package; external files
        are attacker-controllable surface area. The gate is fail-closed by
        default; test suites that need a fixture path set the env var in
        a fixture / conftest.
        """
        from oubliette_dungeon.core import _default_scenarios_path

        try:
            bundled = Path(_default_scenarios_path()).resolve()
            resolved = Path(scenario_file).resolve()
        except (OSError, ValueError):
            # Can't resolve: treat as external / untrusted.
            resolved = Path(scenario_file)
            bundled = Path("<unresolved>")

        if resolved == bundled:
            return

        if os.getenv("DUNGEON_ALLOW_CUSTOM_SCENARIOS", "").lower() != "true":
            raise PermissionError(
                f"Refusing to load custom scenarios from {scenario_file!r}. "
                "Set DUNGEON_ALLOW_CUSTOM_SCENARIOS=true to opt in to external "
                "YAML (scenarios are trusted input and flow as live HTTP "
                "payloads to target_url)."
            )

        try:
            digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
            log.warning(
                "Loading custom (non-bundled) scenarios from %s (sha256=%s). "
                "These payloads will be sent live to target_url.",
                resolved,
                digest,
            )
        except OSError:
            # Let load_scenarios() produce the real error below.
            pass

    def load_scenarios(self) -> None:
        """Load scenarios from YAML file"""
        self.scenarios = []

        try:
            with open(self.scenario_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                return

            if isinstance(data, list):
                scenarios_list = data
            elif isinstance(data, dict) and "scenarios" in data:
                scenarios_list = data["scenarios"]
            else:
                raise ValueError(f"Invalid scenario file format: {self.scenario_file}")

            for scenario_dict in scenarios_list:
                multi_turn_prompts = scenario_dict.get("multi_turn_prompts")
                if not multi_turn_prompts and "multi_turn_sequence" in scenario_dict:
                    multi_turn_prompts = [
                        turn["prompt"] for turn in scenario_dict["multi_turn_sequence"]
                    ]

                scenario = AttackScenario(
                    id=scenario_dict["id"],
                    name=scenario_dict["name"],
                    category=scenario_dict["category"],
                    difficulty=scenario_dict["difficulty"],
                    description=scenario_dict.get("description", ""),
                    owasp_mapping=scenario_dict.get("owasp_mapping", []),
                    mitre_mapping=scenario_dict.get("mitre_mapping", []),
                    prompt=scenario_dict.get("prompt", ""),
                    multi_turn_prompts=multi_turn_prompts,
                    expected_behavior=scenario_dict.get("expected_behavior", ""),
                    success_criteria=scenario_dict.get("success_criteria", ""),
                    bypass_indicators=scenario_dict.get("bypass_indicators", []),
                    safe_indicators=scenario_dict.get("safe_indicators", []),
                    metadata=scenario_dict.get("metadata", {}),
                )
                self.scenarios.append(scenario)

            print(f"Loaded {len(self.scenarios)} attack scenarios from {self.scenario_file}")

        except Exception as e:
            print(f"Error loading scenarios: {e}")
            raise

    def get_all_scenarios(self) -> list[AttackScenario]:
        return self.scenarios

    def list_all(self) -> list[AttackScenario]:
        return self.get_all_scenarios()

    def get_by_category(self, category: str) -> list[AttackScenario]:
        return [s for s in self.scenarios if s.category == category]

    def get_by_difficulty(self, difficulty: str) -> list[AttackScenario]:
        return [s for s in self.scenarios if s.difficulty.lower() == difficulty.lower()]

    def get_by_id(self, scenario_id: str) -> AttackScenario | None:
        for scenario in self.scenarios:
            if scenario.id == scenario_id:
                return scenario
        return None

    def get_owasp_scenarios(self, owasp_id: str) -> list[AttackScenario]:
        return [s for s in self.scenarios if owasp_id in s.owasp_mapping]

    def get_mitre_scenarios(self, technique_id: str) -> list[AttackScenario]:
        return [s for s in self.scenarios if technique_id in s.mitre_mapping]

    def get_statistics(self) -> dict[str, Any]:
        stats = {
            "total": len(self.scenarios),
            "by_category": {},
            "by_difficulty": {},
            "multi_turn_count": sum(1 for s in self.scenarios if s.multi_turn_prompts),
        }
        for scenario in self.scenarios:
            stats["by_category"][scenario.category] = (
                stats["by_category"].get(scenario.category, 0) + 1
            )
            stats["by_difficulty"][scenario.difficulty] = (
                stats["by_difficulty"].get(scenario.difficulty, 0) + 1
            )
        return stats
