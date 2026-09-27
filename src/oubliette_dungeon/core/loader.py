"""
Scenario loader for Oubliette Dungeon.

Loads attack scenarios from YAML files with filtering capabilities.
"""

import hashlib
import logging
import os
from pathlib import Path
from typing import Any

import yaml

from oubliette_dungeon.core.models import AttackScenario
from oubliette_dungeon.license import LicenseManager, require_feature

log = logging.getLogger(__name__)

# Named suites of scenario files that ship inside the package. A suite only
# ever names bundled files, so selecting one never loads anything from outside
# the package and does not touch the DUNGEON_ALLOW_CUSTOM_SCENARIOS gate.
SCENARIO_SUITES: dict[str, tuple[str, ...]] = {
    "default": ("default.yaml",),  # 57 scenarios
    "full": ("default.yaml", "crescendo.yaml"),  # 57 + 15 Crescendo multi-turn = 72
}
DEFAULT_SUITE = "default"

# Dungeon Pro content. The full suite, and the bundled Crescendo file however it
# is reached, need the ``full_scenario_library`` entitlement from a verified,
# Dungeon-scoped license. Without it the request is refused (never downgraded
# to the 57-scenario default).
FULL_SCENARIO_LIBRARY = "full_scenario_library"
SUITE_ENTITLEMENTS: dict[str, str] = {"full": FULL_SCENARIO_LIBRARY}
SUITE_LABELS: dict[str, str] = {"full": "72 scenarios: the default 57 plus 15 Crescendo"}
BUNDLED_FILE_ENTITLEMENTS: dict[str, str] = {"crescendo.yaml": FULL_SCENARIO_LIBRARY}


def bundled_suite_paths(suite: str) -> list[str]:
    """Return the bundled scenario file paths for a named suite.

    Fails closed: any name other than a key of ``SCENARIO_SUITES`` raises
    ``ValueError`` rather than falling back to a default.
    """
    if not isinstance(suite, str) or suite not in SCENARIO_SUITES:
        valid = ", ".join(sorted(SCENARIO_SUITES))
        raise ValueError(f"Unknown scenario suite {suite!r}. Valid suites: {valid}.")

    from importlib.resources import files

    root = files("oubliette_dungeon") / "scenarios"
    return [str(root / name) for name in SCENARIO_SUITES[suite]]


def _bundled_scenario_path(name: str) -> Path:
    from importlib.resources import files

    return Path(str(files("oubliette_dungeon") / "scenarios" / name))


def file_entitlement(scenario_file: str) -> str | None:
    """Return the entitlement needed to load ``scenario_file`` by path, if any.

    Matches a bundled Pro file (``crescendo.yaml``) by resolved path, and by
    identical content so a byte-for-byte copy elsewhere is gated too. Files
    that cannot be read are left to the loader to report.
    """
    try:
        resolved = Path(scenario_file).resolve()
    except (OSError, ValueError):
        resolved = Path(scenario_file)
    try:
        digest: str | None = hashlib.sha256(resolved.read_bytes()).hexdigest()
    except OSError:
        digest = None
    for name, feature in BUNDLED_FILE_ENTITLEMENTS.items():
        bundled = _bundled_scenario_path(name)
        try:
            if resolved == bundled.resolve():
                return feature
            if digest is not None and digest == hashlib.sha256(bundled.read_bytes()).hexdigest():
                return feature
        except OSError:
            continue
    return None


def check_scenario_access(
    scenario_file: str | None = None,
    suite: str | None = None,
    *,
    license_manager: LicenseManager | None = None,
) -> None:
    """Run every access check for a scenario selection without loading it.

    In order: suite name validation (``ValueError``), the
    ``DUNGEON_ALLOW_CUSTOM_SCENARIOS`` gate for non-bundled files
    (``PermissionError``), then the Dungeon Pro entitlement for Pro content
    (:class:`~oubliette_dungeon.license.LicenseRequiredError`, a
    ``PermissionError``). The CLI calls this before doing any work;
    :class:`ScenarioLoader` calls it before loading.
    """
    if scenario_file is not None and suite is not None:
        raise ValueError(
            "Pass either scenario_file or suite, not both: a suite selects "
            "bundled scenario files only."
        )
    if scenario_file is None:
        name = DEFAULT_SUITE if suite is None else suite
        bundled_suite_paths(name)  # validates the name (fail closed)
        feature = SUITE_ENTITLEMENTS.get(name)
        if feature is not None:
            require_feature(
                feature,
                action=f"The '{name}' scenario suite ({SUITE_LABELS.get(name, name)})",
                license_manager=license_manager,
            )
        return
    ScenarioLoader._enforce_custom_scenario_gate(scenario_file)
    feature = file_entitlement(scenario_file)
    if feature is not None:
        require_feature(
            feature,
            action=f"Loading the bundled Crescendo scenarios from {scenario_file!r}",
            license_manager=license_manager,
        )


class ScenarioLoader:
    """
    Loads attack scenarios from YAML files.
    Supports filtering by category, difficulty, and compliance requirements.

    Pass either ``scenario_file`` (a single YAML file; anything other than the
    bundled default library requires ``DUNGEON_ALLOW_CUSTOM_SCENARIOS=true``)
    or ``suite`` (a named set of bundled files, see ``SCENARIO_SUITES``), not
    both. With neither, the ``default`` suite (57 scenarios) is loaded;
    ``suite="full"`` adds the 15 bundled Crescendo scenarios (72 total).

    ``suite="full"``, and ``crescendo.yaml`` loaded by path, are Dungeon Pro:
    they need the ``full_scenario_library`` entitlement from a verified,
    Dungeon-scoped license (``OUBLIETTE_LICENSE_KEY``, or ``license_manager``).
    Without it the constructor raises
    :class:`~oubliette_dungeon.license.LicenseRequiredError` (a
    ``PermissionError``); it never falls back to the 57-scenario default.
    """

    def __init__(
        self,
        scenario_file: str | None = None,
        suite: str | None = None,
        *,
        license_manager: LicenseManager | None = None,
    ):
        # Fail closed before anything is loaded: suite name, custom-file gate,
        # Pro entitlement (see check_scenario_access).
        check_scenario_access(scenario_file, suite, license_manager=license_manager)
        self.suite: str | None
        if scenario_file is None:
            self.suite = DEFAULT_SUITE if suite is None else suite
            # Validates the name (fail closed) before anything is loaded.
            self.scenario_files = bundled_suite_paths(self.suite)
        else:
            self.suite = None
            self.scenario_files = [scenario_file]
        # First file of the selection; kept for callers that read it.
        self.scenario_file = self.scenario_files[0]
        self.scenarios: list[AttackScenario] = []
        # MED-7 fix (2026-04-22 audit): scenario YAML is trusted input but
        # was previously loaded from any path via --scenarios / the
        # ``/api/dungeon/tools/garak/import`` merge flow. A malicious
        # scenarios file turns Dungeon into a weaponised request generator
        # aimed at any target_url the user provides (SSRF probes, credential
        # stuffing, prompt-injection exfil). Gate non-bundled YAML behind an
        # explicit opt-in env var and log the SHA-256 hash on load so an
        # operator post-incident can tell which scenario file was used.
        # A suite resolves to bundled files only, so it never reaches the gate.
        # (check_scenario_access above has already enforced the gate.)
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
        """Load scenarios from the selected YAML file(s), in order."""
        self.scenarios = []
        for path in self.scenario_files:
            self.scenarios.extend(self._load_file(path))
        sources = ", ".join(self.scenario_files)
        print(f"Loaded {len(self.scenarios)} attack scenarios from {sources}")

    @staticmethod
    def _load_file(scenario_file: str) -> list[AttackScenario]:
        """Parse one scenario YAML file."""
        scenarios: list[AttackScenario] = []

        try:
            with open(scenario_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                return scenarios

            if isinstance(data, list):
                scenarios_list = data
            elif isinstance(data, dict) and "scenarios" in data:
                scenarios_list = data["scenarios"]
            else:
                raise ValueError(f"Invalid scenario file format: {scenario_file}")

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
                scenarios.append(scenario)

        except Exception as e:
            print(f"Error loading scenarios: {e}")
            raise

        return scenarios

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
        # Annotate the inner buckets explicitly so the indexed
        # assignments below survive mypy strict mode (otherwise the
        # outer dict's value-type collapses to ``object`` and the
        # ``stats["by_category"][...] = ...`` mutation fails the index
        # check).
        by_category: dict[str, int] = {}
        by_difficulty: dict[str, int] = {}
        for scenario in self.scenarios:
            by_category[scenario.category] = by_category.get(scenario.category, 0) + 1
            by_difficulty[scenario.difficulty] = by_difficulty.get(scenario.difficulty, 0) + 1
        return {
            "total": len(self.scenarios),
            "by_category": by_category,
            "by_difficulty": by_difficulty,
            "multi_turn_count": sum(1 for s in self.scenarios if s.multi_turn_prompts),
        }
