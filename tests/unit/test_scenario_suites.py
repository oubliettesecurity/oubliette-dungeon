"""Named scenario suites: ``--suite`` / ``suite=``.

The default stays 57 scenarios. ``full`` adds the 15 bundled Crescendo
multi-turn scenarios (72 total) without enabling custom scenario files:
DUNGEON_ALLOW_CUSTOM_SCENARIOS keeps gating any non-bundled YAML. Unknown
suite names fail closed.

tests/conftest.py sets DUNGEON_ALLOW_CUSTOM_SCENARIOS=true for the whole
suite, so every test here that asserts on the gate deletes it first.
"""

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from oubliette_dungeon.cli.main import cli
from oubliette_dungeon.core import (
    DEFAULT_SUITE,
    SCENARIO_SUITES,
    RedTeamOrchestrator,
    ScenarioLoader,
)
from oubliette_dungeon.core.loader import bundled_suite_paths

GATE = "DUNGEON_ALLOW_CUSTOM_SCENARIOS"
SCENARIOS_DIR = Path(__file__).resolve().parents[2] / "src" / "oubliette_dungeon" / "scenarios"


@pytest.fixture
def gate_closed(monkeypatch):
    monkeypatch.delenv(GATE, raising=False)


@pytest.fixture
def no_network_run(monkeypatch):
    """Record how many scenarios `run` loaded instead of attacking a target."""
    seen: dict[str, int] = {}

    def fake_run_all(self):
        seen["count"] = len(self.loader.get_all_scenarios())
        return []

    monkeypatch.setattr(RedTeamOrchestrator, "run_all_scenarios", fake_run_all)
    monkeypatch.setattr(RedTeamOrchestrator, "print_summary", lambda self, results: None)
    return seen


# ------------------------------------------------------------- default: 57


class TestDefaultStays57:
    def test_default_suite_name(self):
        assert DEFAULT_SUITE == "default"
        assert set(SCENARIO_SUITES) == {"default", "full"}

    def test_loader_default(self, gate_closed):
        loader = ScenarioLoader()
        assert len(loader.get_all_scenarios()) == 57
        assert loader.suite == "default"

    def test_loader_explicit_default_suite(self, gate_closed):
        assert len(ScenarioLoader(suite="default").get_all_scenarios()) == 57

    def test_orchestrator_default(self, gate_closed):
        orch = RedTeamOrchestrator(target_url="http://localhost:9/none")
        assert len(orch.loader.get_all_scenarios()) == 57

    def test_default_has_no_crescendo(self, gate_closed):
        cats = {s.category for s in ScenarioLoader().get_all_scenarios()}
        assert "multi_turn_attack" not in cats

    def test_cli_stats_default(self, gate_closed):
        result = CliRunner().invoke(cli, ["stats"])
        assert result.exit_code == 0, result.output
        assert "Total Scenarios: 57" in result.output

    def test_cli_run_default(self, gate_closed, no_network_run, tmp_path):
        result = CliRunner().invoke(cli, ["run", "--db-dir", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert no_network_run["count"] == 57


# ---------------------------------------------------------------- full: 72


class TestFullSuite72:
    def test_loader_full(self, gate_closed):
        loader = ScenarioLoader(suite="full")
        scenarios = loader.get_all_scenarios()
        assert len(scenarios) == 72
        assert loader.suite == "full"
        assert loader.get_statistics()["by_category"]["multi_turn_attack"] == 15

    def test_full_is_default_plus_crescendo_with_unique_ids(self, gate_closed):
        ids = [s.id for s in ScenarioLoader(suite="full").get_all_scenarios()]
        assert ids == [f"ATK-{n:03d}" for n in range(1, 73)]
        assert len(set(ids)) == 72

    def test_orchestrator_full(self, gate_closed):
        orch = RedTeamOrchestrator(target_url="http://localhost:9/none", suite="full")
        assert len(orch.loader.get_all_scenarios()) == 72

    def test_cli_stats_full(self, gate_closed):
        result = CliRunner().invoke(cli, ["stats", "--suite", "full"])
        assert result.exit_code == 0, result.output
        assert "Total Scenarios: 72" in result.output

    def test_cli_run_full(self, gate_closed, no_network_run, tmp_path):
        result = CliRunner().invoke(cli, ["run", "--suite", "full", "--db-dir", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert no_network_run["count"] == 72


# -------------------------------------- full does not enable custom files


class TestFullDoesNotAllowCustomFiles:
    def test_suites_resolve_to_bundled_files_only(self):
        for name in SCENARIO_SUITES:
            for path in bundled_suite_paths(name):
                assert Path(path).resolve().parent == SCENARIOS_DIR.resolve()

    def test_full_loads_with_gate_closed_and_leaves_it_closed(self, gate_closed):
        ScenarioLoader(suite="full")
        assert GATE not in os.environ

    def test_custom_file_still_refused_after_full(self, gate_closed, mock_yaml_file):
        ScenarioLoader(suite="full")
        with pytest.raises(PermissionError, match=GATE):
            ScenarioLoader(mock_yaml_file)

    def test_scenario_file_and_suite_together_rejected(self, gate_closed, mock_yaml_file):
        with pytest.raises(ValueError, match="not both"):
            ScenarioLoader(mock_yaml_file, suite="full")

    def test_scenario_file_and_suite_rejected_even_with_gate_open(
        self, monkeypatch, mock_yaml_file
    ):
        # A suite never carries a custom file along, whatever the gate says.
        monkeypatch.setenv(GATE, "true")
        with pytest.raises(ValueError, match="not both"):
            ScenarioLoader(mock_yaml_file, suite="full")

    def test_crescendo_path_as_custom_file_still_gated(self, gate_closed):
        # The file-path route keeps its existing meaning: only default.yaml
        # bypasses the gate; the suite is the ungated way to get Crescendo.
        with pytest.raises(PermissionError, match=GATE):
            ScenarioLoader(str(SCENARIOS_DIR / "crescendo.yaml"))

    @pytest.mark.parametrize("command", ["run", "stats"])
    def test_cli_suite_full_with_custom_file_is_usage_error(
        self, gate_closed, no_network_run, mock_yaml_file, tmp_path, command
    ):
        args = [command, "--suite", "full", "--scenarios", mock_yaml_file]
        if command == "run":
            args += ["--db-dir", str(tmp_path)]
        result = CliRunner().invoke(cli, args)
        assert result.exit_code == 2, result.output
        assert "mutually exclusive" in result.output
        assert "count" not in no_network_run

    def test_cli_custom_file_still_needs_gate(self, gate_closed, mock_yaml_file):
        result = CliRunner().invoke(cli, ["stats", "--scenarios", mock_yaml_file])
        assert result.exit_code != 0
        assert isinstance(result.exception, PermissionError)


# ------------------------------------------------ unknown names fail closed


class TestInvalidSuiteFailsClosed:
    @pytest.mark.parametrize("name", ["bogus", "", "FULL", "Full", " full", "crescendo", "all"])
    def test_loader_rejects_unknown_suite(self, name):
        with pytest.raises(ValueError, match="Unknown scenario suite"):
            ScenarioLoader(suite=name)

    def test_error_lists_valid_suites(self):
        with pytest.raises(ValueError, match="Valid suites: default, full"):
            ScenarioLoader(suite="bogus")

    def test_non_string_suite_rejected(self):
        with pytest.raises(ValueError, match="Unknown scenario suite"):
            ScenarioLoader(suite=["full"])  # type: ignore[arg-type]

    def test_orchestrator_rejects_unknown_suite(self):
        with pytest.raises(ValueError, match="Unknown scenario suite"):
            RedTeamOrchestrator(target_url="http://localhost:9/none", suite="bogus")

    @pytest.mark.parametrize("command", ["run", "stats", "replay", "compare", "nist-rmf"])
    def test_cli_rejects_unknown_suite(self, command, no_network_run):
        result = CliRunner().invoke(cli, [command, "--suite", "bogus"])
        assert result.exit_code == 2, result.output
        assert "Invalid value for '--suite'" in result.output
        assert "count" not in no_network_run
