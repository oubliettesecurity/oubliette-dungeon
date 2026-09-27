"""The full scenario suite is Dungeon Pro, enforced fail-closed.

``--suite full`` / ``suite="full"`` (72 scenarios: the default 57 plus the 15
bundled Crescendo scenarios), and ``crescendo.yaml`` loaded by path, need the
``full_scenario_library`` entitlement from a verified, Dungeon-scoped license:
an ``enterprise`` key, or a ``pro`` key granting the feature, whose signed
``products`` include ``"dungeon"``. Without it the request is refused with an
error naming the entitlement (CLI: non-zero exit; Python: LicenseRequiredError,
a PermissionError). It never quietly runs the 57-scenario default instead.

The explicit dev/test opt-in (OUBLIETTE_INSECURE_DEV_FEATURE_GATE=true plus a
non-empty OUBLIETTE_LICENSE_KEY) keeps working.
"""

import logging
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

pytest.importorskip("cryptography")

from oubliette_dungeon.cli.main import cli
from oubliette_dungeon.core import RedTeamOrchestrator, ScenarioLoader
from oubliette_dungeon.core.loader import (
    BUNDLED_FILE_ENTITLEMENTS,
    SUITE_ENTITLEMENTS,
    check_scenario_access,
)
from oubliette_dungeon.license import (
    PRO_FEATURES,
    LicenseManager,
    LicenseRequiredError,
    require_feature,
)

FEATURE = "full_scenario_library"
GATE = "DUNGEON_ALLOW_CUSTOM_SCENARIOS"
DEV_OPT_IN = "OUBLIETTE_INSECURE_DEV_FEATURE_GATE"
SCENARIOS_DIR = Path(__file__).resolve().parents[2] / "src" / "oubliette_dungeon" / "scenarios"
CRESCENDO = str(SCENARIOS_DIR / "crescendo.yaml")


@pytest.fixture
def no_network_run(monkeypatch):
    seen: dict[str, int] = {}

    def fake_run_all(self):
        seen["count"] = len(self.loader.get_all_scenarios())
        return []

    monkeypatch.setattr(RedTeamOrchestrator, "run_all_scenarios", fake_run_all)
    monkeypatch.setattr(RedTeamOrchestrator, "print_summary", lambda self, results: None)
    return seen


@pytest.fixture
def licensed(monkeypatch, trust_test_key, sign_dungeon_license):
    """Install a signed key built from ``overrides`` as OUBLIETTE_LICENSE_KEY."""

    def _install(**overrides):
        monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", sign_dungeon_license(**overrides))

    return _install


def _assert_refused(exc_info):
    err = exc_info.value
    assert isinstance(err, PermissionError)
    assert err.feature == FEATURE
    assert FEATURE in str(err)
    assert "Dungeon Pro" in str(err)


# ------------------------------------------------------------- wiring


def test_full_suite_uses_the_existing_feature_name():
    assert FEATURE in PRO_FEATURES
    assert SUITE_ENTITLEMENTS == {"full": FEATURE}
    assert BUNDLED_FILE_ENTITLEMENTS == {"crescendo.yaml": FEATURE}


def test_default_suite_needs_no_license():
    assert len(ScenarioLoader().get_all_scenarios()) == 57
    assert len(ScenarioLoader(suite="default").get_all_scenarios()) == 57


# ------------------------------------------------ refused without Pro: Python


def test_loader_full_without_license_raises(capsys):
    with pytest.raises(LicenseRequiredError) as exc_info:
        ScenarioLoader(suite="full")
    _assert_refused(exc_info)
    assert exc_info.value.tier == "free"
    assert "Loaded" not in capsys.readouterr().out  # nothing was loaded


def test_orchestrator_full_without_license_raises():
    with pytest.raises(LicenseRequiredError) as exc_info:
        RedTeamOrchestrator(target_url="http://localhost:9/none", suite="full")
    _assert_refused(exc_info)


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"features": ["scheduler"]}, id="pro-without-feature"),
        pytest.param({"features": []}, id="pro-no-features"),
        pytest.param({"tier": "free"}, id="free-tier-listing-feature"),
        pytest.param({"products": ["shield"]}, id="shield-key"),
        pytest.param({"products": ["trap"], "tier": "enterprise"}, id="trap-enterprise"),
        pytest.param(
            {"products": ["shield", "trap"], "tier": "enterprise"}, id="bundle-no-dungeon"
        ),
        pytest.param(
            {"products": ["shield", "dungeon"], "features": [f"shield:{FEATURE}"]},
            id="feature-namespaced-to-shield",
        ),
        pytest.param({"expires": "2020-01-01"}, id="expired"),
        pytest.param({"expires": ""}, id="no-expiry"),
        pytest.param({"kid": "retired"}, id="unknown-kid"),
        pytest.param({"v": 1}, id="wrong-schema"),
    ],
)
def test_full_refused_for_keys_without_dungeon_entitlement(licensed, overrides):
    licensed(**overrides)
    with pytest.raises(LicenseRequiredError) as exc_info:
        ScenarioLoader(suite="full")
    _assert_refused(exc_info)


def test_full_refused_for_key_not_signed_by_a_trusted_key(monkeypatch, sign_dungeon_license):
    # Validly shaped Dungeon Pro key, but the production keyring doesn't trust it.
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", sign_dungeon_license())
    with pytest.raises(LicenseRequiredError):
        ScenarioLoader(suite="full")


def test_full_refused_for_garbage_key(monkeypatch, trust_test_key):
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", "not-a-license")
    with pytest.raises(LicenseRequiredError):
        ScenarioLoader(suite="full")


# ------------------------------------------------- allowed with Dungeon Pro


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({}, id="pro-with-feature"),
        pytest.param({"tier": "enterprise", "features": []}, id="enterprise"),
        pytest.param({"features": [f"dungeon:{FEATURE}"]}, id="namespaced-to-dungeon"),
        pytest.param(
            {"products": ["shield", "dungeon", "trap"], "tier": "enterprise", "features": []},
            id="bundle-including-dungeon",
        ),
    ],
)
def test_full_loads_72_with_dungeon_entitlement(licensed, overrides):
    licensed(**overrides)
    loader = ScenarioLoader(suite="full")
    assert len(loader.get_all_scenarios()) == 72
    orch = RedTeamOrchestrator(target_url="http://localhost:9/none", suite="full")
    assert len(orch.loader.get_all_scenarios()) == 72


def test_explicit_license_manager_is_honoured(license_keypair, sign_dungeon_license, monkeypatch):
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", sign_dungeon_license())
    mgr = LicenseManager(keyring={"test-2026": license_keypair[1]})
    assert len(ScenarioLoader(suite="full", license_manager=mgr).get_all_scenarios()) == 72
    orch = RedTeamOrchestrator(
        target_url="http://localhost:9/none", suite="full", license_manager=mgr
    )
    assert len(orch.loader.get_all_scenarios()) == 72


# ----------------------------------------------------------------- CLI


@pytest.mark.parametrize("command", ["run", "stats", "replay", "compare", "nist-rmf"])
def test_cli_full_without_license_exits_nonzero(command, no_network_run, tmp_path):
    db_dir = tmp_path / "db"
    args = {
        "run": ["run", "--suite", "full", "--db-dir", str(db_dir)],
        "stats": ["stats", "--suite", "full"],
        "replay": ["replay", str(tmp_path), "--suite", "full"],
        "compare": ["compare", "--models", "a,b", "--suite", "full", "--db-dir", str(db_dir)],
        "nist-rmf": ["nist-rmf", "--suite", "full", "--db-dir", str(db_dir)],
    }[command]
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 1, result.output
    assert FEATURE in result.output
    assert "Dungeon Pro" in result.output
    assert "Total Scenarios" not in result.output
    assert "count" not in no_network_run  # nothing ran, not even the default 57
    assert not db_dir.exists()  # refused before any side effects


def test_cli_full_with_license_runs_72(licensed, no_network_run, tmp_path):
    licensed()
    result = CliRunner().invoke(cli, ["run", "--suite", "full", "--db-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert no_network_run["count"] == 72
    result = CliRunner().invoke(cli, ["stats", "--suite", "full"])
    assert result.exit_code == 0, result.output
    assert "Total Scenarios: 72" in result.output


def test_cli_default_run_needs_no_license(no_network_run, tmp_path):
    result = CliRunner().invoke(cli, ["run", "--db-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert no_network_run["count"] == 57


# ------------------------------------------------------ dev opt-in kept


def test_dev_opt_in_unlocks_full(monkeypatch, caplog):
    monkeypatch.setenv(DEV_OPT_IN, "true")
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", "dev-anything")
    with caplog.at_level(logging.WARNING):
        assert len(ScenarioLoader(suite="full").get_all_scenarios()) == 72
    assert "Do NOT use in production" in caplog.text


def test_dev_opt_in_via_cli(monkeypatch, no_network_run, tmp_path):
    monkeypatch.setenv(DEV_OPT_IN, "1")
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", "dev-anything")
    result = CliRunner().invoke(cli, ["run", "--suite", "full", "--db-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert no_network_run["count"] == 72


def test_dev_opt_in_still_needs_a_key(monkeypatch):
    monkeypatch.setenv(DEV_OPT_IN, "true")
    with pytest.raises(LicenseRequiredError):
        ScenarioLoader(suite="full")


@pytest.mark.parametrize("value", ["", "0", "false", "no"])
def test_dev_opt_in_off_values_refuse(monkeypatch, value):
    monkeypatch.setenv(DEV_OPT_IN, value)
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", "dev-anything")
    with pytest.raises(LicenseRequiredError):
        ScenarioLoader(suite="full")


def test_require_feature_reports_how_access_was_granted(monkeypatch, licensed):
    licensed()
    assert require_feature(FEATURE, action="x") == "license"
    monkeypatch.setenv("OUBLIETTE_LICENSE_KEY", "dev-anything")
    monkeypatch.setenv(DEV_OPT_IN, "true")
    assert require_feature(FEATURE, action="x") == "insecure-dev-opt-in"


def test_require_feature_rejects_non_pro_feature_names():
    with pytest.raises(ValueError):
        require_feature("not_a_feature", action="x")


# ---------------------- crescendo.yaml through DUNGEON_ALLOW_CUSTOM_SCENARIOS


class TestCrescendoFilePathNeedsEntitlement:
    """The custom-file route to the bundled Crescendo file is gated too."""

    def test_gate_open_without_license_refused(self, monkeypatch):
        monkeypatch.setenv(GATE, "true")
        with pytest.raises(LicenseRequiredError) as exc_info:
            ScenarioLoader(CRESCENDO)
        _assert_refused(exc_info)

    def test_gate_closed_still_reports_the_gate_first(self, monkeypatch):
        monkeypatch.delenv(GATE, raising=False)
        with pytest.raises(PermissionError, match=GATE):
            ScenarioLoader(CRESCENDO)

    def test_gate_open_with_license_loads_15(self, monkeypatch, licensed):
        monkeypatch.setenv(GATE, "true")
        licensed()
        assert len(ScenarioLoader(CRESCENDO).get_all_scenarios()) == 15

    def test_identical_copy_elsewhere_refused(self, monkeypatch, tmp_path):
        monkeypatch.setenv(GATE, "true")
        copy = tmp_path / "renamed.yaml"
        shutil.copyfile(CRESCENDO, copy)
        with pytest.raises(LicenseRequiredError):
            ScenarioLoader(str(copy))

    def test_relative_and_dotted_paths_refused(self, monkeypatch):
        monkeypatch.setenv(GATE, "true")
        dotted = str(SCENARIOS_DIR / ".." / "scenarios" / "crescendo.yaml")
        with pytest.raises(LicenseRequiredError):
            ScenarioLoader(dotted)

    def test_custom_files_still_load_without_license(self, monkeypatch, mock_yaml_file):
        monkeypatch.setenv(GATE, "true")
        assert len(ScenarioLoader(mock_yaml_file).get_all_scenarios()) == 2

    def test_bundled_default_file_needs_no_license(self, monkeypatch):
        monkeypatch.delenv(GATE, raising=False)
        default = str(SCENARIOS_DIR / "default.yaml")
        assert len(ScenarioLoader(default).get_all_scenarios()) == 57

    def test_cli_scenarios_crescendo_without_license_exits_nonzero(self, monkeypatch):
        monkeypatch.setenv(GATE, "true")
        result = CliRunner().invoke(cli, ["stats", "--scenarios", CRESCENDO])
        assert result.exit_code == 1, result.output
        assert FEATURE in result.output

    def test_check_scenario_access_matches_loader(self, monkeypatch):
        monkeypatch.setenv(GATE, "true")
        with pytest.raises(LicenseRequiredError):
            check_scenario_access(CRESCENDO)
        with pytest.raises(LicenseRequiredError):
            check_scenario_access(suite="full")
        check_scenario_access(suite="default")


def test_error_explains_missing_cryptography(monkeypatch):
    import importlib.util

    real_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *a, **k: None if name == "cryptography" else real_find_spec(name, *a, **k),
    )
    with pytest.raises(LicenseRequiredError, match=r"oubliette-dungeon\[licensing\]"):
        ScenarioLoader(suite="full")
