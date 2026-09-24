"""Guard: package __version__ must match pyproject.toml project.version.

Published wheels advertise the pyproject version; the CLI (``--version``), the
API root, and benchmark/OSEF/HTML report metadata advertise
``oubliette_dungeon.__version__``. Drift between the two (PyPI 1.0.2 shipped
with a runtime ``__version__`` of 1.0.1) is a packaging bug.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from click.testing import CliRunner

from oubliette_dungeon import __version__

REPO_ROOT = Path(__file__).resolve().parents[2]


def _read_pyproject_version() -> str:
    pyproject = REPO_ROOT / "pyproject.toml"
    if not pyproject.is_file():
        pytest.fail(f"pyproject.toml missing at {pyproject}")

    with pyproject.open("rb") as fh:
        data = tomllib.load(fh)

    try:
        version = data["project"]["version"]
    except KeyError:
        pytest.fail("pyproject.toml missing [project].version")

    if not isinstance(version, str) or not version:
        pytest.fail(f"pyproject.toml [project].version is empty or not a string: {version!r}")
    return version


def test_runtime_version_matches_pyproject():
    pyproject_version = _read_pyproject_version()
    assert __version__ == pyproject_version, (
        f"version drift: oubliette_dungeon.__version__={__version__!r} "
        f"!= pyproject.toml project.version={pyproject_version!r}"
    )


def test_cli_version_option_uses_package_version():
    from oubliette_dungeon.cli.main import cli

    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0, result.output
    assert __version__ in result.output
