"""The published artifacts must contain only the ``oubliette_dungeon`` package.

``oubliette-dungeon`` is a public PyPI package, but this repo also holds
things that must never ship in it: ``tests/``, ``reports/`` (internal
automation output), ``benchmarks/``, ``scripts/``, ``contrib/``, ``docker/``,
the ``dashboard/`` sources, and any local ``.env``. This is an allowlist
check: anything outside the expected layout fails.

This module deliberately imports nothing from ``oubliette_dungeon`` so the
publish workflow can run it with ``--noconftest`` in a venv that has only
build tooling installed.

The artifact test skips when ``dist/`` is empty so it never blocks a plain
test run. Set ``DUNGEON_REQUIRE_DIST=1`` (the publish and CI build jobs do)
to make a missing build a hard failure instead of a silent skip.
"""

from __future__ import annotations

import os
import re
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "oubliette_dungeon"

# Path fragments that must never appear anywhere in a built artifact.
FORBIDDEN_FRAGMENTS = (
    "/tests/",
    "/reports/",
    "/benchmarks/",
    "/scripts/",
    "/contrib/",
    "/docker/",
    "/dashboard/",
    "/.git/",
    "/.github/",
    "/node_modules/",
)
FORBIDDEN_BASENAMES = re.compile(
    r"(^|/)(\.env(\..*)?|.*\.pem|.*\.key|id_rsa.*|.*\.sqlite3?|.*\.db)$"
)


def _dist_artifacts() -> tuple[list[Path], list[Path]]:
    dist = REPO_ROOT / "dist"
    return sorted(dist.glob("*.whl")), sorted(dist.glob("*.tar.gz"))


def _require_or_skip(artifacts: list[Path], kind: str) -> None:
    if artifacts:
        return
    if os.getenv("DUNGEON_REQUIRE_DIST") == "1":
        pytest.fail(f"DUNGEON_REQUIRE_DIST=1 but no {kind} found in dist/")
    pytest.skip(f"no {kind} in dist/ -- nothing to inspect")


def _generic_offenders(names: list[str]) -> list[str]:
    bad = []
    for n in names:
        probe = "/" + n
        if any(frag in probe for frag in FORBIDDEN_FRAGMENTS) or FORBIDDEN_BASENAMES.search(n):
            bad.append(n)
    return bad


def test_setuptools_config_only_finds_the_package() -> None:
    setuptools = pytest.importorskip("setuptools", reason="setuptools required to resolve packages")
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        find_cfg = tomllib.load(fh)["tool"]["setuptools"]["packages"]["find"]
    where = REPO_ROOT / find_cfg.get("where", ["."])[0]
    shipped = setuptools.find_packages(
        where=str(where),
        include=find_cfg.get("include", ["*"]),
        exclude=find_cfg.get("exclude", []),
    )
    # Discrimination: the resolver must actually return the package, otherwise
    # the allowlist assertion below would pass vacuously.
    assert PACKAGE in shipped, f"package resolution looks broken: {shipped!r}"
    stray = [p for p in shipped if p != PACKAGE and not p.startswith(PACKAGE + ".")]
    assert not stray, f"non-{PACKAGE} packages would ship: {sorted(stray)}"


def test_wheel_contains_only_the_package() -> None:
    wheels, _ = _dist_artifacts()
    _require_or_skip(wheels, "wheel")
    offenders: dict[str, list[str]] = {}
    for whl in wheels:
        with zipfile.ZipFile(whl) as zf:
            names = zf.namelist()
        dist_info = re.compile(rf"^{PACKAGE}-[^/]+\.dist-info/")
        outside = [n for n in names if not (n.startswith(PACKAGE + "/") or dist_info.match(n))]
        bad = sorted(set(outside + _generic_offenders(names)))
        assert any(n.startswith(PACKAGE + "/") for n in names), f"{whl.name} has no package files"
        if bad:
            offenders[whl.name] = bad
    assert not offenders, f"wheel contains files outside {PACKAGE}/: {offenders}"


def test_sdist_contains_only_expected_files() -> None:
    _, sdists = _dist_artifacts()
    _require_or_skip(sdists, "sdist")
    allowed_top = {"LICENSE", "README.md", "pyproject.toml", "setup.cfg", "PKG-INFO"}
    offenders: dict[str, list[str]] = {}
    for sd in sdists:
        with tarfile.open(sd) as tf:
            members = [m.name for m in tf.getmembers() if m.isfile()]
        bad = []
        for name in members:
            _, _, rel = name.partition("/")  # strip "<name>-<version>/"
            ok = (
                rel in allowed_top
                or rel.startswith(f"src/{PACKAGE}/")
                or rel.startswith(f"src/{PACKAGE}.egg-info/")
            )
            if not ok:
                bad.append(name)
        bad = sorted(set(bad + _generic_offenders(members)))
        if bad:
            offenders[sd.name] = bad
    assert not offenders, f"sdist contains unexpected files: {offenders}"
