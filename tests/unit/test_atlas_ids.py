"""Validate every MITRE ATLAS ID Dungeon emits against the vendored ATLAS release.

``src/oubliette_dungeon/data/atlas_techniques.json`` is a small extract
(IDs and names only) of the official ATLAS data release named by
``oubliette_dungeon.core.atlas.ATLAS_VERSION``. When bumping ATLAS, regenerate
it from the release YAML and fix mappings until this module passes.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from importlib import resources
from pathlib import Path

import pytest
import yaml

from oubliette_dungeon.core import atlas
from oubliette_dungeon.core.osef import MITRE_ATLAS_TECHNIQUES

REPO_ROOT = Path(__file__).resolve().parents[2]
PKG_DIR = REPO_ROOT / "src" / "oubliette_dungeon"
SCENARIO_FILES = sorted((PKG_DIR / "scenarios").glob("*.yaml"))
ATLAS_ID_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
ANY_ATLAS_ID_RE = re.compile(r"AML\.T\d{4}(?:\.\d{3})?")
# Bare technique codes without the AML. prefix (the old, invalid/mismatched
# T0030/T0061/... style), plus ATT&CK T1059 that was used as an ATLAS mapping.
BARE_TECHNIQUE_RE = re.compile(r"(?<![\w.])T[01]\d{3}(?:\.\d{3})?\b")


def _catalog() -> dict[str, str]:
    return atlas.load_atlas_catalog()


def _scenarios() -> list[dict]:
    out: list[dict] = []
    for path in SCENARIO_FILES:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        out.extend(data if isinstance(data, list) else data.get("scenarios", []))
    return out


def test_vendored_catalog_metadata() -> None:
    raw = resources.files("oubliette_dungeon").joinpath("data/atlas_techniques.json")
    data = json.loads(raw.read_text(encoding="utf-8"))
    assert data["atlas_version"] == atlas.ATLAS_VERSION
    assert data["source"].startswith("https://github.com/mitre-atlas/atlas-data/releases/")
    assert atlas.ATLAS_VERSION in data["source"]
    assert len(data["techniques"]) > 100
    assert all(ATLAS_ID_RE.match(t) for t in data["techniques"])
    for bogus in ("AML.T0030", "AML.T0120", "AML.T0122"):
        assert bogus not in data["techniques"]


def test_scenario_mitre_mappings_are_valid_atlas_ids() -> None:
    catalog = _catalog()
    problems = []
    for sc in _scenarios():
        for tid in sc.get("mitre_mapping") or []:
            if not ATLAS_ID_RE.match(str(tid)) or tid not in catalog:
                problems.append(f"{sc['id']}: {tid}")
    assert not problems, "invalid ATLAS IDs: " + ", ".join(problems)


def test_scenario_yaml_has_no_bare_or_unknown_ids() -> None:
    """Covers free-text fields too (e.g. ATK-049 test_coverage, references)."""
    catalog = _catalog()
    problems = []
    for path in SCENARIO_FILES:
        text = path.read_text(encoding="utf-8")
        problems += [f"{path.name}: bare {m}" for m in BARE_TECHNIQUE_RE.findall(text)]
        problems += [
            f"{path.name}: unknown {t}" for t in ANY_ATLAS_ID_RE.findall(text) if t not in catalog
        ]
    assert not problems, "\n".join(problems)


def test_category_map_matches_scenario_mappings() -> None:
    union: dict[str, set[str]] = defaultdict(set)
    for sc in _scenarios():
        union[sc["category"]].update(sc.get("mitre_mapping") or [])
    for category, ids in union.items():
        assert set(atlas.CATEGORY_TO_ATLAS.get(category, [])) == ids, category


@pytest.mark.parametrize("category", sorted(atlas.CATEGORY_TO_ATLAS))
def test_category_ids_are_valid(category: str) -> None:
    for tid in atlas.atlas_for_category(category):
        assert tid in _catalog(), f"{category}: {tid}"


def test_osef_technique_names_match_atlas() -> None:
    catalog = _catalog()
    for tid, name in MITRE_ATLAS_TECHNIQUES.items():
        assert tid in catalog
        parent, _, sub = tid.rpartition(".")
        expected = f"{catalog[parent]}: {catalog[tid]}" if sub.isdigit() else catalog[tid]
        assert name == expected


def test_atlas_technique_name() -> None:
    assert atlas.atlas_technique_name("AML.T0051.000") == "LLM Prompt Injection: Direct"
    assert atlas.atlas_technique_name("AML.T0054") == "LLM Jailbreak"
    assert atlas.atlas_technique_name("T0030") == "T0030"


def _text_files() -> list[Path]:
    files = sorted(PKG_DIR.rglob("*.py")) + sorted(PKG_DIR.rglob("*.yaml"))
    contrib = REPO_ROOT / "contrib"
    if contrib.is_dir():
        for pattern in ("*.py", "*.yaml", "*.md"):
            files += sorted(contrib.rglob(pattern))
    return files


def test_no_bare_or_unknown_atlas_ids_in_source_or_contrib() -> None:
    catalog = _catalog()
    problems = []
    for path in _text_files():
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(REPO_ROOT)
        problems += [f"{rel}: bare {m}" for m in BARE_TECHNIQUE_RE.findall(text)]
        problems += [
            f"{rel}: unknown {t}" for t in ANY_ATLAS_ID_RE.findall(text) if t not in catalog
        ]
    assert not problems, "\n".join(problems)
