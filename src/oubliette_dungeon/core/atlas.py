"""MITRE ATLAS technique data for Dungeon.

Technique IDs and names come from the MITRE ATLAS data release named by
``ATLAS_VERSION`` (https://github.com/mitre-atlas/atlas-data). The full list of
valid technique and sub-technique IDs for that release is vendored in
``oubliette_dungeon/data/atlas_techniques.json`` (IDs and names only), and
``tests/unit/test_atlas_ids.py`` validates every ATLAS ID Dungeon emits against it.
"""

from __future__ import annotations

import functools
import json
from importlib import resources

ATLAS_VERSION = "2026.06"


@functools.lru_cache(maxsize=1)
def load_atlas_catalog() -> dict[str, str]:
    """Return ``{technique_id: name}`` for every technique in ``ATLAS_VERSION``."""
    raw = resources.files("oubliette_dungeon").joinpath("data/atlas_techniques.json")
    data = json.loads(raw.read_text(encoding="utf-8"))
    techniques: dict[str, str] = data["techniques"]
    return techniques


def atlas_technique_name(technique_id: str) -> str:
    """Full ATLAS name, e.g. ``"LLM Prompt Injection: Direct"`` for ``AML.T0051.000``.

    Returns the ID unchanged if it is not in the vendored catalog.
    """
    catalog = load_atlas_catalog()
    name = catalog.get(technique_id)
    if name is None:
        return technique_id
    parent_id, _, sub = technique_id.rpartition(".")
    if sub.isdigit() and parent_id in catalog:
        return f"{catalog[parent_id]}: {name}"
    return name


# Category-level ATLAS mapping, used where only a scenario's category is known
# (OSEF export and imported garak/promptfoo scenarios). Each entry is the union
# of the per-scenario ``mitre_mapping`` lists of the built-in scenarios in that
# category (scenarios/default.yaml + crescendo.yaml); a unit test keeps the two
# in sync. ``compliance_testing`` scenarios are meta tests and carry no mapping.
CATEGORY_TO_ATLAS: dict[str, list[str]] = {
    "prompt_injection": ["AML.T0051.000", "AML.T0068"],
    "jailbreak": ["AML.T0054"],
    "information_extraction": [
        "AML.T0014",
        "AML.T0056",
        "AML.T0057",
        "AML.T0069",
        "AML.T0083",
        "AML.T0084",
    ],
    "social_engineering": ["AML.T0051.000", "AML.T0057"],
    "context_manipulation": [
        "AML.T0051.001",
        "AML.T0054",
        "AML.T0066",
        "AML.T0068",
        "AML.T0070",
        "AML.T0080.000",
    ],
    "model_exploitation": ["AML.T0015", "AML.T0043", "AML.T0054"],
    "resource_abuse": ["AML.T0029", "AML.T0034.001"],
    "tool_exploitation": ["AML.T0010.005", "AML.T0011.002", "AML.T0051.000", "AML.T0053"],
    "compliance_testing": [],
    "multi_turn_attack": [
        "AML.T0051.000",
        "AML.T0053",
        "AML.T0054",
        "AML.T0068",
        "AML.T0069",
        "AML.T0080.000",
        "AML.T0080.001",
    ],
}


def atlas_for_category(category: str) -> list[str]:
    """ATLAS IDs for a scenario category (empty list if none fits)."""
    return list(CATEGORY_TO_ATLAS.get(category, []))
