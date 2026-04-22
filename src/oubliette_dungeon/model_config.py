"""Central LLM model configuration for Oubliette Dungeon.

Purpose
-------
Externalises provider model IDs so they can be refreshed in one place rather
than scattered through `providers/multi_provider.py` and benchmark scripts.
Runtime code should call :func:`get_model` rather than hard-coding model
strings.

Note for benchmark authors
--------------------------
The helper script ``scripts/benchmark_paper.py`` intentionally pins snapshot
model IDs (e.g. ``claude-sonnet-4-5-20250929``) in its function defaults so
that historical benchmark outputs in ``benchmarks/*.json`` remain reproducible.
Do not route those through :func:`get_model` -- benchmarks must cite the exact
model version that produced the recorded numbers.

Update cadence
--------------
Last verified: 2026-04-22.

A scheduled "model-freshness" agent updates the tier maps below by opening a
PR when a provider releases a newer flagship / mid / small model.

Environment variable precedence
-------------------------------
1. Explicit ``model=`` argument passed to a provider client
2. Provider-scoped env var (e.g. ``DUNGEON_ANTHROPIC_MODEL``)
3. Generic env var ``DUNGEON_LLM_MODEL``
4. Tier default from :data:`MODELS`
"""

from __future__ import annotations

import os
from typing import Literal

Tier = Literal["flagship", "default", "small"]
Provider = Literal[
    "anthropic",
    "openai",
    "azure_openai",
    "bedrock_anthropic",
    "google_gemini",
    "google_vertex",
    "google_gemma",
    "ollama_llama",
]


# Last verified: 2026-04-22 -- update via scheduled model-freshness trigger
MODELS: dict[Provider, dict[Tier, str]] = {
    "anthropic": {
        "flagship": "claude-opus-4-7",
        "default": "claude-sonnet-4-6",
        "small": "claude-haiku-4-5-20251001",
    },
    "openai": {
        "flagship": "gpt-5.4",
        "default": "gpt-5.4-mini",
        "small": "gpt-5.4-nano",
    },
    "azure_openai": {
        "flagship": "gpt-5.4",
        "default": "gpt-5.4-mini",
        "small": "gpt-5.4-nano",
    },
    "bedrock_anthropic": {
        "flagship": "anthropic.claude-opus-4-7",
        "default": "anthropic.claude-sonnet-4-6",
        "small": "anthropic.claude-haiku-4-5",
    },
    "google_gemini": {
        "flagship": "gemini-3.1-pro-preview",
        "default": "gemini-3.1-flash",
        "small": "gemini-3.1-flash-lite-preview",
    },
    "google_vertex": {
        "flagship": "gemini-3.1-pro-preview",
        "default": "gemini-3.1-flash",
        "small": "gemini-3.1-flash-lite-preview",
    },
    "google_gemma": {
        "flagship": "gemma4:27b",
        "default": "gemma3:12b",
        "small": "gemma3:1b",
    },
    "ollama_llama": {
        "flagship": "llama4:maverick",
        "default": "llama4",
        "small": "llama3.3",
    },
}


_ENV_OVERRIDE: dict[Provider, str] = {
    "anthropic": "DUNGEON_ANTHROPIC_MODEL",
    "openai": "DUNGEON_OPENAI_MODEL",
    "azure_openai": "DUNGEON_AZURE_MODEL",
    "bedrock_anthropic": "DUNGEON_BEDROCK_MODEL",
    "google_gemini": "DUNGEON_GEMINI_MODEL",
    "google_vertex": "DUNGEON_VERTEX_MODEL",
    "google_gemma": "DUNGEON_GEMMA_MODEL",
    "ollama_llama": "DUNGEON_LLAMA_MODEL",
}


def get_model(provider: Provider, tier: Tier = "default") -> str:
    """Return the configured model ID for ``provider`` at ``tier``."""
    specific = os.getenv(_ENV_OVERRIDE[provider])
    if specific:
        return specific
    generic = os.getenv("DUNGEON_LLM_MODEL")
    if generic:
        return generic
    return MODELS[provider][tier]
