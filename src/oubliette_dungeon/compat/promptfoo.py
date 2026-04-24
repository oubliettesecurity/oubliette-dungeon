"""
Promptfoo Compatibility Importer
==================================
Parses Promptfoo YAML configuration files and converts them into
Oubliette Dungeon attack scenarios.

Promptfoo configs specify providers, prompts with variable templates,
and assertion-based tests.  This importer maps each test case to a
Dungeon AttackScenario with:
    - providers  -> target configuration metadata
    - tests      -> individual scenarios (one per test entry)
    - assertions -> bypass indicators + evaluation description

Usage::

    from oubliette_dungeon.compat.promptfoo import PromptfooImporter

    importer = PromptfooImporter()
    scenarios = importer.import_config("promptfoo_config.yaml")
    # or from a dict:
    scenarios = importer.import_dict(config_dict)
"""

from typing import Any

import yaml

from oubliette_dungeon.core.models import AttackScenario

# ---------------------------------------------------------------------------
# Provider mapping
# ---------------------------------------------------------------------------

PROVIDER_MAP: dict[str, dict[str, str]] = {
    "openai": {"provider_type": "openai"},
    "anthropic": {"provider_type": "anthropic"},
    "ollama": {"provider_type": "ollama"},
    "azure": {"provider_type": "azure"},
    "bedrock": {"provider_type": "bedrock"},
    "huggingface": {"provider_type": "huggingface"},
    "google": {"provider_type": "google"},
    "vertex": {"provider_type": "vertex"},
    "cohere": {"provider_type": "cohere"},
    "replicate": {"provider_type": "replicate"},
}


# ---------------------------------------------------------------------------
# Assertion -> Dungeon mapping
# ---------------------------------------------------------------------------


def _assertion_to_bypass_indicators(assertion: dict[str, Any]) -> list[str]:
    """Convert a single Promptfoo assertion to bypass indicator strings."""
    atype = assertion.get("type", "")
    value = assertion.get("value", "")

    if atype == "not-contains" and isinstance(value, str):
        return [value]
    if atype == "not-icontains" and isinstance(value, str):
        return [value.lower()]
    if atype in ("regex", "not-regex") and isinstance(value, str):
        # Store the pattern as-is; evaluation will use regex matching
        return [value]
    if atype == "contains" and isinstance(value, str):
        # contains = safe indicator (inverse); not a bypass indicator
        return []
    return []


def _assertion_to_description(assertion: dict[str, Any]) -> str:
    """Extract human-readable description from an assertion."""
    atype = assertion.get("type", "")
    value = assertion.get("value", "")

    if atype == "llm-rubric":
        return str(value)
    if atype == "not-contains":
        return f"Response must not contain: {value}"
    if atype == "not-icontains":
        return f"Response must not contain (case-insensitive): {value}"
    if atype == "contains":
        return f"Response must contain: {value}"
    if atype == "javascript":
        return "Custom JavaScript assertion"
    if atype == "python":
        return "Custom Python assertion"
    if atype == "similar":
        return f"Response must be similar to: {str(value)[:80]}"
    if atype == "cost":
        return f"Cost must be below: {value}"
    if atype == "latency":
        return f"Latency must be below: {value}ms"
    return f"{atype}: {str(value)[:80]}"


def _infer_category(prompt_text: str, assertions: list[dict[str, Any]]) -> str:
    """Heuristic category assignment from prompt content and assertions."""
    text = prompt_text.lower()

    # Check assertion values too
    for a in assertions:
        v = str(a.get("value", "")).lower()
        text += " " + v

    if any(kw in text for kw in ("inject", "ignore", "override", "system prompt")):
        return "prompt_injection"
    if any(kw in text for kw in ("jailbreak", "dan ", "no restrictions", "bypass safety")):
        return "jailbreaking"
    if any(kw in text for kw in ("password", "credential", "api key", "secret", "extract")):
        return "information_extraction"
    if any(kw in text for kw in ("pretend", "impersonate", "trust", "authority")):
        return "social_engineering"
    if any(kw in text for kw in ("harm", "unsafe", "refuse", "dangerous")):
        return "compliance_testing"
    if any(kw in text for kw in ("hack", "exploit", "attack", "vulnerability")):
        return "model_exploitation"

    return "prompt_injection"


def _infer_difficulty(prompt_text: str, num_assertions: int) -> str:
    """Heuristic difficulty based on prompt length and assertion count."""
    length = len(prompt_text)
    if length > 500 or num_assertions > 4:
        return "advanced"
    if length > 200 or num_assertions > 2:
        return "hard"
    if length > 80 or num_assertions > 1:
        return "medium"
    return "easy"


def _render_template(template: str, variables: dict[str, Any]) -> str:
    """Substitute Promptfoo-style {{variable}} templates."""
    result = template
    for key, value in variables.items():
        result = result.replace("{{" + key + "}}", str(value))
    return result


# ---------------------------------------------------------------------------
# PromptfooImporter
# ---------------------------------------------------------------------------


class PromptfooImporter:
    """Import Promptfoo YAML configs and convert to Dungeon scenarios."""

    def import_file(self, filepath: str) -> list[AttackScenario]:
        """Load a Promptfoo YAML config file and convert to scenarios.

        Args:
            filepath: Path to the YAML config file.

        Returns:
            List of AttackScenario objects.
        """
        with open(filepath, encoding="utf-8") as f:
            config = yaml.safe_load(f)
        return self.import_dict(config or {})

    def import_yaml_string(self, yaml_string: str) -> list[AttackScenario]:
        """Parse a YAML string and convert to scenarios.

        Args:
            yaml_string: YAML content as a string.

        Returns:
            List of AttackScenario objects.
        """
        config = yaml.safe_load(yaml_string) or {}
        return self.import_dict(config)

    def import_dict(self, config: dict[str, Any]) -> list[AttackScenario]:
        """Convert a parsed Promptfoo config dict to Dungeon scenarios.

        Args:
            config: Parsed Promptfoo config dictionary.

        Returns:
            List of AttackScenario objects.
        """
        providers = self._parse_providers(config.get("providers", []))
        prompts = config.get("prompts", [])
        tests = config.get("tests", [])

        if not prompts:
            prompts = ["{{prompt}}"]

        scenarios: list[AttackScenario] = []
        counter = 0

        for test_entry in tests:
            variables = test_entry.get("vars", {})
            assertions = test_entry.get("assert", [])
            test_description = test_entry.get("description", "")

            # Collect bypass indicators and descriptions from all assertions
            bypass_indicators: list[str] = []
            descriptions: list[str] = []
            safe_indicators: list[str] = []

            for assertion in assertions:
                bypass_indicators.extend(_assertion_to_bypass_indicators(assertion))
                desc = _assertion_to_description(assertion)
                if desc:
                    descriptions.append(desc)

                # "contains" type = safe indicator
                if assertion.get("type") == "contains":
                    val = assertion.get("value", "")
                    if val:
                        safe_indicators.append(val)

            # Generate one scenario per prompt template
            for prompt_template in prompts:
                counter += 1
                prompt_text = _render_template(prompt_template, variables)

                category = _infer_category(prompt_text, assertions)
                difficulty = _infer_difficulty(prompt_text, len(assertions))

                # Build description
                full_desc = (
                    test_description
                    or " | ".join(descriptions)
                    or f"Imported from Promptfoo config (test #{counter})"
                )

                scenario = AttackScenario(
                    id=f"PF-{counter:03d}",
                    name=f"Promptfoo Test #{counter}",
                    category=category,
                    difficulty=difficulty,
                    description=full_desc[:500],
                    owasp_mapping=self._owasp_for_category(category),
                    mitre_mapping=["T1059"],
                    prompt=prompt_text,
                    bypass_indicators=list(set(bypass_indicators))
                    or ["here's how", "certainly", "sure"],
                    safe_indicators=list(set(safe_indicators))
                    or ["i cannot", "i can't", "i'm sorry", "inappropriate"],
                    metadata={
                        "source": "promptfoo",
                        "providers": providers,
                        "variables": variables,
                        "assertion_count": len(assertions),
                    },
                )
                scenarios.append(scenario)

        return scenarios

    def _parse_providers(self, providers_raw: list) -> list[dict[str, str]]:
        """Parse Promptfoo provider specifications.

        Providers can be strings like "openai:gpt-4" or dicts.
        """
        parsed: list[dict[str, str]] = []
        for p in providers_raw:
            if isinstance(p, str):
                parts = p.split(":", 1)
                provider_name = parts[0].lower()
                model = parts[1] if len(parts) > 1 else "default"
                info = PROVIDER_MAP.get(provider_name, {"provider_type": provider_name})
                parsed.append({**info, "model": model, "raw": p})
            elif isinstance(p, dict):
                # Dict-style provider spec
                pid = p.get("id", str(p))
                parsed.append({"provider_type": "custom", "model": pid, "raw": str(p)})
        return parsed

    @staticmethod
    def _owasp_for_category(category: str) -> list[str]:
        """Map category to OWASP LLM Top 10 IDs."""
        mapping = {
            "prompt_injection": ["LLM01"],
            "jailbreaking": ["LLM01", "LLM06"],
            "information_extraction": ["LLM06"],
            "social_engineering": ["LLM09"],
            "context_manipulation": ["LLM01"],
            "model_exploitation": ["LLM05"],
            "compliance_testing": ["LLM06", "LLM09"],
            "resource_abuse": ["LLM10"],
            "tool_exploitation": ["LLM06"],
        }
        return mapping.get(category, ["LLM01"])
