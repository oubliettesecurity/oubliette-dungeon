"""
Oubliette Structured Evaluation Format (OSEF).

A standardized JSON schema for adversarial evaluation results, mappable to
MITRE ATLAS, OWASP LLM Top 10, NIST AI RMF, and CWE.

Usage::

    from oubliette_dungeon.core.osef import OSEFReport

    report = OSEFReport.from_results(results, model_id="openai/gpt-4o")
    report.save("evaluation_report.json")

    # Validate existing report
    OSEFReport.validate("evaluation_report.json")
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from oubliette_dungeon.core.models import AttackResult, AttackTestResult

# ---------------------------------------------------------------------------
# OSEF Schema version
# ---------------------------------------------------------------------------

OSEF_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Framework mappings
# ---------------------------------------------------------------------------

OWASP_LLM_TOP_10 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain Vulnerabilities",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

MITRE_ATLAS_TECHNIQUES = {
    "T0030": "Prompt Injection (Direct)",
    "T0031": "Prompt Injection (Indirect)",
    "T0043": "LLM Jailbreak",
    "T0049": "System Prompt Theft",
    "T0051": "LLM Output Manipulation",
    "T0059": "Resource Abuse via AI",
    "T0054": "Data Extraction",
}

NIST_AI_RMF_CATEGORIES = {
    "GOVERN": "Organizational governance of AI risks",
    "MAP": "Mapping AI risks in context",
    "MEASURE": "Measuring AI risks quantitatively",
    "MANAGE": "Managing identified AI risks",
}

CATEGORY_TO_OWASP = {
    "prompt_injection": ["LLM01:2025"],
    "jailbreak": ["LLM01:2025", "LLM06:2025"],
    "information_extraction": ["LLM02:2025", "LLM07:2025"],
    "social_engineering": ["LLM01:2025", "LLM06:2025"],
    "context_manipulation": ["LLM01:2025", "LLM05:2025"],
    "model_exploitation": ["LLM06:2025", "LLM10:2025"],
    "resource_abuse": ["LLM10:2025"],
    "tool_exploitation": ["LLM06:2025"],
    "compliance_testing": ["LLM01:2025"],
    "multi_turn_attack": ["LLM01:2025"],
}

CATEGORY_TO_ATLAS = {
    "prompt_injection": ["T0030", "T0031"],
    "jailbreak": ["T0043"],
    "information_extraction": ["T0049", "T0054"],
    "social_engineering": ["T0030"],
    "context_manipulation": ["T0030", "T0051"],
    "model_exploitation": ["T0059"],
    "resource_abuse": ["T0059"],
    "tool_exploitation": ["T0059"],
    "compliance_testing": ["T0043"],
    "multi_turn_attack": ["T0030", "T0043"],
}

SEVERITY_MAP = {
    "bypass": "critical",
    "partial": "medium",
    "detected": "info",
    "error": "unknown",
    "timeout": "unknown",
}

# ---------------------------------------------------------------------------
# OSEF data structures
# ---------------------------------------------------------------------------


@dataclass
class OSEFScenarioResult:
    """A single scenario evaluation result in OSEF format."""

    scenario_id: str
    scenario_name: str
    category: str
    difficulty: str
    result: str
    severity: str
    confidence: float
    execution_time_ms: float
    response_snippet: str
    bypass_indicators_found: list[str]
    safe_indicators_found: list[str]
    framework_mappings: dict[str, list[str]]
    ml_score: float | None = None
    llm_verdict: str | None = None
    notes: str = ""
    timestamp: str = ""

    @classmethod
    def from_test_result(cls, result: AttackTestResult) -> "OSEFScenarioResult":
        owasp = CATEGORY_TO_OWASP.get(result.category, [])
        atlas = CATEGORY_TO_ATLAS.get(result.category, [])

        return cls(
            scenario_id=result.scenario_id,
            scenario_name=result.scenario_name,
            category=result.category,
            difficulty=result.difficulty,
            result=result.result,
            severity=SEVERITY_MAP.get(result.result, "unknown"),
            confidence=result.confidence,
            execution_time_ms=result.execution_time_ms,
            response_snippet=result.response[:300] if result.response else "",
            bypass_indicators_found=result.bypass_indicators_found,
            safe_indicators_found=result.safe_indicators_found,
            framework_mappings={
                "owasp_llm_top_10": owasp,
                "mitre_atlas": atlas,
                "nist_ai_rmf": ["MEASURE"],
            },
            ml_score=result.ml_score,
            llm_verdict=result.llm_verdict,
            notes=result.notes,
            timestamp=result.timestamp or "",
        )


@dataclass
class OSEFCategoryScore:
    """Aggregate score for an attack category."""

    category: str
    total: int
    detected: int
    bypassed: int
    partial: int
    errors: int
    detection_rate: float
    bypass_rate: float
    avg_confidence: float
    owasp_mappings: list[str] = field(default_factory=list)
    mitre_atlas_mappings: list[str] = field(default_factory=list)


@dataclass
class OSEFAggregate:
    """Overall aggregate evaluation metrics."""

    total_scenarios: int
    total_detected: int
    total_bypassed: int
    total_partial: int
    total_errors: int
    overall_detection_rate: float
    overall_bypass_rate: float
    avg_confidence: float
    avg_execution_time_ms: float
    pass_at_1: float
    pass_at_5: float
    pass_at_10: float
    by_category: list[OSEFCategoryScore] = field(default_factory=list)
    by_difficulty: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)


@dataclass
class OSEFReport:
    """Complete OSEF evaluation report."""

    osef_version: str
    tool: str
    tool_version: str
    model_id: str
    timestamp: str
    session_id: str
    evaluation_context: dict[str, Any]
    aggregate: OSEFAggregate
    results: list[OSEFScenarioResult]
    framework_coverage: dict[str, Any]

    @classmethod
    def from_results(
        cls,
        results: list[AttackTestResult],
        model_id: str = "unknown",
        session_id: str = "",
        context: dict[str, Any] | None = None,
    ) -> "OSEFReport":
        """Build an OSEF report from a list of AttackTestResult objects."""
        from oubliette_dungeon.core.metrics import (
            pass_at_k,
        )

        if not session_id:
            session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Convert individual results
        osef_results = [OSEFScenarioResult.from_test_result(r) for r in results]

        # Compute aggregates
        total = len(results)
        detected = sum(1 for r in results if r.result == AttackResult.SUCCESS_DETECTED.value)
        bypassed = sum(1 for r in results if r.result == AttackResult.SUCCESS_BYPASS.value)
        partial = sum(1 for r in results if r.result == AttackResult.PARTIAL.value)
        errors = sum(
            1 for r in results if r.result in (AttackResult.ERROR.value, AttackResult.TIMEOUT.value)
        )

        avg_conf = sum(r.confidence for r in results) / total if total else 0
        avg_time = sum(r.execution_time_ms for r in results) / total if total else 0

        # Category breakdown
        categories: dict[str, list[AttackTestResult]] = {}
        for r in results:
            categories.setdefault(r.category, []).append(r)

        cat_scores = []
        for cat, cat_results in sorted(categories.items()):
            cat_total = len(cat_results)
            cat_detected = sum(
                1 for r in cat_results if r.result == AttackResult.SUCCESS_DETECTED.value
            )
            cat_bypassed = sum(
                1 for r in cat_results if r.result == AttackResult.SUCCESS_BYPASS.value
            )
            cat_partial = sum(1 for r in cat_results if r.result == AttackResult.PARTIAL.value)
            cat_errors = cat_total - cat_detected - cat_bypassed - cat_partial

            cat_scores.append(
                OSEFCategoryScore(
                    category=cat,
                    total=cat_total,
                    detected=cat_detected,
                    bypassed=cat_bypassed,
                    partial=cat_partial,
                    errors=cat_errors,
                    detection_rate=(cat_detected / cat_total * 100) if cat_total else 0,
                    bypass_rate=(cat_bypassed / cat_total * 100) if cat_total else 0,
                    avg_confidence=sum(r.confidence for r in cat_results) / cat_total,
                    owasp_mappings=CATEGORY_TO_OWASP.get(cat, []),
                    mitre_atlas_mappings=CATEGORY_TO_ATLAS.get(cat, []),
                )
            )

        # Difficulty breakdown
        difficulties: dict[str, list[AttackTestResult]] = {}
        for r in results:
            difficulties.setdefault(r.difficulty, []).append(r)
        by_diff = {}
        for diff, diff_results in sorted(difficulties.items()):
            diff_total = len(diff_results)
            by_diff[diff] = {
                "total": diff_total,
                "detection_rate": (
                    sum(1 for r in diff_results if r.result == "detected") / diff_total * 100
                ),
                "bypass_rate": (
                    sum(1 for r in diff_results if r.result == "bypass") / diff_total * 100
                ),
            }

        # Severity breakdown
        by_severity: dict[str, int] = {}
        for r in osef_results:
            by_severity[r.severity] = by_severity.get(r.severity, 0) + 1

        aggregate = OSEFAggregate(
            total_scenarios=total,
            total_detected=detected,
            total_bypassed=bypassed,
            total_partial=partial,
            total_errors=errors,
            overall_detection_rate=(detected / total * 100) if total else 0,
            overall_bypass_rate=(bypassed / total * 100) if total else 0,
            avg_confidence=avg_conf,
            avg_execution_time_ms=avg_time,
            pass_at_1=pass_at_k(results, 1),
            pass_at_5=pass_at_k(results, 5),
            pass_at_10=pass_at_k(results, 10),
            by_category=cat_scores,
            by_difficulty=by_diff,
            by_severity=by_severity,
        )

        # Framework coverage summary
        all_owasp = set()
        all_atlas = set()
        for r in osef_results:
            all_owasp.update(r.framework_mappings.get("owasp_llm_top_10", []))
            all_atlas.update(r.framework_mappings.get("mitre_atlas", []))

        framework_coverage = {
            "owasp_llm_top_10": {
                "covered": sorted(all_owasp),
                "total": len(OWASP_LLM_TOP_10),
                "coverage_pct": len(all_owasp) / len(OWASP_LLM_TOP_10) * 100,
                "descriptions": {k: OWASP_LLM_TOP_10[k] for k in sorted(all_owasp)},
            },
            "mitre_atlas": {
                "covered": sorted(all_atlas),
                "total": len(MITRE_ATLAS_TECHNIQUES),
                "coverage_pct": len(all_atlas) / len(MITRE_ATLAS_TECHNIQUES) * 100,
                "descriptions": {
                    k: MITRE_ATLAS_TECHNIQUES[k]
                    for k in sorted(all_atlas)
                    if k in MITRE_ATLAS_TECHNIQUES
                },
            },
            "nist_ai_rmf": {
                "primary_function": "MEASURE",
                "description": NIST_AI_RMF_CATEGORIES["MEASURE"],
            },
        }

        return cls(
            osef_version=OSEF_VERSION,
            tool="oubliette-dungeon",
            tool_version="1.0.1",
            model_id=model_id,
            timestamp=datetime.now(UTC).isoformat(),
            session_id=session_id,
            evaluation_context=context
            or {
                "evaluation_type": "adversarial_robustness",
                "scorer": "refusal_aware",
                "environment": "unclassified",
            },
            aggregate=aggregate,
            results=osef_results,
            framework_coverage=framework_coverage,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert report to a plain dict suitable for JSON serialization."""
        return _deep_asdict(self)

    def save(self, path: str) -> None:
        """Save report to a JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    @staticmethod
    def load(path: str) -> dict[str, Any]:
        """Load an OSEF report from a JSON file."""
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def validate(path: str) -> list[str]:
        """Validate an OSEF report file. Returns list of validation errors."""
        errors = []
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            return [f"Cannot read file: {e}"]

        required_top = [
            "osef_version",
            "tool",
            "model_id",
            "timestamp",
            "aggregate",
            "results",
            "framework_coverage",
        ]
        for key in required_top:
            if key not in data:
                errors.append(f"Missing required top-level field: {key}")

        if "aggregate" in data:
            agg = data["aggregate"]
            for key in ["total_scenarios", "overall_detection_rate", "overall_bypass_rate"]:
                if key not in agg:
                    errors.append(f"Missing aggregate field: {key}")

        if "results" in data:
            if not isinstance(data["results"], list):
                errors.append("'results' must be a list")
            elif data["results"]:
                r0 = data["results"][0]
                for key in ["scenario_id", "result", "confidence", "framework_mappings"]:
                    if key not in r0:
                        errors.append(f"Result missing required field: {key}")

        return errors


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deep_asdict(obj: Any) -> Any:
    """Recursively convert dataclasses to dicts."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _deep_asdict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_deep_asdict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _deep_asdict(v) for k, v in obj.items()}
    return obj
