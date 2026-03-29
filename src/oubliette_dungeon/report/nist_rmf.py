"""
NIST AI RMF Compliance Report Generator
=========================================
Maps Oubliette Dungeon attack scenarios and test results to the
NIST AI Risk Management Framework (AI RMF 1.0) functions and
sub-categories.  Generates markdown compliance reports suitable
for federal documentation packages.

Reference: https://www.nist.gov/artificial-intelligence/ai-risk-management-framework

Functions:
    GOVERN  - Organizational policies & accountability
    MAP     - Context & risk framing
    MEASURE - Analysis & monitoring of AI risks
    MANAGE  - Prioritization & treatment of AI risks
"""

from datetime import datetime
from typing import Dict, List, Optional, Tuple

from oubliette_dungeon.core.models import AttackScenario, AttackTestResult


# ---------------------------------------------------------------------------
# NIST AI RMF sub-category definitions & scenario mapping
# ---------------------------------------------------------------------------

RMF_TAXONOMY: Dict[str, Dict[str, Dict]] = {
    "GOVERN": {
        "GV-1.1": {
            "title": "Legal and regulatory requirements involving AI are understood",
            "categories": ["compliance_testing"],
            "keywords": ["compliance", "federal", "owasp", "nist"],
        },
        "GV-1.2": {
            "title": "Trustworthy AI characteristics are integrated into policies",
            "categories": ["compliance_testing"],
            "keywords": ["baseline", "policy"],
        },
        "GV-1.3": {
            "title": "Processes for AI risk management are established",
            "categories": ["compliance_testing", "resource_abuse"],
            "keywords": ["risk", "management", "process"],
        },
        "GV-3.1": {
            "title": "AI risk management processes include assessment of potential harms",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking",
                           "information_extraction", "social_engineering"],
            "keywords": ["harm", "assessment", "risk"],
        },
        "GV-4.1": {
            "title": "Organizational practices are in place for AI oversight",
            "categories": ["compliance_testing"],
            "keywords": ["oversight", "governance", "monitoring"],
        },
    },
    "MAP": {
        "MP-2.1": {
            "title": "Intended use and potential misuse of AI are enumerated",
            "categories": ["jailbreak", "jailbreaking", "prompt_injection",
                           "social_engineering"],
            "keywords": ["misuse", "jailbreak", "injection"],
        },
        "MP-2.2": {
            "title": "Potential risks from third-party components are assessed",
            "categories": ["tool_exploitation", "context_manipulation"],
            "keywords": ["tool", "plugin", "mcp", "third-party"],
        },
        "MP-3.1": {
            "title": "AI system risks across demographic groups are assessed",
            "categories": ["compliance_testing", "social_engineering"],
            "keywords": ["bias", "fairness", "demographic"],
        },
        "MP-4.1": {
            "title": "Risks in context of intended deployment are assessed",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking",
                           "information_extraction", "model_exploitation"],
            "keywords": ["deployment", "production", "operational"],
        },
        "MP-5.1": {
            "title": "Likelihood and magnitude of each risk are assessed",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking",
                           "information_extraction", "social_engineering",
                           "context_manipulation", "model_exploitation",
                           "resource_abuse", "tool_exploitation"],
            "keywords": ["success_rate", "severity", "critical"],
        },
    },
    "MEASURE": {
        "MS-1.1": {
            "title": "Approaches for measurement of AI risks are developed",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking"],
            "keywords": ["detection", "measurement", "metric"],
        },
        "MS-2.1": {
            "title": "AI system is evaluated for trustworthy characteristics",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking",
                           "information_extraction", "social_engineering",
                           "context_manipulation"],
            "keywords": ["evaluate", "test", "assessment"],
        },
        "MS-2.2": {
            "title": "AI system performance is evaluated against benchmarks",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking",
                           "information_extraction", "model_exploitation"],
            "keywords": ["benchmark", "performance", "comparison"],
        },
        "MS-2.5": {
            "title": "AI system is evaluated for adversarial robustness",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking",
                           "information_extraction", "social_engineering",
                           "context_manipulation", "model_exploitation",
                           "resource_abuse", "tool_exploitation"],
            "keywords": ["adversarial", "robustness", "attack", "red team"],
        },
        "MS-2.6": {
            "title": "AI system security and resilience are evaluated",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking",
                           "information_extraction", "tool_exploitation",
                           "resource_abuse"],
            "keywords": ["security", "resilience", "breach"],
        },
        "MS-2.7": {
            "title": "AI system is evaluated for privacy risks",
            "categories": ["information_extraction"],
            "keywords": ["privacy", "data", "extraction", "credential"],
        },
        "MS-2.8": {
            "title": "AI system is evaluated for safety risks",
            "categories": ["jailbreak", "jailbreaking", "social_engineering",
                           "compliance_testing"],
            "keywords": ["safety", "harmful", "unsafe"],
        },
        "MS-3.1": {
            "title": "AI risk tracking approaches are applied",
            "categories": ["compliance_testing"],
            "keywords": ["tracking", "monitoring", "session"],
        },
        "MS-4.1": {
            "title": "Measurement results are documented and shared",
            "categories": ["compliance_testing"],
            "keywords": ["report", "document", "export"],
        },
    },
    "MANAGE": {
        "MG-1.1": {
            "title": "AI risks based on assessments are prioritized and responded to",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking",
                           "information_extraction"],
            "keywords": ["prioritize", "critical", "severity"],
        },
        "MG-2.1": {
            "title": "Response to identified AI risks is planned",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking",
                           "information_extraction", "social_engineering"],
            "keywords": ["response", "mitigation", "plan"],
        },
        "MG-2.2": {
            "title": "Mechanisms to mitigate AI risks are in place",
            "categories": ["prompt_injection", "jailbreak", "jailbreaking",
                           "information_extraction", "social_engineering",
                           "context_manipulation", "model_exploitation",
                           "resource_abuse", "tool_exploitation"],
            "keywords": ["mitigation", "filter", "block", "detection"],
        },
        "MG-3.1": {
            "title": "AI risks are monitored on a regular basis",
            "categories": ["compliance_testing", "resource_abuse"],
            "keywords": ["monitor", "continuous", "regular"],
        },
        "MG-3.2": {
            "title": "Pre-determined change protocols are followed when risks arise",
            "categories": ["compliance_testing"],
            "keywords": ["incident", "protocol", "change"],
        },
        "MG-4.1": {
            "title": "Post-deployment AI system monitoring is in place",
            "categories": ["resource_abuse", "compliance_testing"],
            "keywords": ["post-deployment", "monitoring", "operational"],
        },
    },
}


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------

def _normalize_category(cat: str) -> str:
    """Normalize a scenario category string for matching."""
    return cat.lower().replace("-", "_").replace(" ", "_")


def map_scenario_to_subcategories(scenario: AttackScenario) -> List[str]:
    """Return the list of RMF sub-category IDs that a scenario covers.

    Matching is based on scenario category, tags (if available), and
    keyword heuristics applied to the scenario name and description.
    """
    cat = _normalize_category(scenario.category)
    text = f"{scenario.name} {scenario.description}".lower()
    tags = set()
    if hasattr(scenario, "metadata") and scenario.metadata:
        for t in scenario.metadata.get("tags", []):
            tags.add(t.lower())

    matched: List[str] = []
    for func_id, subcats in RMF_TAXONOMY.items():
        for sub_id, sub_def in subcats.items():
            # Category match
            if cat in [_normalize_category(c) for c in sub_def["categories"]]:
                matched.append(sub_id)
                continue
            # Keyword match
            for kw in sub_def["keywords"]:
                if kw.lower() in text or kw.lower() in tags:
                    matched.append(sub_id)
                    break

    return sorted(set(matched))


def _sub_to_function(sub_id: str) -> str:
    """Extract function name from sub-category ID (e.g. 'GV-1.1' -> 'GOVERN')."""
    prefix = sub_id.split("-")[0]
    prefix_map = {"GV": "GOVERN", "MP": "MAP", "MS": "MEASURE", "MG": "MANAGE"}
    return prefix_map.get(prefix, prefix)


# ---------------------------------------------------------------------------
# NISTRMFReport
# ---------------------------------------------------------------------------

class NISTRMFReport:
    """Generate NIST AI RMF compliance reports from Dungeon test results.

    Usage::

        from oubliette_dungeon.report.nist_rmf import NISTRMFReport

        report = NISTRMFReport()
        md = report.generate(scenarios=scenarios, results=results)
    """

    # Risk-level thresholds for coverage percentages
    _RISK_THRESHOLDS = {
        "LOW": 75,
        "MEDIUM": 50,
        "HIGH": 25,
    }

    def __init__(self):
        self.taxonomy = RMF_TAXONOMY

    # -- Public API ---------------------------------------------------------

    def generate(
        self,
        scenarios: List[AttackScenario],
        results: Optional[List[dict]] = None,
        session_id: Optional[str] = None,
        organization: str = "Oubliette Security",
    ) -> str:
        """Generate a full NIST AI RMF compliance report in markdown.

        Args:
            scenarios: Loaded attack scenarios.
            results: Optional list of result dicts (from a test session).
            session_id: Optional session identifier for the report header.
            organization: Organization name for the header.

        Returns:
            Markdown string.
        """
        mapping = self._build_mapping(scenarios)
        func_stats = self._compute_function_stats(mapping, results)
        overall = self._overall_coverage(func_stats)

        lines: List[str] = []

        # --- Header ---
        lines.append("# NIST AI RMF Compliance Report")
        lines.append("")
        lines.append(f"**Organization:** {organization}")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if session_id:
            lines.append(f"**Session ID:** {session_id}")
        lines.append(f"**Framework:** NIST AI Risk Management Framework (AI RMF 1.0)")
        lines.append(f"**Total Scenarios Evaluated:** {len(scenarios)}")
        if results:
            lines.append(f"**Total Test Results:** {len(results)}")
        lines.append(f"**Overall Coverage:** {overall:.1f}%")
        lines.append("")

        # --- Executive Summary ---
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(
            "This report maps adversarial red team testing results to the NIST AI "
            "Risk Management Framework (AI RMF 1.0). Each RMF function and sub-category "
            "is assessed for coverage by the tested attack scenarios."
        )
        lines.append("")

        # --- Summary Table ---
        lines.append("## Coverage Summary")
        lines.append("")
        lines.append("| Function | Sub-categories Tested | Total Sub-categories | Coverage | Risk Level |")
        lines.append("|----------|----------------------|---------------------|----------|------------|")

        for func_name in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
            stats = func_stats[func_name]
            risk = self._risk_level(stats["coverage_pct"])
            lines.append(
                f"| {func_name} | {stats['tested']} | {stats['total']} "
                f"| {stats['coverage_pct']:.1f}% | {risk} |"
            )

        lines.append("")
        lines.append(f"**Overall Coverage: {overall:.1f}%** | "
                      f"**Overall Risk Level: {self._risk_level(overall)}**")
        lines.append("")

        # --- Per-function detail ---
        for func_name in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
            lines.extend(self._function_section(func_name, mapping, results))

        # --- Results Analysis (if results provided) ---
        if results:
            lines.extend(self._results_analysis(results, scenarios))

        # --- Recommendations ---
        lines.extend(self._recommendations(func_stats, results))

        # --- Footer ---
        lines.append("---")
        lines.append(
            "*Report generated by Oubliette Dungeon - AI Red Team Engine. "
            "This assessment supports federal AI compliance documentation per "
            "NIST AI RMF 1.0 and Executive Order 14110.*"
        )
        lines.append("")

        return "\n".join(lines)

    # -- Internal helpers ---------------------------------------------------

    def _build_mapping(
        self, scenarios: List[AttackScenario]
    ) -> Dict[str, Dict[str, List[AttackScenario]]]:
        """Build func -> sub_id -> [scenarios] mapping."""
        mapping: Dict[str, Dict[str, List[AttackScenario]]] = {}
        for func_name, subcats in self.taxonomy.items():
            mapping[func_name] = {}
            for sub_id in subcats:
                mapping[func_name][sub_id] = []

        for sc in scenarios:
            matched_subs = map_scenario_to_subcategories(sc)
            for sub_id in matched_subs:
                func = _sub_to_function(sub_id)
                if func in mapping and sub_id in mapping[func]:
                    mapping[func][sub_id].append(sc)

        return mapping

    def _compute_function_stats(
        self,
        mapping: Dict[str, Dict[str, List[AttackScenario]]],
        results: Optional[List[dict]],
    ) -> Dict[str, Dict]:
        """Compute per-function coverage statistics."""
        stats: Dict[str, Dict] = {}
        for func_name, subcats in mapping.items():
            total = len(subcats)
            tested = sum(1 for scs in subcats.values() if len(scs) > 0)
            coverage = (tested / total * 100) if total > 0 else 0.0
            stats[func_name] = {
                "total": total,
                "tested": tested,
                "coverage_pct": coverage,
            }
        return stats

    def _overall_coverage(self, func_stats: Dict[str, Dict]) -> float:
        """Compute overall coverage across all functions."""
        total_sub = sum(s["total"] for s in func_stats.values())
        tested_sub = sum(s["tested"] for s in func_stats.values())
        return (tested_sub / total_sub * 100) if total_sub > 0 else 0.0

    def _risk_level(self, coverage_pct: float) -> str:
        """Map coverage percentage to a risk level string."""
        if coverage_pct >= self._RISK_THRESHOLDS["LOW"]:
            return "LOW"
        if coverage_pct >= self._RISK_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        if coverage_pct >= self._RISK_THRESHOLDS["HIGH"]:
            return "HIGH"
        return "CRITICAL"

    def _function_section(
        self,
        func_name: str,
        mapping: Dict[str, Dict[str, List[AttackScenario]]],
        results: Optional[List[dict]],
    ) -> List[str]:
        """Generate markdown section for one RMF function."""
        lines: List[str] = []
        lines.append(f"## {func_name}")
        lines.append("")

        result_lookup: Dict[str, dict] = {}
        if results:
            for r in results:
                sid = r.get("scenario_id", "")
                if sid:
                    result_lookup[sid] = r

        subcats = mapping.get(func_name, {})
        for sub_id, scenarios_list in subcats.items():
            sub_def = self.taxonomy[func_name][sub_id]
            status = "TESTED" if scenarios_list else "NOT TESTED"

            lines.append(f"### {sub_id}: {sub_def['title']}")
            lines.append("")
            lines.append(f"**Status:** {status}")
            lines.append("")

            if scenarios_list:
                lines.append("| Scenario ID | Name | Category | Difficulty | Result |")
                lines.append("|-------------|------|----------|------------|--------|")
                for sc in scenarios_list:
                    result_str = "N/A"
                    if sc.id in result_lookup:
                        result_str = result_lookup[sc.id].get("result", "N/A")
                    lines.append(
                        f"| {sc.id} | {sc.name[:40]} | {sc.category} "
                        f"| {sc.difficulty} | {result_str} |"
                    )
                lines.append("")
            else:
                lines.append("*No scenarios currently mapped to this sub-category. "
                             "Consider expanding test coverage.*")
                lines.append("")

        return lines

    def _results_analysis(
        self, results: List[dict], scenarios: List[AttackScenario]
    ) -> List[str]:
        """Generate results analysis section."""
        lines: List[str] = []
        lines.append("## Test Results Analysis")
        lines.append("")

        total = len(results)
        detected = sum(1 for r in results if r.get("result") == "detected")
        bypassed = sum(1 for r in results if r.get("result") == "bypass")
        partial = sum(1 for r in results if r.get("result") == "partial")
        errors = sum(1 for r in results if r.get("result") in ("error", "timeout"))

        det_rate = (detected / total * 100) if total > 0 else 0.0
        bypass_rate = (bypassed / total * 100) if total > 0 else 0.0

        lines.append(f"- **Total Tests:** {total}")
        lines.append(f"- **Detected (blocked):** {detected} ({det_rate:.1f}%)")
        lines.append(f"- **Bypassed:** {bypassed} ({bypass_rate:.1f}%)")
        lines.append(f"- **Partial:** {partial}")
        lines.append(f"- **Errors/Timeouts:** {errors}")
        lines.append("")

        # Highlight bypassed scenarios as high-risk findings
        if bypassed > 0:
            lines.append("### Critical Findings -- Bypassed Attacks")
            lines.append("")
            lines.append("| Scenario ID | Name | Category | RMF Sub-categories |")
            lines.append("|-------------|------|----------|--------------------|")
            sc_lookup = {s.id: s for s in scenarios}
            for r in results:
                if r.get("result") == "bypass":
                    sid = r.get("scenario_id", "")
                    sc = sc_lookup.get(sid)
                    if sc:
                        subs = map_scenario_to_subcategories(sc)
                        lines.append(
                            f"| {sid} | {sc.name[:40]} | {sc.category} "
                            f"| {', '.join(subs[:5])} |"
                        )
            lines.append("")

        return lines

    def _recommendations(
        self, func_stats: Dict[str, Dict], results: Optional[List[dict]]
    ) -> List[str]:
        """Generate recommendations section."""
        lines: List[str] = []
        lines.append("## Recommendations")
        lines.append("")

        rec_num = 0

        # Low-coverage functions
        for func_name in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
            stats = func_stats[func_name]
            if stats["coverage_pct"] < 50:
                rec_num += 1
                gap = stats["total"] - stats["tested"]
                lines.append(
                    f"{rec_num}. **{func_name}** has {stats['coverage_pct']:.0f}% coverage "
                    f"({gap} untested sub-categories). Expand test scenarios to cover "
                    f"missing sub-categories."
                )

        if results:
            bypassed = sum(1 for r in results if r.get("result") == "bypass")
            total = len(results)
            if bypassed > 0:
                bypass_rate = bypassed / total * 100
                rec_num += 1
                lines.append(
                    f"{rec_num}. **Bypass rate is {bypass_rate:.1f}%** -- review bypassed "
                    f"scenarios and add targeted detection rules."
                )

        rec_num += 1
        lines.append(
            f"{rec_num}. Schedule periodic re-assessment (quarterly recommended) to "
            f"track compliance drift."
        )

        rec_num += 1
        lines.append(
            f"{rec_num}. Cross-reference with OWASP LLM Top 10 and MITRE ATLAS for "
            f"comprehensive risk coverage."
        )

        lines.append("")
        return lines
