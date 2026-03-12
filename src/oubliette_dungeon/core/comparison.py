"""
Multi-model comparison report for Oubliette Dungeon.

Runs the same attack suite against multiple LLM models and produces a
side-by-side resilience comparison with JSON and HTML output.

Usage::

    from oubliette_dungeon.core.comparison import ModelComparison

    comp = ModelComparison()
    comp.add_results("openai/gpt-4o", gpt4o_results)
    comp.add_results("anthropic/claude-3.5", claude_results)
    comp.add_results("ollama/llama3", llama_results)

    comp.save_json("comparison.json")
    comp.save_html("comparison.html")

CLI::

    oubliette-dungeon compare --models llama3,mistral,phi3 --osef comparison.json
"""

import html
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from oubliette_dungeon.core.models import AttackResult, AttackTestResult
from oubliette_dungeon.core.metrics import pass_at_k


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ModelScore:
    """Aggregate resilience score for a single model."""

    model_id: str
    total_scenarios: int
    detected: int
    bypassed: int
    partial: int
    errors: int
    detection_rate: float
    bypass_rate: float
    avg_confidence: float
    avg_execution_time_ms: float
    pass_at_1: float
    pass_at_5: float
    by_category: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    by_difficulty: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_results(cls, model_id: str, results: List[AttackTestResult]) -> "ModelScore":
        total = len(results)
        if total == 0:
            return cls(
                model_id=model_id, total_scenarios=0, detected=0, bypassed=0,
                partial=0, errors=0, detection_rate=0, bypass_rate=0,
                avg_confidence=0, avg_execution_time_ms=0, pass_at_1=0, pass_at_5=0,
            )

        detected = sum(1 for r in results if r.result == AttackResult.SUCCESS_DETECTED.value)
        bypassed = sum(1 for r in results if r.result == AttackResult.SUCCESS_BYPASS.value)
        partial = sum(1 for r in results if r.result == AttackResult.PARTIAL.value)
        errors = total - detected - bypassed - partial

        # Category breakdown
        cats: Dict[str, List[AttackTestResult]] = {}
        for r in results:
            cats.setdefault(r.category, []).append(r)

        by_cat = {}
        for cat, cr in sorted(cats.items()):
            ct = len(cr)
            cd = sum(1 for r in cr if r.result == AttackResult.SUCCESS_DETECTED.value)
            cb = sum(1 for r in cr if r.result == AttackResult.SUCCESS_BYPASS.value)
            by_cat[cat] = {
                "total": ct,
                "detected": cd,
                "bypassed": cb,
                "detection_rate": round(cd / ct * 100, 1) if ct else 0,
                "bypass_rate": round(cb / ct * 100, 1) if ct else 0,
            }

        # Difficulty breakdown
        diffs: Dict[str, List[AttackTestResult]] = {}
        for r in results:
            diffs.setdefault(r.difficulty, []).append(r)

        by_diff = {}
        for diff, dr in sorted(diffs.items()):
            dt = len(dr)
            dd = sum(1 for r in dr if r.result == AttackResult.SUCCESS_DETECTED.value)
            db = sum(1 for r in dr if r.result == AttackResult.SUCCESS_BYPASS.value)
            by_diff[diff] = {
                "total": dt,
                "detected": dd,
                "bypassed": db,
                "detection_rate": round(dd / dt * 100, 1) if dt else 0,
            }

        return cls(
            model_id=model_id,
            total_scenarios=total,
            detected=detected,
            bypassed=bypassed,
            partial=partial,
            errors=errors,
            detection_rate=round(detected / total * 100, 1),
            bypass_rate=round(bypassed / total * 100, 1),
            avg_confidence=round(sum(r.confidence for r in results) / total, 3),
            avg_execution_time_ms=round(sum(r.execution_time_ms for r in results) / total, 1),
            pass_at_1=round(pass_at_k(results, 1), 4),
            pass_at_5=round(pass_at_k(results, 5), 4),
            by_category=by_cat,
            by_difficulty=by_diff,
        )


@dataclass
class ScenarioComparison:
    """Per-scenario comparison across models."""

    scenario_id: str
    scenario_name: str
    category: str
    difficulty: str
    model_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# ModelComparison
# ---------------------------------------------------------------------------


class ModelComparison:
    """Build and export multi-model comparison reports."""

    def __init__(self) -> None:
        self._results: Dict[str, List[AttackTestResult]] = {}
        self._scores: Dict[str, ModelScore] = {}

    def add_results(self, model_id: str, results: List[AttackTestResult]) -> None:
        """Add results for a model."""
        self._results[model_id] = results
        self._scores[model_id] = ModelScore.from_results(model_id, results)

    @property
    def model_ids(self) -> List[str]:
        return list(self._results.keys())

    @property
    def scores(self) -> Dict[str, ModelScore]:
        return dict(self._scores)

    def ranking(self) -> List[ModelScore]:
        """Return models ranked by detection rate (highest first)."""
        return sorted(self._scores.values(), key=lambda s: s.detection_rate, reverse=True)

    def scenario_matrix(self) -> List[ScenarioComparison]:
        """Build per-scenario comparison across all models."""
        # Collect all unique scenarios across all models
        scenario_map: Dict[str, ScenarioComparison] = {}

        for model_id, results in self._results.items():
            for r in results:
                if r.scenario_id not in scenario_map:
                    scenario_map[r.scenario_id] = ScenarioComparison(
                        scenario_id=r.scenario_id,
                        scenario_name=r.scenario_name,
                        category=r.category,
                        difficulty=r.difficulty,
                    )
                scenario_map[r.scenario_id].model_results[model_id] = {
                    "result": r.result,
                    "confidence": r.confidence,
                    "execution_time_ms": r.execution_time_ms,
                    "bypass_indicators": r.bypass_indicators_found,
                }

        return sorted(scenario_map.values(), key=lambda s: s.scenario_id)

    def to_dict(self) -> Dict[str, Any]:
        """Export comparison as a plain dict."""
        matrix = self.scenario_matrix()
        ranked = self.ranking()

        return {
            "schema_version": "1.0",
            "tool": "oubliette-dungeon",
            "report_type": "multi_model_comparison",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_count": len(self._results),
            "ranking": [asdict(s) for s in ranked],
            "scenario_matrix": [asdict(s) for s in matrix],
            "category_comparison": self._category_comparison(),
        }

    def _category_comparison(self) -> Dict[str, Dict[str, Any]]:
        """Category-level comparison across models."""
        cats: Dict[str, Dict[str, Any]] = {}
        for model_id, score in self._scores.items():
            for cat, cat_data in score.by_category.items():
                if cat not in cats:
                    cats[cat] = {}
                cats[cat][model_id] = cat_data
        return cats

    def save_json(self, path: str) -> None:
        """Save comparison report as JSON."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    def save_html(self, path: str) -> None:
        """Save comparison report as an HTML page."""
        ranked = self.ranking()
        matrix = self.scenario_matrix()
        models = self.model_ids

        rows_ranking = ""
        for i, s in enumerate(ranked, 1):
            color = "#e8f5e9" if i == 1 else "#fff"
            rows_ranking += (
                f"<tr style='background:{color}'>"
                f"<td>{i}</td>"
                f"<td><b>{_esc(s.model_id)}</b></td>"
                f"<td>{s.detection_rate}%</td>"
                f"<td>{s.bypass_rate}%</td>"
                f"<td>{s.avg_confidence:.2f}</td>"
                f"<td>{s.avg_execution_time_ms:.0f}ms</td>"
                f"<td>{s.pass_at_1:.3f}</td>"
                f"</tr>\n"
            )

        rows_matrix = ""
        for sc in matrix:
            cells = (
                f"<td>{_esc(sc.scenario_id)}</td>"
                f"<td>{_esc(sc.scenario_name)}</td>"
                f"<td>{_esc(sc.category)}</td>"
                f"<td>{_esc(sc.difficulty)}</td>"
            )
            for m in models:
                mr = sc.model_results.get(m)
                if mr is None:
                    cells += "<td>-</td>"
                else:
                    result = mr["result"]
                    if result == "detected":
                        badge = '<span style="color:green">DETECTED</span>'
                    elif result == "bypass":
                        badge = '<span style="color:red;font-weight:bold">BYPASS</span>'
                    elif result == "partial":
                        badge = '<span style="color:orange">PARTIAL</span>'
                    else:
                        badge = f'<span style="color:gray">{_esc(result)}</span>'
                    cells += f"<td>{badge} ({mr['confidence']:.2f})</td>"
            rows_matrix += f"<tr>{cells}</tr>\n"

        model_headers = "".join(f"<th>{_esc(m)}</th>" for m in models)

        page = _HTML_TEMPLATE.format(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            model_count=len(models),
            scenario_count=len(matrix),
            rows_ranking=rows_ranking,
            model_headers=model_headers,
            rows_matrix=rows_matrix,
        )

        with open(path, "w", encoding="utf-8") as f:
            f.write(page)

    def print_summary(self) -> None:
        """Print a console summary."""
        ranked = self.ranking()
        print("\n" + "=" * 70)
        print("MULTI-MODEL COMPARISON REPORT")
        print("=" * 70)
        print(f"Models evaluated: {len(ranked)}")
        print()

        hdr = f"  {'Rank':<6}{'Model':<30}{'Det%':<8}{'Byp%':<8}{'Conf':<8}{'ms':<10}"
        print(hdr)
        print("  " + "-" * 64)

        for i, s in enumerate(ranked, 1):
            print(
                f"  {i:<6}{s.model_id:<30}"
                f"{s.detection_rate:<8.1f}{s.bypass_rate:<8.1f}"
                f"{s.avg_confidence:<8.2f}{s.avg_execution_time_ms:<10.0f}"
            )

        print("=" * 70)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    return html.escape(str(s))


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Oubliette Dungeon - Multi-Model Comparison</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 1400px; margin: 0 auto; padding: 20px; background: #fafafa; }}
  h1 {{ color: #1a1a2e; }}
  h2 {{ color: #16213e; margin-top: 30px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
  th {{ background: #1a1a2e; color: white; padding: 10px 12px; text-align: left; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #ddd; }}
  tr:hover {{ background: #f0f0f0; }}
  .meta {{ color: #666; font-size: 0.9em; margin-bottom: 20px; }}
  .footer {{ margin-top: 40px; color: #999; font-size: 0.85em; border-top: 1px solid #ddd; padding-top: 10px; }}
</style>
</head>
<body>
<h1>Oubliette Dungeon - Multi-Model Adversarial Comparison</h1>
<p class="meta">Generated: {timestamp} | Models: {model_count} | Scenarios: {scenario_count}</p>

<h2>Model Ranking (by Detection Rate)</h2>
<table>
<tr><th>#</th><th>Model</th><th>Detection %</th><th>Bypass %</th><th>Avg Confidence</th><th>Avg Latency</th><th>pass@1</th></tr>
{rows_ranking}
</table>

<h2>Scenario-Level Results</h2>
<table>
<tr><th>ID</th><th>Scenario</th><th>Category</th><th>Difficulty</th>{model_headers}</tr>
{rows_matrix}
</table>

<div class="footer">
  Generated by <a href="https://oubliettesecurity.com">Oubliette Dungeon</a> v1.0.1 |
  OWASP LLM Top 10 + MITRE ATLAS aligned | Apache 2.0
</div>
</body>
</html>"""
