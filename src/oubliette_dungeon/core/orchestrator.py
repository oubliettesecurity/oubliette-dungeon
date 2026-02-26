"""
Red Team Orchestrator for Oubliette Dungeon.

Coordinates scenario loading, execution, evaluation, and reporting.
"""

import json
from dataclasses import asdict
from datetime import datetime
from typing import List, Dict, Optional

from oubliette_dungeon.core.models import (
    AttackResult, AttackTestResult,
)
from oubliette_dungeon.core.loader import ScenarioLoader
from oubliette_dungeon.core.executor import AttackExecutor
from oubliette_dungeon.core.evaluator import ResultEvaluator
from oubliette_dungeon.core.metrics import pass_at_k, avg_turns_to_jailbreak, avg_risk_density


class RedTeamOrchestrator:
    """
    Orchestrates the red team testing workflow.
    Coordinates scenario loading, execution, evaluation, and reporting.
    """

    def __init__(
        self,
        target_url: str,
        scenario_file: Optional[str] = None,
        results_db=None,
        timeout: int = 30
    ):
        self.loader = ScenarioLoader(scenario_file)
        self.executor = AttackExecutor(target_url, timeout)
        self.evaluator = ResultEvaluator()
        self.results_db = results_db
        self.current_session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    def run_single_scenario(self, scenario_id: str) -> AttackTestResult:
        scenario = self.loader.get_by_id(scenario_id)
        if not scenario:
            raise ValueError(f"Scenario not found: {scenario_id}")

        print(f"Executing scenario {scenario_id}: {scenario.name}...")

        response, elapsed_ms, is_multi_turn = self.executor.execute(scenario)
        pipeline_meta = self.executor.get_last_meta()
        result = self.evaluator.evaluate(scenario, response, pipeline_meta=pipeline_meta)
        result.execution_time_ms = elapsed_ms

        if self.results_db:
            self.results_db.save_result(result, self.current_session_id)

        print(f"  Result: {result.result} (confidence: {result.confidence:.2f})")
        print(f"  Execution time: {elapsed_ms:.2f}ms")

        return result

    def run_all_scenarios(self) -> List[AttackTestResult]:
        scenarios = self.loader.get_all_scenarios()
        results = []

        print(f"\nRunning {len(scenarios)} attack scenarios...")
        print(f"Session ID: {self.current_session_id}")
        print("=" * 70)

        for i, scenario in enumerate(scenarios, 1):
            print(f"\n[{i}/{len(scenarios)}] {scenario.id}: {scenario.name}")
            print(f"  Category: {scenario.category}, Difficulty: {scenario.difficulty}")

            try:
                result = self.run_single_scenario(scenario.id)
                results.append(result)
            except Exception as e:
                print(f"  ERROR: {e}")
                error_result = AttackTestResult(
                    scenario_id=scenario.id,
                    scenario_name=scenario.name,
                    category=scenario.category,
                    difficulty=scenario.difficulty,
                    result=AttackResult.ERROR.value,
                    confidence=1.0,
                    response=f"Exception: {str(e)}",
                    execution_time_ms=0,
                    bypass_indicators_found=[],
                    safe_indicators_found=[],
                    notes=f"Exception during execution: {str(e)}"
                )
                results.append(error_result)

                if self.results_db:
                    self.results_db.save_result(error_result, self.current_session_id)

        print("\n" + "=" * 70)
        print(f"Testing complete! {len(results)} scenarios executed.")

        return results

    def run_by_category(self, category: str) -> List[AttackTestResult]:
        scenarios = self.loader.get_by_category(category)
        results = []
        print(f"\nRunning {len(scenarios)} scenarios in category {category}...")
        for scenario in scenarios:
            result = self.run_single_scenario(scenario.id)
            results.append(result)
        return results

    def run_category(self, category: str) -> List[AttackTestResult]:
        return self.run_by_category(category)

    def run_by_difficulty(self, difficulty: str) -> List[AttackTestResult]:
        scenarios = self.loader.get_by_difficulty(difficulty)
        results = []
        print(f"\nRunning {len(scenarios)} {difficulty} scenarios...")
        for scenario in scenarios:
            result = self.run_single_scenario(scenario.id)
            results.append(result)
        return results

    def replay(
        self, results_file: str, scenario_ids: Optional[List[str]] = None
    ) -> List[AttackTestResult]:
        with open(results_file, "r", encoding="utf-8") as f:
            prev_data = json.load(f)

        if isinstance(prev_data, list):
            prev_results = prev_data
        elif isinstance(prev_data, dict):
            prev_results = prev_data.get("results", prev_data.get("suites", []))
            if isinstance(prev_results, dict):
                flat = []
                for suite_results in prev_results.values():
                    if isinstance(suite_results, list):
                        flat.extend(suite_results)
                prev_results = flat
        else:
            prev_results = []

        ids_to_replay = set()
        for r in prev_results:
            sid = r.get("scenario_id", "")
            if sid and (scenario_ids is None or sid in scenario_ids):
                ids_to_replay.add(sid)

        print(f"Replaying {len(ids_to_replay)} scenarios from {results_file}...")
        new_results = []
        for sid in sorted(ids_to_replay):
            try:
                result = self.run_single_scenario(sid)
                new_results.append(result)
            except Exception as e:
                print(f"  Replay {sid} failed: {e}")

        return new_results

    def generate_summary(self, results: List[AttackTestResult]) -> Dict:
        if not results:
            return {'error': 'No results to summarize'}

        summary = {
            'schema_version': '1.0',
            'tool': 'oubliette-dungeon',
            'tool_version': '1.0.0',
            'total_tests': len(results),
            'session_id': self.current_session_id,
            'timestamp': datetime.now().isoformat(),
            'by_result': {},
            'by_category': {},
            'by_difficulty': {},
            'avg_execution_time_ms': 0,
            'detection_rate': 0,
            'bypass_rate': 0,
            'avg_confidence': 0
        }

        total_time = 0
        total_confidence = 0
        detected_count = 0
        bypass_count = 0

        for result in results:
            summary['by_result'][result.result] = \
                summary['by_result'].get(result.result, 0) + 1
            summary['by_category'][result.category] = \
                summary['by_category'].get(result.category, 0) + 1
            summary['by_difficulty'][result.difficulty] = \
                summary['by_difficulty'].get(result.difficulty, 0) + 1

            total_time += result.execution_time_ms
            total_confidence += result.confidence

            if result.result == AttackResult.SUCCESS_DETECTED.value:
                detected_count += 1
            elif result.result == AttackResult.SUCCESS_BYPASS.value:
                bypass_count += 1

        summary['avg_execution_time_ms'] = total_time / len(results)
        summary['avg_confidence'] = total_confidence / len(results)
        summary['detection_rate'] = (detected_count / len(results)) * 100
        summary['bypass_rate'] = (bypass_count / len(results)) * 100

        summary['pass_at_1'] = pass_at_k(results, 1)
        summary['pass_at_5'] = pass_at_k(results, 5)
        summary['pass_at_10'] = pass_at_k(results, 10)
        summary['avg_turns_to_jailbreak'] = avg_turns_to_jailbreak(results)
        summary['avg_risk_density'] = avg_risk_density(results)

        return summary

    def export_benchmark(
        self, results: List[AttackTestResult], output_path: str
    ) -> Dict:
        summary = self.generate_summary(results)
        report = {
            "schema_version": "1.0",
            "tool": "oubliette-dungeon",
            "tool_version": "1.0.0",
            "timestamp": datetime.now().isoformat(),
            "session_id": self.current_session_id,
            "aggregate": summary,
            "results": [asdict(r) for r in results],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Benchmark report saved to {output_path}")
        return report

    def print_summary(self, results: List[AttackTestResult]) -> None:
        summary = self.generate_summary(results)

        print("\n" + "=" * 70)
        print("RED TEAM TEST SUMMARY")
        print("=" * 70)
        print(f"Session ID: {summary['session_id']}")
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Average Execution Time: {summary['avg_execution_time_ms']:.2f}ms")
        print(f"Average Confidence: {summary['avg_confidence']:.2%}")
        print()
        print(f"Detection Rate: {summary['detection_rate']:.1f}%")
        print(f"Bypass Rate: {summary['bypass_rate']:.1f}%")
        print()
        print("Results by Type:")
        for result_type, count in summary['by_result'].items():
            print(f"  {result_type}: {count}")
        print()
        print("Results by Category:")
        for category, count in summary['by_category'].items():
            print(f"  {category}: {count}")
        print()
        print("Advanced Metrics:")
        print(f"  pass@1:  {summary['pass_at_1']:.3f}")
        print(f"  pass@5:  {summary['pass_at_5']:.3f}")
        print(f"  pass@10: {summary['pass_at_10']:.3f}")
        ttj = summary.get('avg_turns_to_jailbreak')
        print(f"  Avg Turns to Jailbreak: {f'{ttj:.1f}' if ttj is not None else 'N/A'}")
        print(f"  Avg Risk Density: {summary['avg_risk_density']:.4f}")
        print("=" * 70)
