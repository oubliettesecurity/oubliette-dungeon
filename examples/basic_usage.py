"""
Basic usage example for oubliette-dungeon.

Run red team scenarios against a target LLM endpoint and print results.

Usage:
    python examples/basic_usage.py
"""

from oubliette_dungeon import RedTeamOrchestrator, RedTeamResultsDB


def main():
    # Initialize results storage
    db = RedTeamResultsDB("./results")

    # Create orchestrator pointing at your LLM endpoint
    orch = RedTeamOrchestrator(
        scenario_file=None,  # Uses built-in default scenarios
        target_url="http://localhost:5000/api/chat",
        results_db=db,
        timeout=30,
    )

    # Run all 57 built-in scenarios
    print("Running all scenarios...")
    results = orch.run_all_scenarios()

    # Print summary
    orch.print_summary(results)

    # Export benchmark JSON
    orch.export_benchmark(results, "benchmark_results.json")
    print("\nBenchmark exported to benchmark_results.json")

    # Run only prompt injection scenarios
    print("\nRunning prompt injection scenarios only...")
    injection_results = orch.run_by_category("prompt_injection")
    orch.print_summary(injection_results)

    # Run a single specific scenario
    print("\nRunning single scenario ATK-006 (Roleplay Jailbreak)...")
    single = orch.run_single_scenario("ATK-006")
    print(f"  Result: {single.get('result', 'unknown')}")
    print(f"  Confidence: {single.get('confidence', 0):.2f}")


if __name__ == "__main__":
    main()
