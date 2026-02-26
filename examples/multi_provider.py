"""
Multi-provider comparison example.

Run the same red team scenarios against multiple LLM providers
and compare their resilience.

Prerequisites:
    pip install oubliette-dungeon[all]
    pip install oubliette-shield

Usage:
    python examples/multi_provider.py
"""

from oubliette_dungeon import RedTeamOrchestrator, RedTeamResultsDB


PROVIDERS = [
    {
        "name": "Local Ollama (llama3)",
        "url": "http://localhost:5000/api/chat",
    },
    {
        "name": "OpenAI GPT-4",
        "url": "http://localhost:5001/api/chat",
    },
    {
        "name": "Anthropic Claude",
        "url": "http://localhost:5002/api/chat",
    },
]


def main():
    db = RedTeamResultsDB("./comparison_results")
    all_results = {}

    for provider in PROVIDERS:
        print(f"\n{'='*60}")
        print(f"Testing: {provider['name']}")
        print(f"Target:  {provider['url']}")
        print(f"{'='*60}")

        orch = RedTeamOrchestrator(
            scenario_file=None,
            target_url=provider["url"],
            results_db=db,
            timeout=30,
        )

        results = orch.run_all_scenarios()
        all_results[provider["name"]] = results
        orch.print_summary(results)

    # Compare results
    print(f"\n{'='*60}")
    print("COMPARISON SUMMARY")
    print(f"{'='*60}")
    print(f"{'Provider':<30} {'Detected':<10} {'Bypassed':<10} {'Rate':<10}")
    print("-" * 60)

    for name, results in all_results.items():
        detected = sum(1 for r in results if r.get("result") == "detected")
        bypassed = sum(1 for r in results if r.get("result") == "bypass")
        total = len(results) or 1
        rate = detected / total * 100
        print(f"{name:<30} {detected:<10} {bypassed:<10} {rate:<10.1f}%")


if __name__ == "__main__":
    main()
