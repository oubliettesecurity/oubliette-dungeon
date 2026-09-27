# Oubliette Dungeon

Standalone adversarial testing engine for LLM applications. Run red team attack scenarios against any LLM endpoint and measure safety guardrail effectiveness.

## Features

- **57 scenarios by default, 72 with `--suite full`.** Two bundled sets, 10 categories in total:
  - **Default library** (`scenarios/default.yaml`): 57 scenarios across 9 categories (prompt injection, jailbreak, information extraction, social engineering, model exploitation, context manipulation, tool exploitation, resource abuse, compliance testing). This is what `run`, `stats`, the API and the Python API use when no scenario file or suite is given.
  - **Crescendo multi-turn set** (`scenarios/crescendo.yaml`): 15 further `multi_turn_attack` scenarios. It is not loaded by default; `--suite full` (Python: `suite="full"`) loads it together with the default library, 72 scenarios in all (see [Scenario suites](#scenario-suites)).
- **Refusal-aware evaluation** - reduces false positive bypasses when LLMs mention attack keywords in refusal context
- **Honeypot-aware scoring** - detects honey token decoys from pipeline metadata
- **Multi-turn attack support** - escalating conversation sequences
- **Click CLI** with `run`, `stats`, `serve`, `demo`, `replay`, `export` commands
- **React SPA dashboard** with 6 pages (Command Center, Scenarios, Sessions, Providers, Scheduler, Reports)
- **Flask REST API** at `/api/dungeon/`
- **Tool integrations** - PyRIT, DeepTeam, AIX Framework, Garak probe importer
- **Cron scheduler** with webhook notifications
- **PDF report generation**
- **Multi-provider comparison** - benchmark multiple LLMs side-by-side

## Install

```bash
pip install oubliette-dungeon
```

With optional extras:

```bash
pip install oubliette-dungeon[flask]     # API server + dashboard
pip install oubliette-dungeon[pdf]       # PDF reports
pip install oubliette-dungeon[pyrit]     # PyRIT integration
pip install oubliette-dungeon[all]       # Everything
```

## Quick Start

### CLI

```bash
# Run the default library (57 scenarios) against a target
oubliette-dungeon run --target http://localhost:5000/api/chat

# Run the full bundled suite (72 scenarios: default 57 + 15 Crescendo multi-turn)
oubliette-dungeon run --suite full --target http://localhost:5000/api/chat

# Show scenario library statistics
oubliette-dungeon stats

# Start demo mode with mock target and seeded data
oubliette-dungeon demo

# Start the API server + dashboard
oubliette-dungeon serve --port 8666

# Export results
oubliette-dungeon export --format json --output results.json
```

### Python API

```python
from oubliette_dungeon import RedTeamOrchestrator, RedTeamResultsDB

db = RedTeamResultsDB("./results")
orch = RedTeamOrchestrator(
    scenario_file=None,  # Uses the default library (default.yaml, 57 scenarios)
    target_url="http://localhost:5000/api/chat",
    results_db=db,
    # suite="full",  # Or: the full bundled suite, 72 scenarios
)
results = orch.run_all_scenarios()
orch.print_summary(results)
```

### Docker

```bash
cd docker
docker compose up
```

Dashboard available at `http://localhost:8666`.

## Target API Contract

Your LLM endpoint should accept POST requests with:

```json
{"message": "the attack prompt text"}
```

And return:

```json
{
  "response": "the LLM's response text",
  "blocked": false,
  "ml_score": 0.15,
  "llm_verdict": "SAFE"
}
```

Only `response` is required. The additional fields (`blocked`, `ml_score`, `llm_verdict`) enable richer evaluation when available.

## Scenario suites

Only run Dungeon against targets you own or are authorized to test: every
scenario payload is sent live to `--target`.

| Suite | Scenarios | Files |
|---|---|---|
| `default` (used when neither `--suite` nor `--scenarios` is given) | 57 | `default.yaml` |
| `full` | 72 | `default.yaml` + `crescendo.yaml` (15 Crescendo multi-turn) |

```bash
oubliette-dungeon stats --suite full   # Total Scenarios: 72
oubliette-dungeon run --suite full --target http://localhost:5000/api/chat
```

`--suite` is available on `run`, `stats`, `replay`, `compare` and `nist-rmf`.
The Python API takes the same names: `RedTeamOrchestrator(..., suite="full")` or
`ScenarioLoader(suite="full")`.

A suite only loads scenario files that ship inside the package, so it does not
need, set, or imply `DUNGEON_ALLOW_CUSTOM_SCENARIOS`. It fails closed: an
unknown suite name is an error (the CLI exits with status 2, and the Python API
raises `ValueError`), and `--suite` together with `--scenarios` (or
`suite=` together with `scenario_file=`) is rejected instead of guessing which
one you meant.

## Custom Scenarios

```yaml
# my_scenarios.yaml
scenarios:
  - id: CUSTOM-001
    name: My Custom Attack
    category: prompt_injection
    difficulty: medium
    description: Custom injection test
    attack_text: "Ignore all previous instructions..."
    bypass_indicators: ["system prompt", "here's how"]
    safe_indicators: ["cannot", "won't"]
```

Any file passed with `--scenarios` other than the bundled default library is gated behind an explicit opt-in, because scenario payloads are sent live to the target. The gate is fail-closed: without the opt-in the file is refused.

```bash
DUNGEON_ALLOW_CUSTOM_SCENARIOS=true oubliette-dungeon run --scenarios my_scenarios.yaml --target http://localhost:5000/api/chat
```

To run the bundled Crescendo set, use `--suite full` (see [Scenario suites](#scenario-suites)), which needs no opt-in. Passing `crescendo.yaml` by path with `--scenarios` still goes through the gate and loads only its 15 scenarios.

## Development

```bash
git clone https://github.com/oubliette-security/oubliette-dungeon.git
cd oubliette-dungeon
pip install -e ".[dev]"
pytest tests/ -v
```

Dashboard development:

```bash
cd dashboard
npm install
npm run dev  # Vite dev server on :5173, proxies API to :8666
```

## Releasing (maintainers)

Releases publish to PyPI from `.github/workflows/publish.yml` via Trusted
Publishing (OIDC, no API token) when a `vX.Y.Z` tag is pushed; the moving
`v1` GitHub Action tag does not trigger it. One-time PyPI setup (Owner
`oubliettesecurity`, Repository `oubliette-dungeon`, Workflow `publish.yml`,
Environment `pypi`) and the full tag flow are in
[docs/pypi-trusted-publishing.md](https://github.com/oubliettesecurity/oubliette-dungeon/blob/main/docs/pypi-trusted-publishing.md).

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

Oubliette Dungeon is a product of [Oubliette Security](https://oubliettesecurity.com), a disabled veteran-owned cybersecurity company.
