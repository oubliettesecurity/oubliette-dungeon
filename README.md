# Oubliette Dungeon

Standalone adversarial testing engine for LLM applications. Run red team attack scenarios against any LLM endpoint and measure safety guardrail effectiveness.

## Features

- **57 built-in attack scenarios** across 6 categories (prompt injection, jailbreaking, information extraction, social engineering, model exploitation, multi-turn attacks)
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
# Run all scenarios against a target
oubliette-dungeon run --target http://localhost:5000/api/chat

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
    scenario_file=None,  # Uses built-in scenarios
    target_url="http://localhost:5000/api/chat",
    results_db=db,
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

```bash
oubliette-dungeon run --scenarios my_scenarios.yaml --target http://localhost:5000/api/chat
```

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

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

Oubliette Dungeon is a product of [Oubliette Security](https://oubliettesecurity.com), a disabled veteran-owned cybersecurity company.
