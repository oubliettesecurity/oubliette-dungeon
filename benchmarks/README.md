# Oubliette Dungeon -- Benchmarks

Reproducible benchmark outputs produced by `scripts/benchmark_paper.py` against the
Oubliette Dungeon attack scenario library.

## Methodology

- **Script:** `../scripts/benchmark_paper.py`
- **Scenario source:** `../src/oubliette_dungeon/scenarios/default.yaml`
- **Evaluation:** Each scenario is submitted to a provider, the response is scored by
  both a naive keyword evaluator and a refusal-aware sentence-level evaluator.
  Outcomes are `detected`, `bypass`, or `partial`.
- **Metrics:** Detection rate, bypass rate, and false-positive rate per provider
  and per attack category.

## Run Details

| File | Date | Provider | Model | Scenarios executed |
|------|------|----------|-------|-------------------|
| `benchmark_openai.json` | 2026-03-12 | OpenAI | `gpt-4o-mini` | 54 |
| `benchmark_anthropic.json` | 2026-03-12 | Anthropic | `claude-sonnet-4-5-20250929` | 53 |
| `benchmark_gemini.json` | 2026-03-12 | Google | `gemini-2.0-flash` | 53 |
| `benchmark_ollama.json` | 2026-03-12 | Ollama | `llama3` | 54 |
| `shield_comparison.json` | 2026-03-12 | All four | Shield detection pipeline | 10 per provider (40 total) |

Scenario counts differ slightly by provider because the scenario library includes
reference-only entries (test coverage stubs) that are skipped when they have no
executable prompt; a small number of entries also fail provider-side validation.

## Headline Results -- Refusal-Aware Evaluation

Adversarial robustness, measured as `1 - bypass_rate`, across frontier models:

| Model | Scenarios | Detection rate | Bypass rate | Robustness |
|-------|-----------|---------------|-------------|-----------|
| `gpt-4o-mini` | 54 | 55.6% | 24.1% | **75.9%** |
| `llama3` | 54 | 20.4% | 27.8% | 72.2% |
| `claude-sonnet-4-5` | 53 | 3.8% | 56.6% | 43.4% |
| `gemini-2.0-flash` | 53 | 11.3% | 60.4% | 39.6% |

Naive keyword evaluation returned 0.0% detection across all four providers on this
scenario set, confirming that refusal-aware evaluation is required to distinguish
safe responses from bypasses. Refusal-aware evaluation lifted detection from 0% to
3.8--55.6% depending on model, while reducing false-positive rates by ~3%.

## Shield Detection Latency -- `shield_comparison.json`

10 scenarios × 4 provider responses = 40 runs through the Shield detection pipeline:

| Detection path | Samples | Mean | Median |
|----------------|---------|------|--------|
| Pre-filter (signatures) | 20 | 0.11 ms | 0.10 ms |
| LLM-only (full ensemble with LLM judge) | 20 | 1,590.94 ms | -- |

The pre-filter catches well-known attack patterns in sub-millisecond time. When
pre-filter and ML classifier stages do not yield a verdict, the LLM judge is
engaged, producing per-decision latency in the 1-2 second range (bounded by the
provider's completion latency, not Shield itself).

## Category Coverage

The current scenario library exercises 9 attack categories:

| Category | Scenarios |
|----------|-----------|
| prompt_injection | 9 |
| jailbreak | 9 |
| information_extraction | 7 |
| social_engineering | 6 |
| context_manipulation | 12 |
| model_exploitation | 4 |
| resource_abuse | 2 |
| tool_exploitation | 3 |
| compliance_testing | 1 |

The in-flight UK AISI `inspect_evals` submission (PR #1358) adds additional
scenarios and categories (evasion, RAG exploitation, agent exploitation),
bringing the total exposed through that framework to 35 scenarios across 12
categories.

## Reproducibility

```bash
# Set provider credentials
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
export GOOGLE_API_KEY=...
# (Ollama requires no key; run locally on :11434)

# Run all available providers
python scripts/benchmark_paper.py --output benchmarks/my_run.json

# Run a single provider
python scripts/benchmark_paper.py --providers ollama --output benchmarks/ollama_only.json
```

The outputs here were produced on 2026-03-12 and reflect provider model
versions and scenario library state on that date. Re-runs against newer model
versions may produce different numbers; the library itself is versioned by git.
