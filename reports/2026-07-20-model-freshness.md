# Model Freshness Report — 2026-07-20

**Advisory run**: 2026-07-20  
**Repos reviewed**: oubliettesecurity/oubliette · oubliettesecurity/oubliette-dungeon  
**Last config verification date (both repos)**: 2026-06-01  
**Scope**: Anthropic, OpenAI, Google (Gemini · Gemma), Meta (Llama)

> This report is advisory only. James applies model bumps manually after review.  
> Do **not** touch benchmark-pinned snapshot IDs in `benchmarks/*.json`.

---

## Findings

### Anthropic — ACTION REQUIRED

Two tiers are behind newer GA models.

| Repo | Tier | Current | Latest GA | Recommended Action |
|------|------|---------|-----------|-------------------|
| oubliette / oubliette-dungeon | flagship | `claude-opus-4-8` | `claude-fable-5` | **UPGRADE** |
| oubliette / oubliette-dungeon | default | `claude-sonnet-4-6` | `claude-sonnet-5` | **UPGRADE** |
| oubliette / oubliette-dungeon | small | `claude-haiku-4-5-20251001` | `claude-haiku-4-5-20251001` | No change |

**Claude Fable 5** (`claude-fable-5`) became GA on June 9, 2026, on the Claude API, Amazon Bedrock, Google Cloud, and Microsoft Foundry. Access was briefly restricted June 9–30 for export-control review; global availability restored July 1, 2026. It is now the highest-capability generally-available Claude model, exceeding Opus 4.8 on nearly all benchmarks.

**Claude Sonnet 5** (`claude-sonnet-5`) is GA. Performance is close to Opus 4.8 at a lower price point — a direct upgrade from Sonnet 4.6 for the `default` tier.

**Claude Haiku 4.5** (`claude-haiku-4-5-20251001`) is already current. No change needed.

> **Note — Mythos 5**: `claude-mythos-5` is **not GA**. It is in limited availability to approved customers (Project Glasswing) only. Do not promote it to the `flagship` tier.

#### Bedrock Anthropic Tier (same bump applies)

| Repo | Tier | Current | Latest GA | Recommended Action |
|------|------|---------|-----------|-------------------|
| oubliette / oubliette-dungeon | flagship | `anthropic.claude-opus-4-8` | `anthropic.claude-fable-5` | **UPGRADE** |
| oubliette / oubliette-dungeon | default | `anthropic.claude-sonnet-4-6` | `anthropic.claude-sonnet-5` | **UPGRADE** |
| oubliette / oubliette-dungeon | small | `anthropic.claude-haiku-4-5` | `anthropic.claude-haiku-4-5` | No change |

Fable 5 is confirmed available on Amazon Bedrock as of June 9, 2026.

**Sources**: [Claude Fable 5 & Mythos 5 announcement](https://www.anthropic.com/news/claude-fable-5-mythos-5) · [Redeploying Fable 5 (global availability restored)](https://www.anthropic.com/news/redeploying-fable-5) · [Claude Sonnet 5 announcement](https://www.anthropic.com/news/claude-sonnet-5) · [Haiku 4.5 announcement](https://www.anthropic.com/news/claude-haiku-4-5)

---

### OpenAI — WATCH (no change today)

| Repo | Tier | Current | Latest GA | Recommended Action |
|------|------|---------|-----------|-------------------|
| oubliette / oubliette-dungeon | flagship | `gpt-5.5` | `gpt-5.5` | No change |
| oubliette / oubliette-dungeon | default | `gpt-5.4-mini` | Unconfirmed | Review next sweep |
| oubliette / oubliette-dungeon | small | `gpt-5.4-nano` | Unconfirmed | Review next sweep |

**GPT-5.6** (Sol · Terra · Luna) was announced July 9, 2026, with GA described as "coming weeks." As of 2026-07-20 the models remain in limited preview with restricted partner access. `gpt-5.5` (GA since April 24, 2026) is the last confirmed GA flagship. No upgrade warranted today.

**Default / Small tiers**: OpenAI's platform docs reference `gpt-5-mini` and `gpt-5-nano` pages, but versioned GA mid/small IDs for the GPT-5.5 generation could not be confirmed from public sources in this sweep. The existing `gpt-5.4-mini` / `gpt-5.4-nano` remain as-is pending clarification. Recommend a targeted API doc check next sweep or when GPT-5.6 goes GA.

**Sources**: [GPT-5.6 announcement](https://openai.com/index/gpt-5-6/) · [Previewing GPT-5.6 Sol](https://openai.com/index/previewing-gpt-5-6-sol/) · [GPT-5.5 announcement](https://openai.com/index/introducing-gpt-5-5/) · [OpenAI Models reference](https://platform.openai.com/docs/models)

---

### Google Gemini / Vertex — No change

| Repo | Tier | Current | Latest GA | Recommended Action |
|------|------|---------|-----------|-------------------|
| oubliette / oubliette-dungeon | flagship | `gemini-3.5-flash` | `gemini-3.5-flash` | No change |
| oubliette / oubliette-dungeon | default | `gemini-3.1-flash` | `gemini-3.1-flash` | No change |
| oubliette / oubliette-dungeon | small | `gemini-3.1-flash-lite` | `gemini-3.1-flash-lite` | No change |

`gemini-3.5-flash` is GA and is the current model behind `gemini-flash-latest`. `gemini-3.1-flash-lite` is confirmed GA for cost-sensitive workloads. `gemini-3.1-flash` appears still in service. No Gemini 4.x announced as GA. Gemini 2.0 models have been shut down; Google recommends `gemini-3.5-flash` or `gemini-3.1-flash-lite` for any remaining Gemini 2.0 users.

**Sources**: [Gemini 3.5 Flash — AI for Developers](https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash) · [Gemini API models](https://ai.google.dev/gemini-api/docs/models) · [Gemini Enterprise Agent Platform model list](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/google-models) · [Gemini 3.1 Flash-Lite](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/gemini/3-1-flash-lite)

---

### Google Gemma — No change

| Repo | Tier | Current | Latest GA | Recommended Action |
|------|------|---------|-----------|-------------------|
| oubliette / oubliette-dungeon | flagship | `gemma4:31b` | `gemma4:31b` | No change |
| oubliette / oubliette-dungeon | default | `gemma4:26b` | `gemma4:26b` | No change |
| oubliette / oubliette-dungeon | small | `gemma4:e4b` | `gemma4:e4b` | No change |

Gemma 4 (released April 2, 2026) is the latest GA open-weight Gemma family. Sizes: E2B (2B), E4B (4B), 12B Unified, 26B MoE, 31B Dense. The existing tier mapping (31B Dense / 26B MoE / E4B) is current. A new **12B Unified** multimodal model (GA June 3, 2026, `gemma4:12b` on Ollama) adds a capability tier between E4B and 26B but there is no existing slot for it — noting for future consideration. No Gemma 5 announced.

**Sources**: [Gemma 4 blog (Google)](https://blog.google/innovation-and-ai/technology/developers-tools/gemma-4/) · [Gemma 4 DeepMind](https://deepmind.google/models/gemma/gemma-4/) · [Gemma releases](https://ai.google.dev/gemma/docs/releases) · [Gemma 4 12B introduction](https://blog.google/innovation-and-ai/technology/developers-tools/introducing-gemma-4-12b/)

---

### Meta Llama (via Ollama) — No change

| Repo | Tier | Current | Latest GA | Recommended Action |
|------|------|---------|-----------|-------------------|
| oubliette / oubliette-dungeon | flagship | `llama4:maverick` | `llama4:maverick` | No change |
| oubliette / oubliette-dungeon | default | `llama4` | `llama4` | No change |
| oubliette / oubliette-dungeon | small | `llama3.3` | `llama3.3` | No change |

Llama 4 (Scout + Maverick) remains Meta's current GA open-weight flagship family. No Llama 5 GA release found. `llama3.3` remains the current recommended small model; no Llama 4 small-tier variant has been announced.

**Sources**: [Llama 4 announcement](https://ai.meta.com/blog/llama-4-multimodal-intelligence/) · [LlamaCon summary](https://ai.meta.com/blog/llamacon-llama-news/) · [Meta AI open source](https://ai.meta.com/open/)

---

## SUSPICIOUS Flags

None. No fetched content attempted to redirect model IDs, change API endpoints, or inject instructions. Official provider documentation pages (docs.anthropic.com, developers.openai.com, ai.google.dev) returned HTTP 403 to direct fetch; all data was sourced from web search snippets of official domains and cross-referenced across multiple sources per provider. No anomalies detected.

---

## Sentinel Note

`canthaxit` (private repo, not cloud-accessible) was not reviewed in this sweep. It should receive the **same Anthropic and Bedrock bumps** applied to `oubliette` and `oubliette-dungeon`. Apply locally:
- `anthropic.flagship`: `claude-opus-4-8` → `claude-fable-5`
- `anthropic.default`: `claude-sonnet-4-6` → `claude-sonnet-5`
- `bedrock_anthropic.flagship`: `anthropic.claude-opus-4-8` → `anthropic.claude-fable-5`
- `bedrock_anthropic.default`: `anthropic.claude-sonnet-4-6` → `anthropic.claude-sonnet-5`

---

## Action Summary

| Priority | Provider | Change |
|----------|----------|--------|
| HIGH | Anthropic | `flagship`: `claude-opus-4-8` → `claude-fable-5` (both repos + canthaxit) |
| HIGH | Anthropic | `default`: `claude-sonnet-4-6` → `claude-sonnet-5` (both repos + canthaxit) |
| HIGH | Bedrock Anthropic | `flagship`: `anthropic.claude-opus-4-8` → `anthropic.claude-fable-5` (both repos + canthaxit) |
| HIGH | Bedrock Anthropic | `default`: `anthropic.claude-sonnet-4-6` → `anthropic.claude-sonnet-5` (both repos + canthaxit) |
| WATCH | OpenAI | GPT-5.6 Sol/Terra/Luna moving toward GA — reassess next weekly sweep |
| WATCH | OpenAI | Confirm GA mid/small IDs for GPT-5.5 generation (default/small tiers may be stale) |
| INFO | Google Gemma | `gemma4:12b` (12B Unified) now available; no tier slot today — consider for future |

---

COVERAGE: 2/2 repos reviewed  
*(canthaxit: private/inaccessible from cloud session — same bumps apply locally)*
