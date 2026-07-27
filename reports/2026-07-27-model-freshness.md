# Model Freshness Report — 2026-07-27

**Advisory run**: 2026-07-27  
**Repos reviewed**: oubliettesecurity/oubliette · oubliettesecurity/oubliette-dungeon  
**Last config verification date (both repos)**: 2026-06-01  
**Last model-freshness report**: 2026-07-20  
**Scope**: Anthropic, OpenAI, Google (Gemini · Gemma), Meta (Llama)

> This report is advisory only. James applies model bumps manually after review.  
> Do **not** touch benchmark-pinned snapshot IDs in `benchmarks/*.json`.

---

## Summary — High-activity week

Three provider updates require attention this sweep:

| Priority | Provider | What changed |
|----------|----------|-------------|
| HIGH (carry-forward + new) | Anthropic | `claude-opus-5` GA July 24; prior `claude-fable-5` / `claude-sonnet-5` recommendations from July 20 **still unactioned** in config |
| HIGH (new) | OpenAI | GPT-5.6 Sol / Terra / Luna GA — API doc pages live; all three tiers ready to bump |
| MEDIUM (new) | Google Gemini | `gemini-3.6-flash` GA; `gemini-3.1-flash` superseded (shut-down path per changelog) |
| — | Google Gemma | No change |
| — | Meta Llama | No change |

---

## Findings

### Anthropic — ACTION REQUIRED (carry-forward + new flagship candidate)

> **July 20 status**: `claude-fable-5` (flagship) and `claude-sonnet-5` (default) were recommended. Config was **not updated** — still shows `claude-opus-4-8` / `claude-sonnet-4-6` as of this sweep.
>
> **New this week**: `claude-opus-5` system card published and GA confirmed July 24, 2026 — three days ago. This creates a second flagship candidate alongside `claude-fable-5`.

#### Flagship tier — Two candidates; James's call

Both `claude-fable-5` and `claude-opus-5` are now GA. The July 20 report rated Fable 5 as "highest-capability generally-available Claude model, exceeding Opus 4.8 on nearly all benchmarks." Opus 5 (just released) is described as an upgrade to Opus 4.8 with "22% improvement over Opus 4.7 on hardest agentic coding tasks" and "strongest computer-use and browser-agent model tested, scoring 84% on Online-Mind2Web." Relative capability between Fable 5 and Opus 5 could not be confirmed from search snippets alone — official benchmarks were not yet indexed. **Recommend James review the Anthropic models overview before committing the flagship bump.**

| Repo | Tier | Current | Latest GA options | Recommended Action |
|------|------|---------|-------------------|-------------------|
| oubliette / oubliette-dungeon | flagship | `claude-opus-4-8` | `claude-fable-5` (GA Jun 9) · `claude-opus-5` (GA Jul 24) | **UPGRADE — choose one; see note** |
| oubliette / oubliette-dungeon | default | `claude-sonnet-4-6` | `claude-sonnet-5` | **UPGRADE** |
| oubliette / oubliette-dungeon | small | `claude-haiku-4-5-20251001` | `claude-haiku-4-5-20251001` | No change |

**Claude Opus 5** (`claude-opus-5`) is available on the Claude Platform, Amazon Bedrock, Google Cloud, and Microsoft Foundry. Released July 24, 2026.

**Claude Fable 5** (`claude-fable-5`) is available on the Claude Platform, Amazon Bedrock, Google Cloud, and Microsoft Foundry. GA since June 9, 2026 (global availability fully restored July 1 after brief export-control review).

**Claude Sonnet 5** (`claude-sonnet-5`) GA June 30, 2026. Current default model for all Claude plan tiers.

**Claude Haiku 4.5** (`claude-haiku-4-5-20251001`) is current — no change needed.

> **Note — Mythos 5**: `claude-mythos-5` is **not GA**. Limited availability to approved customers (Project Glasswing) only. Do not promote to any production tier.

#### Bedrock Anthropic Tier (same bump applies)

| Repo | Tier | Current | Latest GA options | Recommended Action |
|------|------|---------|-------------------|-------------------|
| oubliette / oubliette-dungeon | flagship | `anthropic.claude-opus-4-8` | `anthropic.claude-fable-5` · `anthropic.claude-opus-5` | **UPGRADE — choose same as above** |
| oubliette / oubliette-dungeon | default | `anthropic.claude-sonnet-4-6` | `anthropic.claude-sonnet-5` | **UPGRADE** |
| oubliette / oubliette-dungeon | small | `anthropic.claude-haiku-4-5` | `anthropic.claude-haiku-4-5` | No change |

Both Fable 5 and Opus 5 are confirmed on Bedrock.

**Sources**: [Introducing Claude Opus 5](https://www.anthropic.com/news/claude-opus-5) · [Claude Opus 5 System Card (Jul 24)](https://www-cdn.anthropic.com/c5fbac3f0b1280a933ebd26d3cb8bb9f5bdeaf48/Claude%20Opus%205%20System%20Card.pdf) · [Claude Fable 5 & Mythos 5 announcement](https://www.anthropic.com/news/claude-fable-5-mythos-5) · [Claude Sonnet 5 announcement](https://www.anthropic.com/news/claude-sonnet-5) · [Claude Haiku 4.5 announcement](https://www.anthropic.com/news/claude-haiku-4-5)

---

### OpenAI — ACTION REQUIRED (GPT-5.6 GA)

> **July 20 status**: GPT-5.6 was in preview, GA "coming weeks." As of this sweep, API documentation pages for all three variants are live and the launch post says "available starting today across ChatGPT, Codex, and the OpenAI API" (announced July 9). Treating as GA.

| Repo | Tier | Current | Latest GA | Recommended Action |
|------|------|---------|-----------|-------------------|
| oubliette / oubliette-dungeon | flagship | `gpt-5.5` | `gpt-5.6-sol` | **UPGRADE** |
| oubliette / oubliette-dungeon | default | `gpt-5.4-mini` | `gpt-5.6-terra` | **UPGRADE** |
| oubliette / oubliette-dungeon | small | `gpt-5.4-nano` | `gpt-5.6-luna` | **UPGRADE** |

**GPT-5.6 Sol** (`gpt-5.6-sol`) — Flagship; complex reasoning and coding. $5/1M input · $30/1M output. Context: 1M tokens.

**GPT-5.6 Terra** (`gpt-5.6-terra`) — Balanced; "competitive performance to GPT-5.5 while being 2× cheaper." $2.50/1M input · $15/1M output.

**GPT-5.6 Luna** (`gpt-5.6-luna`) — Fast and affordable; lowest cost. $1/1M input · $6/1M output.

> Same bumps apply to `azure_openai` tier (deployment names are deployment-specific but the model ID defaults should track).

**Sources**: [GPT-5.6 announcement](https://openai.com/index/gpt-5-6/) · [GPT-5.6 Luna API docs](https://developers.openai.com/api/docs/models/gpt-5.6-luna) · [GPT-5.6 Terra API docs](https://developers.openai.com/api/docs/models/gpt-5.6-terra) · [Previewing GPT-5.6 Sol](https://openai.com/index/previewing-gpt-5-6-sol/)

---

### Google Gemini / Vertex — ACTION REQUIRED

> **July 20 status**: `gemini-3.5-flash` (flagship), `gemini-3.1-flash` (default), `gemini-3.1-flash-lite` (small) were all marked no-change. Since that sweep, **Gemini 3.6 Flash went GA** and `gemini-3.1-flash` has entered a deprecation path.

| Repo | Tier | Current | Latest GA | Recommended Action |
|------|------|---------|-----------|-------------------|
| oubliette / oubliette-dungeon | flagship | `gemini-3.5-flash` | `gemini-3.6-flash` | **UPGRADE** |
| oubliette / oubliette-dungeon | default | `gemini-3.1-flash` | `gemini-3.5-flash` | **UPGRADE** (3.1 deprecating) |
| oubliette / oubliette-dungeon | small | `gemini-3.1-flash-lite` | `gemini-3.5-flash-lite` | **UPGRADE** |

**Gemini 3.6 Flash** (`gemini-3.6-flash`) — GA. "Stronger performance on complex agentic and multimodal tasks while reducing token usage, at a lower price point than 3.5 Flash." Supports 1M token context, 64k max output, full built-in tool suite including Computer Use.

**Gemini 3.5 Flash** (`gemini-3.5-flash`) — GA and stable; appropriate for `default` slot (previously the flagship). 3.1 Flash is being deprecated per Google's changelog (Gemini 2.0 models shut down June 1, 2026; Gemini 3.1 on same trajectory).

**Gemini 3.5 Flash-Lite** (`gemini-3.5-flash-lite`) — GA. "Fastest, lowest-cost model in the 3.5 family; outperforms prior Flash-Lite generations for high-throughput execution." Replaces 3.1-flash-lite.

> Same bumps apply to `google_vertex` tier.

**Sources**: [Gemini 3.6 Flash — AI for Developers](https://ai.google.dev/gemini-api/docs/models/gemini-3.6-flash) · [Gemini 3.5 Flash — AI for Developers](https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash) · [Gemini API changelog](https://ai.google.dev/gemini-api/docs/changelog) · [Gemini API models overview](https://ai.google.dev/gemini-api/docs/models) · [Gemini Enterprise Agent Platform model list](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/google-models)

---

### Google Gemma — No change

| Repo | Tier | Current | Latest GA | Recommended Action |
|------|------|---------|-----------|-------------------|
| oubliette / oubliette-dungeon | flagship | `gemma4:31b` | `gemma4:31b` | No change |
| oubliette / oubliette-dungeon | default | `gemma4:26b` | `gemma4:26b` | No change |
| oubliette / oubliette-dungeon | small | `gemma4:e4b` | `gemma4:e4b` | No change |

Gemma 4 (released April 2, 2026) remains the latest GA open-weight Gemma family. Sizes: E2B, E4B, 12B Unified, 26B MoE, 31B Dense. July 15, 2026 weights/kernels refresh applied to all sizes on HuggingFace — no version number change, existing Ollama tags updated in-place. No Gemma 5 announced. `gemma4:12b` noted for future consideration (no tier slot currently).

**Sources**: [Gemma 4 blog (Google)](https://blog.google/innovation-and-ai/technology/developers-tools/gemma-4/) · [Gemma 4 12B introduction](https://blog.google/innovation-and-ai/technology/developers-tools/introducing-gemma-4-12b/) · [Gemma 4 July 2026 updates](https://www.explainx.ai/blog/gemma-4-updates-flash-attention-tool-calling-july-2026)

---

### Meta Llama (via Ollama) — No change

| Repo | Tier | Current | Latest GA | Recommended Action |
|------|------|---------|-----------|-------------------|
| oubliette / oubliette-dungeon | flagship | `llama4:maverick` | `llama4:maverick` | No change |
| oubliette / oubliette-dungeon | default | `llama4` | `llama4` | No change |
| oubliette / oubliette-dungeon | small | `llama3.3` | `llama3.3` | No change |

Llama 4 (Scout + Maverick) remains Meta's current GA open-weight flagship family. No Llama 5 GA release found. `llama3.3` remains the current recommended small model; Llama 4 Scout (`llama4:scout`) exists on HuggingFace but Ollama tag availability for production use was not confirmed — flagged for future sweep.

**Sources**: [Llama 4 announcement](https://ai.meta.com/blog/llama-4-multimodal-intelligence/) · [Llama 4 Maverick on HuggingFace](https://huggingface.co/meta-llama/Llama-4-Maverick-17B-128E-Instruct) · [LlamaCon summary](https://ai.meta.com/blog/llamacon-llama-news/)

---

## SUSPICIOUS Flags

None. No fetched content attempted to redirect model IDs, change API endpoints, or inject instructions. Official provider documentation pages (docs.anthropic.com, platform.openai.com) returned HTTP 403 to direct fetch; all data was sourced from web search snippets of official domains and cross-referenced across multiple results per provider. No anomalies detected.

---

## Sentinel Note

`canthaxit` (private repo, not cloud-accessible) was not reviewed in this sweep. It should receive the **same Anthropic, Bedrock, OpenAI, and Gemini bumps** applied to `oubliette` and `oubliette-dungeon`. Apply locally:

**Anthropic (choose flagship: fable-5 or opus-5 — match whatever oubliette uses):**
- `anthropic.flagship`: `claude-opus-4-8` → `claude-fable-5` OR `claude-opus-5`
- `anthropic.default`: `claude-sonnet-4-6` → `claude-sonnet-5`
- `bedrock_anthropic.flagship`: `anthropic.claude-opus-4-8` → `anthropic.claude-fable-5` OR `anthropic.claude-opus-5`
- `bedrock_anthropic.default`: `anthropic.claude-sonnet-4-6` → `anthropic.claude-sonnet-5`

**OpenAI:**
- `openai.flagship`: `gpt-5.5` → `gpt-5.6-sol`
- `openai.default`: `gpt-5.4-mini` → `gpt-5.6-terra`
- `openai.small`: `gpt-5.4-nano` → `gpt-5.6-luna`

**Google Gemini:**
- `google_gemini.flagship`: `gemini-3.5-flash` → `gemini-3.6-flash`
- `google_gemini.default`: `gemini-3.1-flash` → `gemini-3.5-flash`
- `google_gemini.small`: `gemini-3.1-flash-lite` → `gemini-3.5-flash-lite`

---

## Full Action Summary

| Priority | Provider | Change |
|----------|----------|--------|
| HIGH | Anthropic | `flagship`: `claude-opus-4-8` → `claude-fable-5` or `claude-opus-5` — **James to choose** (both repos + canthaxit; review Anthropic models page first) |
| HIGH | Anthropic | `default`: `claude-sonnet-4-6` → `claude-sonnet-5` (both repos + canthaxit) |
| HIGH | Bedrock Anthropic | Mirror same flagship/default bumps with `anthropic.` prefix (both repos + canthaxit) |
| HIGH | OpenAI | `flagship`: `gpt-5.5` → `gpt-5.6-sol` (both repos + canthaxit) |
| HIGH | OpenAI | `default`: `gpt-5.4-mini` → `gpt-5.6-terra` (both repos + canthaxit) |
| HIGH | OpenAI | `small`: `gpt-5.4-nano` → `gpt-5.6-luna` (both repos + canthaxit) |
| HIGH | Azure OpenAI | Mirror same OpenAI bumps (deployment-specific, but model ID defaults should track) |
| MEDIUM | Google Gemini | `flagship`: `gemini-3.5-flash` → `gemini-3.6-flash` (both repos + canthaxit) |
| MEDIUM | Google Gemini | `default`: `gemini-3.1-flash` → `gemini-3.5-flash` (3.1 deprecating; both repos + canthaxit) |
| MEDIUM | Google Gemini | `small`: `gemini-3.1-flash-lite` → `gemini-3.5-flash-lite` (both repos + canthaxit) |
| MEDIUM | Google Vertex | Mirror same Gemini bumps |
| INFO | Llama | `llama4:scout` as potential future small-tier candidate — confirm Ollama tag availability |
| INFO | Google Gemma | `gemma4:12b` (12B Unified) available; no tier slot today — consider for future |

---

COVERAGE: 2/2 repos reviewed  
*(canthaxit: private/inaccessible from cloud session — same bumps apply locally)*
