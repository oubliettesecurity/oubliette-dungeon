# Oubliette Dungeon -- Garak Probe Contribution

Garak probe and detector modules ported from [Oubliette Dungeon](https://github.com/oubliettesecurity/oubliette-dungeon), an open-source adversarial testing engine for LLM applications.

## What's included

| File | Description |
|------|-------------|
| `oubliette_adversarial.py` | 10 probe classes covering 57 attack scenarios across 9 categories |
| `oubliette_detector.py` | 2 detector classes with refusal-aware evaluation logic |

### Probe classes

| Class | Category | Scenarios | Key techniques |
|-------|----------|-----------|----------------|
| `OubliettePromptInjection` | CAT-01 | ATK-001--005, 028, 030--034 | Instruction override, nested injection, Base64 encoding, Unicode obfuscation, XML/HTML/CSV/JSON injection |
| `OublietteJailbreak` | CAT-02 | ATK-006--011, 035--037 | Roleplay, DAN, hypothetical framing, logic traps, recursive prompting, chain-of-thought, few-shot poisoning |
| `OublietteInformationExtraction` | CAT-03 | ATK-012--015, 038--040 | System prompt extraction, training data inference, credential extraction, config/path/network disclosure |
| `OublietteSocialEngineering` | CAT-04 | ATK-016--018, 041--043 | Authority impersonation, urgency, trust exploitation, false consensus, reciprocity, scarcity |
| `OublietteContextManipulation` | CAT-05 | ATK-019--020, 044--046, 051--057 | Attention shifting, memory poisoning, token-limit exploitation, context overflow, 7 RAG-specific attacks |
| `OublietteModelExploitation` | CAT-06 | ATK-021--022, 047--048 | Prefix forcing, safety erosion, adversarial examples, model steering |
| `OublietteResourceAbuse` | CAT-07 | ATK-023--024 | Token flooding, cost amplification |
| `OublietteToolExploitation` | CAT-08 | ATK-025--027 | Unauthorized tool calls, parameter injection, MCP exploitation |
| `OublietteComplianceTesting` | CAT-09 | ATK-028--029, 049--050 | OWASP LLM01, federal baseline, MITRE ATLAS coverage, real-world attack chain |
| `OublietteAllAttacks` | All | All 57 | Aggregates every prompt from the above classes |

### Detector classes

| Class | Description |
|-------|-------------|
| `OublietteRefusalAware` | Sentence-level bypass detection that filters out indicators appearing only in refusal context (reduces false positives) |
| `OublietteComplianceDetector` | Flags responses containing compliance language ("here's how", "step 1", etc.) |

## Installation

Copy the modules into your garak probe/detector directories:

```bash
# From the oubliette-dungeon repo root
cp contrib/garak/oubliette_adversarial.py /path/to/garak/garak/probes/
cp contrib/garak/oubliette_detector.py /path/to/garak/garak/detectors/
```

Or install as a garak plugin (once garak plugin support is available):

```bash
pip install oubliette-dungeon
# The probes will be auto-discovered under garak.probes.oubliette_adversarial
```

## Usage

### Run all 57 scenarios

```bash
garak --model_type openai --model_name gpt-4 \
      --probes oubliette_adversarial.OublietteAllAttacks
```

### Run a specific category

```bash
# Prompt injection only
garak --model_type openai --model_name gpt-4 \
      --probes oubliette_adversarial.OubliettePromptInjection

# Jailbreak only
garak --model_type openai --model_name gpt-4 \
      --probes oubliette_adversarial.OublietteJailbreak

# RAG-specific attacks (part of context manipulation)
garak --model_type openai --model_name gpt-4 \
      --probes oubliette_adversarial.OublietteContextManipulation
```

### Use the refusal-aware detector

```bash
garak --model_type openai --model_name gpt-4 \
      --probes oubliette_adversarial.OublietteAllAttacks \
      --detector oubliette_detector.OublietteRefusalAware
```

## Standards coverage

### OWASP LLM Top 10 (2025)

All 10 categories are covered:

| OWASP ID | Category | Probes |
|----------|----------|--------|
| LLM01 | Prompt Injection | `OubliettePromptInjection`, `OublietteJailbreak` |
| LLM02 | Sensitive Information Disclosure | `OublietteInformationExtraction` |
| LLM03 | Supply Chain Vulnerabilities | `OublietteToolExploitation` |
| LLM04 | Data and Model Poisoning | `OublietteContextManipulation` (RAG) |
| LLM05 | Improper Output Handling | `OublietteModelExploitation` |
| LLM06 | Excessive Agency | `OublietteToolExploitation` |
| LLM07 | System Prompt Leakage | `OublietteInformationExtraction` |
| LLM08 | Vector and Embedding Weaknesses | `OublietteContextManipulation` |
| LLM09 | Misinformation | `OublietteSocialEngineering` |
| LLM10 | Unbounded Consumption | `OublietteResourceAbuse` |

### MITRE ATLAS

21 technique / sub-technique IDs from MITRE ATLAS v2026.06, derived from the
per-scenario `mitre_mapping` in oubliette-dungeon (see each probe's `tags`):

- AML.T0010.005 -- AI Supply Chain Compromise: AI Agent Tool
- AML.T0011.002 -- User Execution: Poisoned AI Agent Tool
- AML.T0014 -- Discover AI Model Family
- AML.T0015 -- Evade AI Model
- AML.T0029 -- Denial of AI Service
- AML.T0034.001 -- Cost Harvesting: Resource-Intensive Queries
- AML.T0043 -- Craft Adversarial Data
- AML.T0051 -- LLM Prompt Injection (.000 Direct, .001 Indirect)
- AML.T0053 -- AI Agent Tool Invocation
- AML.T0054 -- LLM Jailbreak
- AML.T0056 -- Extract LLM System Prompt
- AML.T0057 -- LLM Data Leakage
- AML.T0066 -- Retrieval Content Crafting
- AML.T0068 -- LLM Prompt Obfuscation
- AML.T0069 -- Discover LLM System Information
- AML.T0070 -- RAG Poisoning
- AML.T0080.000 -- AI Agent Context Poisoning: Memory
- AML.T0083 -- Credentials from AI Agent Configuration
- AML.T0084 -- Discover AI Agent Configuration

## License

Apache-2.0, matching both garak and oubliette-dungeon.
