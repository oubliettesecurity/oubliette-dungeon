# Changelog

All notable changes to oubliette-dungeon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-09-27

1.0.3 was never released; its changes ship in this release. The full scenario
suite becomes a Dungeon Pro feature and licensing moves to product-scoped
Ed25519 keys, both breaking changes: see *Changed (breaking)*.

### Changed (breaking)
- **The full scenario suite requires Dungeon Pro.** `--suite full` /
  `suite="full"` (72 scenarios) needs the `full_scenario_library`
  entitlement from a verified Dungeon license key: a key scoped to
  `dungeon` that is either `enterprise` or `pro` granting the feature. So
  does loading the bundled `crescendo.yaml` by path through
  `DUNGEON_ALLOW_CUSTOM_SCENARIOS`, including a byte-identical copy of it at
  another path. Without the entitlement the request is refused, never
  downgraded to the 57-scenario default:
  - The CLI prints an error naming the entitlement and exits 1 before any
    work.
  - `ScenarioLoader` / `RedTeamOrchestrator` raise
    `oubliette_dungeon.license.LicenseRequiredError`, a `PermissionError`.

  The default suite needs no license. The dev opt-in
  (`OUBLIETTE_INSECURE_DEV_FEATURE_GATE=true` plus a non-empty
  `OUBLIETTE_LICENSE_KEY`) still works.
- **Product-scoped license keys (schema v2).** Keys are signed with Ed25519
  and carry a signed `products` list. Dungeon accepts a key only if
  `"dungeon"` is in that list, so a Shield or Trap key does not unlock
  Dungeon Pro. Verification runs in `oubliette_dungeon/_license_core.py`,
  vendored byte-identical from `oubliette-commerce`, which is now the only
  issuer.
- **HMAC licenses removed.** This supersedes the HMAC notes below.
  `LicenseManager(signing_key=...)` and `OUBLIETTE_LICENSE_SIGNING_KEY` are
  gone. The signature is now `LicenseManager(*, storage_backend=None,
  keyring=None)`.
- **No perpetual keys.** `expires` is required, so an empty or missing
  `expires` gives the free tier. Pre-v2 keys also give the free tier. No
  licenses had been issued, so this is a clean cutover.

### Removed
- `oubliette_dungeon.license_issuer` and `oubliette_dungeon.license_webhook`.
  Issuing and the Gumroad/Paddle sale webhook now live only in
  `oubliette-commerce`.

### Added
- **Named scenario suites: 57 scenarios by default, 72 with `--suite full`.**
  `--suite full` on `run`, `stats`, `replay`, `compare` and `nist-rmf`
  (Python: `RedTeamOrchestrator(..., suite="full")` /
  `ScenarioLoader(suite="full")`) loads the default library plus the 15
  bundled Crescendo multi-turn scenarios. A suite only loads files that ship
  in the package, so it does not need or enable
  `DUNGEON_ALLOW_CUSTOM_SCENARIOS`, which keeps gating custom scenario files
  exactly as before. `--suite default` (57) is the default. Unknown suite
  names fail closed (CLI usage error, exit 2; `ValueError` from the Python
  API), and `--suite` with `--scenarios` (or `suite=` with `scenario_file=`)
  is rejected. `full` requires Dungeon Pro (see *Changed (breaking)*).
- `licensing` extra (`cryptography>=48.0.1`), also included in `dev`, `test`
  and `all`.
- `oubliette_dungeon.license.require_feature()` and `LicenseRequiredError`.
- `license_manager=` keyword on `ScenarioLoader` and `RedTeamOrchestrator`.

### Security
- **New production license-signing key.** The embedded keyring
  (`PRODUCTION_KEYRING`) now trusts only kid `oubliette-2026-10`, generated
  2026-10-06. Kid `oubliette-2026-07` is removed outright: no license was ever
  issued under it, so no customer key is affected, and a token naming it now
  gives the free tier. `_license_core.py` stays byte-identical across Commerce,
  Shield, Trap and Dungeon.
- **License verification fails closed.** `LicenseManager` previously skipped
  HMAC verification entirely when no signing key was configured, so any
  base64 JSON blob claiming `"tier": "enterprise"` was trusted. With no
  `OUBLIETTE_LICENSE_SIGNING_KEY` (or `signing_key=`) configured, a license
  key is now rejected and Dungeon runs in the free tier. A license whose
  signature is missing, malformed, or does not match is also rejected. The
  HMAC-SHA256 signing scheme itself is unchanged.
- **License webhook requires HMAC authentication.** The Gumroad sale webhook
  now requires a valid HMAC-SHA256 signature over the raw request body before
  minting a license; with no `OUBLIETTE_WEBHOOK_SECRET` configured, every
  request is rejected (401) instead of minting unauthenticated (#2). The
  verifier now comes from `oubliette-sec-utils>=0.1.2` (#5).
- **Offline executor validates the resolved IP.** The Ollama URL check now
  resolves the host and requires every resolved address to be loopback
  (unresolvable hosts are rejected), instead of string-matching
  `localhost` / `127.0.0.1` / `::1` (#4).
- **OSEF and PDF report reads honor per-API-key session scoping** (#1).
- **Usage metering rejects negative quantities** (including negative token
  counts) with `ValueError` before any counter is updated (#3).
- **License expiry fails closed.** A correctly signed license whose `expires`
  cannot be parsed as an ISO date (or is not a string) now falls back to the
  free tier instead of being treated as never expiring.
- **`FeatureGate` without a `LicenseManager` fails closed.** An unverified
  non-empty key no longer grants Pro; the gate stays at `community`. The old
  behaviour is available for development and tests only via
  `insecure_simple_mode=True` or `OUBLIETTE_INSECURE_DEV_FEATURE_GATE=true`
  (default off).

### Fixed
- Concurrent `save_result` calls for the same session no longer drop
  results: writes are serialized per session and use an atomic temp-file
  replace; orchestrator session ids gain a short random suffix to avoid
  same-second collisions (#1).
- Multi-turn executions now populate the pipeline metadata the evaluator
  uses (#1).
- The executor and PyRIT targets gain `close()` / context-manager support,
  and the AIX and DeepTeam adapters close their per-call HTTP sessions (#1).
- `__version__`, `oubliette-dungeon --version`, the API root, and the
  version stamped into benchmark / OSEF / HTML comparison reports now come
  from a single source that matches the package version (1.0.2 reported
  `1.0.1` or `1.0.0` depending on where you looked); guarded by
  `tests/unit/test_version_sync.py`.
- The `[pyrit]` extra depended on `pyrit-core`, which does not exist on PyPI,
  so `pip install oubliette-dungeon[pyrit]` could not resolve. It now depends
  on `pyrit>=0.8,<0.10`, the range whose API (`pyrit.orchestrator`,
  `pyrit.models.PromptRequestPiece`) the PyRIT adapter uses. Those PyRIT
  releases require Python < 3.14.
- **MITRE ATLAS mappings use real ATLAS v2026.06 techniques.** Scenario
  `mitre_mapping` lists, the OSEF category map, and the ATK-049 coverage block
  used codes that don't exist in ATLAS (`T0030`, `T0120`, `T0122`) or that
  name unrelated techniques (e.g. `T0061` is *LLM Prompt Self-Replication*, not
  jailbreak). Each scenario is now mapped by its described behaviour to full
  ATLAS IDs (`AML.T0051.000`), and compliance-testing scenarios stay unmapped.
  Imported garak/promptfoo scenarios get their category's ATLAS IDs instead of
  the ATT&CK ID `T1059`. The contrib garak probe tags and inspect_evals
  scenarios were corrected the same way. A vendored IDs-and-names list of the
  ATLAS release (`data/atlas_techniques.json`) and
  `tests/unit/test_atlas_ids.py` validate every emitted ID.

### Changed
- Releases publish to PyPI from `.github/workflows/publish.yml` via Trusted
  Publishing (OIDC) with PEP 740 attestations, gated by a packaging-boundary
  test (`tests/unit/test_packaging_boundary.py`) that allows only
  `oubliette_dungeon` package files in the wheel and sdist. It triggers only
  on `vX.Y.Z` tags, not the moving `v1` GitHub Action tag. Replaces
  `release.yml`.
- GitHub Actions in the workflows and the composite `action.yml` moved to
  Node 24 majors.
- CI builds the dashboard on Node.js 24 (was 20, which reached end of life on
  2026-04-30).

### Documentation
- Scenario counts now describe the two bundled sets accurately: the default
  library (`default.yaml`, 57 scenarios, 9 categories) that `run`, `stats`,
  and the APIs load, and the Crescendo multi-turn set (`crescendo.yaml`, 15
  scenarios), which is only loaded when passed with `--scenarios`. Together
  that is 72 scenarios in 10 categories. The README now documents the
  `DUNGEON_ALLOW_CUSTOM_SCENARIOS=true` opt-in that any non-default scenario
  file needs, and the per-difficulty and severity tallies in the YAML summary
  comments and the benchmark category table were corrected against the data.

## [1.0.2] - 2026-06-16

### Added
- **72 built-in attack scenarios across 10 categories** (up from 57/9): adds
  the `crescendo` multi-turn attack set (15 scenarios, new `multi_turn_attack`
  category) — gradual-escalation jailbreaks that single-turn tests miss.
- Open-core commercial layer (license / metering / auth / issuer / webhook).
- `[test]` extra bundling the flask + inspect integration dependencies.

### Changed
- Model registry refreshed to current flagships (Claude Opus 4.8, Gemini 3.5,
  GPT-5.5, Gemma 4).
- mypy-strict clean; ruff lint + format gates green.

## [1.0.0] - 2026-02-26

### Added
- Initial release as standalone package (extracted from oubliette-redteam)
- 57 built-in attack scenarios across 6 categories
- Click CLI with `run`, `stats`, `serve`, `demo`, `replay`, `export` commands
- React SPA dashboard with 6 pages (Command Center, Scenarios, Session Detail, Provider Comparison, Scheduler, Reports)
- Flask REST API at `/api/dungeon/`
- Refusal-aware result evaluation (reduces false positive bypasses)
- Honeypot-aware scoring (detects honey token decoys)
- Multi-turn attack support
- JSON file-based results storage with session indexing
- Cron-based job scheduler with webhook notifications
- PDF report generation
- Tool integrations: PyRIT, DeepTeam, AIX Framework, Garak
- Multi-provider comparison support
- Demo mode with mock LLM target and fixture data
- Docker support with multi-stage build
- CI/CD workflows for GitHub Actions
