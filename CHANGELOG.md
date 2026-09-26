# Changelog

All notable changes to oubliette-dungeon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - Unreleased

### Security
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

### Changed
- Releases publish to PyPI from `.github/workflows/publish.yml` via Trusted
  Publishing (OIDC) with PEP 740 attestations, gated by a packaging-boundary
  test (`tests/unit/test_packaging_boundary.py`) that allows only
  `oubliette_dungeon` package files in the wheel and sdist. It triggers only
  on `vX.Y.Z` tags, not the moving `v1` GitHub Action tag. Replaces
  `release.yml`.
- GitHub Actions in the workflows and the composite `action.yml` moved to
  Node 24 majors.

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
