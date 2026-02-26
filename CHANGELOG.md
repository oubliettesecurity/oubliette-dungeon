# Changelog

All notable changes to oubliette-dungeon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
