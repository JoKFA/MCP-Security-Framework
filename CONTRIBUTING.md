# Contributing to MCP Security Framework

Guidelines for building, testing, and releasing MCPSF (AMSAW v2 + detector engine + reporting).

## Table of Contents
- [Project Overview](#project-overview)
- [Development Setup](#development-setup)
- [Tooling & Commands](#tooling--commands)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing Expectations](#testing-expectations)
- [Development Workflow](#development-workflow)
- [Release & Versioning](#release--versioning)
- [What to Commit / Ignore](#what-to-commit--ignore)
- [Getting Help](#getting-help)

## Project Overview

MCP Security Framework automatically sandboxes MCP servers (AMSAW v2), runs 14 security detectors, and generates JSON/SARIF/CLI reports. The CLI (`mcpsf.py`) and Flask web view (`web_view.py`) are the primary entry points.

## Development Setup

Prerequisites:
- Python 3.11+ (tested on 3.11/3.12)
- Node.js 18+ with `npm`
- Docker 24+ (required for sandboxing/provisioning)
- Git

Steps:
1. Clone and enter the repo:
   ```bash
   git clone https://github.com/yourorg/mcp-security-framework
   cd mcp-security-framework
   ```
2. Create a virtualenv and install dependencies (dev extras include lint/format/test):
   ```bash
   python -m venv .venv
   . .venv/Scripts/Activate.ps1  # Windows
   # or source .venv/bin/activate
   pip install -e .[dev]
   ```
3. Verify Docker is running: `docker info`
4. Optional: install `uv` if you prefer `uv pip install -e .[dev]`.

## Tooling & Commands

- Lint: `ruff check .`
- Format: `black .`
- Unit tests: `pytest tests/unit/`
- Integration/e2e (Docker required): `pytest tests/integration/` and `python tests/test_challenge1.py`
- Smoke a target: `python mcpsf.py assess targets/vulnerable/dv-mcp/challenges/easy/challenge1`

## Project Structure

```
.
├── docs/                  # Product and technical docs
├── src/                   # Framework code (discovery, provisioner, bridge, detectors)
├── tests/                 # Unit + integration + e2e harnesses
├── examples/              # Sample usages
├── scripts/               # Helper scripts
├── docker/                # Dockerfiles/assets for runner images
├── templates/, static/    # Web view assets
├── mcpsf.py               # CLI entry point
├── web_view.py            # Flask web UI
├── captures/, reports/    # Generated output (gitignored)
└── targets/               # Test targets (local, gitignored)
```

## Coding Standards

- Use type hints where practical; prefer clear, small functions.
- Formatting: `black` (line length 100).
- Linting: `ruff` (line length 100). Fix warnings or add targeted ignores with justification.
- Logging: prefer structured/contextual messages over prints.
- Security: avoid widening sandbox scope; document any privileged operations.

## Testing Expectations

Run before sending a PR (as applicable):
- `ruff check .`
- `black .` (or ensure clean diff after formatting)
- `pytest tests/unit/`
- `pytest tests/integration/` (needs Docker)
- E2E spot checks when touching detectors/provisioning:
  - `python tests/test_challenge1.py`
  - `python tests/test_challenge2.py`
  - `python tests/test_wikipedia_mcp.py`

For new features/bug fixes:
- Add/adjust unit tests.
- Add integration/E2E coverage if behavior spans Docker provisioning, bridge, or detectors.

## Development Workflow

- Branch naming: `feature/<name>` or `fix/<name>`.
- Keep changes scoped and tested; include rationale in PR descriptions.
- Prefer small, focused commits; conventional-style prefixes (`Add/Update/Fix/Docs/Test`) are fine.
- When touching security-sensitive areas (sandboxing, detectors), include a short risk note in the PR.

## Release & Versioning

1. Bump versions:
   - `pyproject.toml` `[project].version`
   - Front-matter version and dates in user-facing docs (e.g., `docs/README.md`, `docs/DOCUMENTATION_INDEX.md`, `docs/ARCHITECTURE.md`, `docs/WRAPPER_GUIDE.md`, `docs/DETECTORS_GUIDE.md`, `docs/REPORTS_GUIDE.md`, `docs/API_REFERENCE.md`, `WEB_VIEW_README.md`).
2. Update metrics/status claims if they changed (e.g., detector count, success rate).
3. Run and record validation:
   - `ruff`, `black`, `pytest tests/unit/`, `pytest tests/integration/`
   - E2E: `tests/test_challenge1.py`, `tests/test_challenge2.py`, `tests/test_wikipedia_mcp.py`
   - Refresh `TEST_RESULTS.md` if release validation changes.
4. Tag and publish:
   ```bash
   git tag vX.Y.Z
   git push origin main --tags
   ```

## What to Commit / Ignore

Include:
- Source (`src/`, `mcpsf.py`, `web_view.py`, `scripts/`, `examples/`, `templates/`, `static/`)
- Tests and docs (`tests/`, `docs/`, `WEB_VIEW_README.md`, `TEST_RESULTS.md`)
- Config (`pyproject.toml`, `docker/`, `.gitignore`)

Exclude (already gitignored, keep it that way):
- Generated artifacts (`captures/`, `reports/`, `__pycache__/`, `.pytest_cache/`)
- Local environments (`.venv/`, `env/`)
- Test targets (`targets/` contents)

## Getting Help

- Open an issue with `documentation`, `bug`, or `feature` labels as appropriate.
- For security-sensitive issues, follow the repo security policy if present; otherwise, use private channels before disclosure.
