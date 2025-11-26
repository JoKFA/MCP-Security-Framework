# MCP Test Playbook – Ten-Server Batch (2025-11-05)

This note captures exactly how the latest MCP regression sweep was executed so anyone on the team can reproduce or spot check the runs.

---

## 1. Targets Exercised

| Category | Server | Location | Transport | Notes |
|----------|--------|----------|-----------|-------|
| Official Samples | `mcp-simple-tool`, `mcp-simple-resource`, `mcp-simple-prompt`, `mcp-simple-pagination` | `targets/python-sdk/examples/servers/...` | stdio | Each lives in its own virtualenv (`.venv/`) under the sample directory. |
| Utilities | `zcaceres/fetch`, `glaucia86/todo-list`, `haris-musa/excel-mcp`, `Rudra-ravi/wikipedia` | `targets/{fetch-mcp,todo-list-mcp-server,excel-mcp-server,wikipedia-mcp}` | stdio | Node repos use `npm install`; Python repos use `.venv` + `pip install -e .`. |
| Vulnerable Cases | `Sunwood-ai-labs/command-executor` `v0.1.0`, `48Nauts-Operator/hubble` `v1.3.1` | `targets/{command-executor-mcp-server,hubble}` | stdio | Both intentionally contain documented flaws; additional deps (`sqlite3`, `sqlite`) installed via `npm`. |
| Templated CLI | `@starwind-ui/mcp` | `npx` (no repo checkout required) | stdio | Invoked via `npx -y @starwind-ui/mcp --transport stdio`. SSE run attempted but stdio output already sufficient. |

All servers were launched sequentially; only one MCP instance was active at any given time to keep logs clean and avoid port conflicts.

---

## 2. Environment Prep

1. **Python samples**  
   ```powershell
   python -m venv targets\python-sdk\examples\servers\<sample>\.venv
   targets\...\<sample>\.venv\Scripts\python -m pip install --upgrade pip
   Set-Location targets\python-sdk\examples\servers\<sample>
   .venv\Scripts\python -m pip install -e .
   ```

2. **Node-based servers**  
   ```powershell
   cmd /c "cd targets\<repo> && npm install"
   ```
   - `command-executor-mcp-server` already ships built JS: run from `build/index.js`.
   - `hubble` required extra `npm install sqlite3` and `npm install sqlite`.
   - `@starwind-ui/mcp` executed directly via `npx`, so no local install is needed.

3. **Ensure clean stdout**  
   - Some servers print banners/logs. Mcpsf tolerates this, but expect occasional `UNKNOWN` statuses (Starwind UI, fetch). No action taken for this run.
   - After each test, `Get-Process node | Stop-Process -Force` cleans up leftover stdio transports.

---

## 3. Running Assessments

All runs use the mcpsf CLI in aggressive mode. Pattern:

```powershell
python mcpsf.py assess <target> --mode aggressive --output reports/<NAME>
```

Sample invocations:

```powershell
# Simple Tool
python mcpsf.py assess `
  stdio://targets\python-sdk\examples\servers\simple-tool\.venv\Scripts\python.exe/-m/mcp_simple_tool `
  --mode aggressive --output reports/SIMPLE_TOOL

# Todo List (Node)
python mcpsf.py assess `
  stdio://node/targets\todo-list-mcp-server\dist\index.js `
  --mode aggressive --output reports/TODO_LIST

# Wikipedia (Python CLI wrapper)
python mcpsf.py assess `
  stdio://targets\wikipedia-mcp\.venv\Scripts\python.exe/-m/wikipedia_mcp/--transport/stdio `
  --mode aggressive --output reports/WIKIPEDIA_MCP
```

Reports (JSON, SARIF, TXT, audit logs) land in `reports/<NAME>/`.

---

## 4. Outcome Snapshot

| Folder | Key Findings |
|--------|--------------|
| `SIMPLE_TOOL` | Expected `Excessive Permissions`, `Unauthenticated Access` (CRITICAL). |
| `SIMPLE_RESOURCE` / `SIMPLE_PROMPT` | Clean baselines (no findings). |
| `SIMPLE_PAGINATION` | `Unauthenticated Access` (CRITICAL) only. |
| `TODO_LIST` | Multiple issues (Excessive Permissions, Indirect Injection, Rug Pull, Tool Enumeration, UA). |
| `FETCH_MCP` | Exposed to EP, Indirect Injection, and UA; two detectors flagged UNKNOWN due to stdout chatter. |
| `EXCEL_MCP` | Broad coverage: EP, Indirect Injection, Tool Poisoning, Tool Shadowing, Tool Enumeration, UA. |
| `COMMAND_EXECUTOR` | Tool Enumeration + UA (command injection surface confirmed). |
| `HUBBLE` | EP, Indirect Injection, UA after adding sqlite deps. |
| `STARWIND_UI` | EP, Indirect Injection, Rug Pull, Tool Enumeration, UA (unknowns caused by lock-file logging). |
| `WIKIPEDIA_MCP` | EP, Indirect Injection, Rug Pull, Tool Enumeration, UA (expected for public API server). |

No false positives observed on the “clean” samples; known vulnerable targets tripped the expected detectors. A handful of benign `UNKNOWN` statuses appear where servers emit plain text before the JSON handshake.

---

## 5. Suggested Follow‑Ups

- **Wrapper scripts**: add convenience launchers (PowerShell or batch) per server so the CLI command boils down to `python mcpsf.py assess stdio://scripts/run-fetch.cmd ...`.
- **Stdout hygiene**: patch or redirect noisy servers (Starwind UI, fetch, Hubble) to reduce `UNKNOWN` results.
- **Expectation tracking**: maintain a table of “expected detectors” per MCP so new runs can be diffed automatically against baselines.

This document should give teammates enough context to rerun or extend the test matrix without retracing setup steps. Let me know if anything needs more detail.

