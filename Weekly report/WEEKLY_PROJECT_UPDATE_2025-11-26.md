# Weekly Project Update

**Project Title:** MCP Security Framework – Automated Vulnerability Assessment Tool for Model Context Protocol Servers
**Week #:** 10
**Date:** November 26, 2025
**Student:** Yaoting, Joshua, Tanish
**Instructor:** Mohammand

---

## 1. Summary

This week we completed the AMSAW v2 (Auto-Sandbox Wrapper) redesign, bringing automatic MCP assessment from any source (npm, GitHub, local directories) to production readiness. The new architecture eliminates manual configuration through intelligent discovery, containerized provisioning, and universal transport bridging. Additionally, we launched a Flask-based Web UI for browser-based assessments and implemented comprehensive error handling with actionable diagnostics.

---

## 2. Progress

### AMSAW v2 Core Infrastructure (Yaoting & Joshua - 2 weeks)

#### Phase 1: Discovery Engine (`src/core/discovery.py`)
- **AST-based MCP detection** for Python and Node.js projects using static analysis
- **Multi-source support**: npm packages (`@modelcontextprotocol/server-time`), GitHub repositories, local directories, and remote HTTPS URLs
- **Transport auto-detection** using AST visitor pattern (scoring stdio vs SSE signals)
- **Port and host binding detection** from source code patterns
- **Monorepo support** returning multiple `ServerConfig` objects from single repository

#### Phase 2: Container Provisioner (`src/core/provisioner.py`)
- **Runner Pattern** implementation: volume-mount code into pre-built fat Docker images (no build needed!)
- **Fat images built**: `mcp-runner-python:latest` (1.02GB) and `mcp-runner-node:latest` (622MB) with common dependencies pre-installed
- **Runtime dependency installation** via pip/npm (uv integration for fast Python installs)
- **CLI auto-detection** (`src/core/cli_detector.py`) parsing `--help` output to determine correct server invocation
- **Crash analysis loop** with 3-retry system detecting and auto-installing missing system dependencies (ffmpeg, pandoc, poppler-utils)
- **Host binding auto-fix** injecting `--host 0.0.0.0` when servers bind to localhost only
- **Mock provisioning** for PostgreSQL and MongoDB with auto-generated connection strings
- **Interactive credential prompting** allowing users to provide real API keys before falling back to mocks

#### Phase 3: Universal Bridge (`src/core/bridge.py`)
- **Sidecar pattern** using long-running `sleep infinity` containers for stable lifecycle management
- **stdio bridge**: FastAPI server wrapping `docker exec` sessions, exposing HTTP interface for stdio MCPs
- **SSE reverse proxy** forwarding HTTP requests to container-published ports
- **Smoke test** validation ensuring MCP initialize handshake succeeds before assessment
- **Transport normalization** presenting all MCPs as HTTP regardless of actual transport

#### Phase 0: Assessment Pipeline (`src/core/pipeline.py`)
- **End-to-end orchestration** coordinating Discovery → Provisioner → Bridge → TestRunner
- **Error handling** at each phase with graceful degradation
- **Progress reporting** with clear phase indicators and status messages

### Web UI Development (Joshua & Yaoting)

#### Flask Application (`web_view.py`)
- **Assessment interface** allowing users to input sources and configure profiles via web form
- **Report browsing** with directory-based navigation and file type filtering
- **Live progress** using Server-Sent Events for real-time assessment status updates
- **File viewer** supporting JSON, SARIF, TXT, and JSONL formats with syntax highlighting
- **Responsive design** using Tailwind CSS for mobile and desktop compatibility

#### Key Features
- **Multi-format report display** with collapsible JSON/SARIF trees
- **Report metadata** showing assessment dates, MCP names, and vulnerability counts
- **Download support** for individual report files
- **Navigation breadcrumbs** for easy report discovery

### Infrastructure & Quality (Yaoting - This Week)

#### Container Lifecycle Management
- **Container labeling system**: All MCPSF containers tagged with metadata (name, language, transport, creation timestamp)
- **Signal handlers** for graceful shutdown (SIGINT/SIGTERM) ensuring cleanup on Ctrl+C
- **Resource tracking** guaranteeing cleanup even on unexpected errors
- **`mcpsf cleanup` command**: New CLI command to scan and remove orphaned containers with age calculation

#### Error Handling Enhancements
- **Enhanced exception classes** with actionable suggestions:
  - `SourceDetectionError` explaining supported source types
  - `MCPNotFoundError` providing language-specific troubleshooting tips
  - `ProvisioningError` detecting Docker connectivity, missing images, port conflicts
- **Platform-specific guidance** for Docker startup (Windows/macOS/Linux)
- **Context-aware suggestions** analyzing error patterns to recommend fixes

#### Documentation Improvements
- **Prerequisites section** documenting system requirements (Python 3.11+, Docker 24+, Node 18+)
- **Known limitations** clarifying scope boundaries and success rate context
- **Contributing guidelines** streamlined with clearer workflow and tooling commands
- **Version management** centralized to prevent inconsistencies across CLI outputs

---

## 3. Issues / Blockers

| Issue | Impact | Resolution |
|-------|--------|------------|
| Node.js native modules fail inside container | Build errors on `npm install` for packages with `.node` binaries | Delete host `node_modules` before container install to force Linux recompilation |
| SSE servers binding to 127.0.0.1 unreachable from host | Container starts but bridge cannot connect | Auto-inject `--host 0.0.0.0` flag via crash analysis loop |
| Port detection inaccurate for CLI-configured servers | Wrong port causes connection failures | Pre-detection phase runs `--help` parsing before final container launch |
| Temporary containers not cleaned up on Ctrl+C | Orphaned containers accumulating | Signal handler + container labels + cleanup command |

All blockers resolved this week; no outstanding critical issues.

---

## 4. Plan for Next Week

1. **Performance benchmarking**: Measure end-to-end assessment time against <60s target for various MCP types
2. **Integration tests**: Add automated E2E tests for Discovery → Provisioner → Bridge pipeline
3. **Mock catalog expansion**: Populate `mocks.json` with top 10 MCP APIs (Stripe, AWS, GitHub, etc.)
4. **Web UI authentication**: Add basic auth option for production deployments (currently localhost-only)
5. **Batch assessment mode**: Extend Web UI to handle multiple targets with progress dashboard

---

## 5. Risk & Mitigation

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| AMSAW v2 untested on edge-case MCPs | Medium | Expand test coverage to include monorepos, multi-transport MCPs, and unusual CLI patterns |
| Container resource leaks on abnormal termination | Low | Signal handlers + labeled containers + cleanup command address this |
| Web UI lacks production hardening | High | Document as localhost-only; add authentication in next sprint |
| Performance target (<60s) may not hold for complex MCPs | Medium | Profile and optimize slowest phases (CLI detection, dependency install) |

---

## 6. Questions for Instructor / TA

1. Should AMSAW v2 support Windows containers, or is Linux-only Docker acceptable?
2. Is the Web UI sufficient for demo purposes, or should we prioritize security hardening?
3. Would you like end-to-end testing demonstrated during final presentation, or is documentation adequate?

---

## 7. Attachments / Links

- **Branch:** `main` (v0.4.0 released)
- **AMSAW v2 Core:**
  - `src/core/discovery.py` (698 lines) - Source discovery and AST analysis
  - `src/core/provisioner.py` (836 lines) - Container lifecycle and crash recovery
  - `src/core/bridge.py` (400+ lines) - Transport normalization
  - `src/core/pipeline.py` (272 lines) - End-to-end orchestration
  - `src/core/cli_detector.py` (200+ lines) - CLI auto-detection
- **Web UI:**
  - `web_view.py` (Flask application)
  - `templates/` (Jinja2 templates)
  - `static/` (CSS/JS assets)
- **Docker Images:**
  - `docker/mcp-runner-python.Dockerfile`
  - `docker/mcp-runner-node.Dockerfile`
- **Documentation:**
  - `docs/WRAPPER_GUIDE.md` - AMSAW v2 architecture
  - `docs/README.md` - Updated with prerequisites and limitations
  - `CONTRIBUTING.md` - Streamlined development workflow
- **Command Examples:**
  - `mcpsf assess @modelcontextprotocol/server-time` (npm package)
  - `mcpsf assess https://github.com/owner/repo/tree/main/src/mcp` (GitHub)
  - `mcpsf assess ./local/mcp-server` (local directory)
  - `mcpsf cleanup --force` (container management)
  - `python web_view.py` (launch Web UI)

---

## 8. Metrics Summary

| Metric | Value |
|--------|-------|
| Lines of code added (AMSAW v2) | ~2,400 |
| New CLI commands | 1 (`cleanup`) |
| Docker images built | 2 (Python, Node) |
| Source types supported | 4 (npm, GitHub, local, HTTPS) |
| Transport types supported | 2 (stdio, SSE) |
| Auto-provisioned mocks | 2 (PostgreSQL, MongoDB) |
| System dependencies auto-detected | 5 (ffmpeg, pandoc, poppler-utils, imagemagick, tesseract) |
| Crash recovery retry attempts | 3 per failure mode |
| Enhanced error classes | 3 (SourceDetectionError, MCPNotFoundError, ProvisioningError) |
| Signal handlers added | 2 (SIGINT, SIGTERM) |
| Web UI routes | 6 (index, assess, browse, view, status, download) |
| End-to-end tests passing | 9/9 (from test suite) |

---

## 9. Technical Highlights

### Discovery Engine Innovation
- **AST-based detection eliminates guesswork**: Scores stdio vs SSE transport by analyzing import patterns and function calls
- **Monorepo-aware**: Single GitHub URL can return multiple `ServerConfig` objects for repos with multiple MCPs
- **Zero configuration**: Automatically detects entry points, dependencies, and transport from code structure

### Provisioner Crash Recovery
- **Intelligent retry logic**: Parses error logs to detect missing dependencies (ffmpeg, pandoc) and installs them automatically
- **Host binding auto-fix**: Detects when servers listen on 127.0.0.1 and injects `--host 0.0.0.0` flag
- **Pre-detection optimization**: Runs CLI detection in temporary container to avoid wasteful recreations

### Bridge Architecture
- **Sidecar pattern** solves stdio lifecycle issues (servers exit after request but container stays alive)
- **Universal HTTP interface** means TestRunner never needs to change regardless of MCP transport
- **Binary stream handling** correctly parses Docker exec multiplexed output using struct header parsing

### Error Handling Philosophy
- **Context-aware suggestions**: Port conflicts recommend `mcpsf cleanup`, Docker issues show platform-specific startup commands
- **Fail-fast with guidance**: Errors include actionable next steps rather than generic messages
- **Progressive enhancement**: Warnings logged but don't block assessment unless critical

---

## 10. Additional Notes

### Testing Strategy
- **End-to-end validation**: All 9 test files (`test_*_mcp.py`) exercise AMSAW v2 pipeline with real sources
- **Manual testing**: Validated against Wikipedia MCP, Excel MCP, Markitdown MCP, Server-Time npm package
- **Regression prevention**: Signal handlers and cleanup verified with manual Ctrl+C interrupts

### Performance Observations
- **npm package assessment**: ~45s (download + install + assess)
- **GitHub clone assessment**: ~60s (clone + analyze + assess)
- **Local directory assessment**: ~30s (no download needed)
- **Bottlenecks identified**: npm install (15-20s), CLI detection (5-10s), dependency analysis (5s)

### Web UI Architecture
- **Server-Sent Events** for live progress updates avoid polling overhead
- **Tailwind CSS** for rapid UI development with minimal custom CSS
- **Report caching** via filesystem prevents re-assessment of completed targets
- **Security caveat**: Flask debug mode + no auth = localhost-only deployment

---

**Prepared By:** Yaoting
**Date:** November 26, 2025
