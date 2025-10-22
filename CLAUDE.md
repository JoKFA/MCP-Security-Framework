# MCP Security Testing Framework

## Project Vision
Build a Metasploit-like tool for testing and exploiting MCP (Model Context Protocol) servers. The framework connects to MCP servers via stdio and HTTP/SSE, runs scripted security tests as a "fake agent," captures all interactions, and produces reproducible PoC reports.

---

## Current Phase: **Phase 2 - Security Assessment Framework (v0.2)** ✅

**Status:** Core framework complete! First detector operational and validated against DV-MCP Challenge 1.

**Next:** Implement reporting engines (JSON/SARIF/HTML) and CLI interface.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                 Test Runner (Core)              │
│  - Loads adapters                               │
│  - Orchestrates test execution                  │
│  - Handles timeouts/retries                     │
│  - Session management                           │
└─────────────────────────────────────────────────┘
                         │
          ┌──────────────┴──────────────┐
          │                             │
┌─────────▼─────────┐         ┌─────────▼─────────┐
│  stdio_adapter    │         │ http_sse_adapter  │
│  - stdin/stdout   │         │ - HTTP requests   │
│  - Process mgmt   │         │ - SSE streaming   │
│  - JSON-RPC       │         │ - Connection pool │
└───────────────────┘         └───────────────────┘
          │                             │
          └──────────────┬──────────────┘
                         │
                ┌────────▼────────┐
                │  Capture Store  │
                │  - NDJSON logs  │
                │  - Metadata     │
                │  - Timestamps   │
                └─────────────────┘
```

---

## Phase 1: Adapters (Current Focus)

### 1.1 McpClientAdapter (✅ Implemented)

**Primary adapter using the official MCP Python SDK**

**Responsibilities:**
- Connect to MCP servers via stdio or SSE transport
- Handle MCP protocol handshake and session management
- Execute MCP operations (list tools/resources, call tools, read resources)
- Capture all traffic in NDJSON format

**Key Features:**
- Uses official `mcp` Python SDK for robust protocol handling
- Supports both stdio and SSE transports
- Automatic session lifecycle management
- Full request/response capture with timestamps
- Works with real-world MCP servers (tested with DV-MCP)

**Interface:**
```python
class McpClientAdapter:
    async def connect() -> Dict[str, Any]
    async def list_tools() -> List[Dict[str, Any]]
    async def list_resources() -> List[Dict[str, Any]]
    async def call_tool(name: str, arguments: dict) -> Any
    async def read_resource(uri: str) -> Dict[str, Any]
    async def disconnect() -> None
    def save_capture(filepath: str) -> None
    def get_capture_log() -> List[Dict[str, Any]]
```

**Transport Configuration:**
```python
# SSE transport
adapter = McpClientAdapter(transport="sse", url="http://localhost:9001/sse")

# stdio transport
adapter = McpClientAdapter(
    transport="stdio",
    command="npx",
    args=["mcp-server-package"]
)
```

### 1.2 HttpSseAdapter (Legacy - for raw testing)

**Low-level HTTP/SSE adapter for protocol testing**

**Note:** This adapter is kept for direct protocol manipulation and edge case testing. For normal operations, use `McpClientAdapter` instead.

**Interface:**
```python
class HttpSseAdapter:
    def connect() -> Dict[str, Any]
    def send(message: dict) -> Dict[str, Any]
    def receive_stream(timeout: int) -> Generator[dict]
    def close() -> None
    def get_connection_info() -> dict
```

---

## Capture & Evidence Store

Every interaction is logged in **NDJSON** format:

```json
{"type": "connection", "ts": "2025-10-07T10:30:00Z", "adapter": "stdio", "config": {...}}
{"type": "request", "ts": "2025-10-07T10:30:01Z", "data": {"jsonrpc": "2.0", "method": "initialize", ...}}
{"type": "response", "ts": "2025-10-07T10:30:01.042Z", "data": {...}, "latency_ms": 42}
{"type": "error", "ts": "2025-10-07T10:30:05Z", "source": "stderr", "message": "..."}
{"type": "disconnect", "ts": "2025-10-07T10:30:10Z", "reason": "timeout"}
```

**Storage:**
- One `.ndjson` file per test session
- Indexed by SHA256 hash
- Bundled with metadata (server version, test config, findings)

---

## Lab Targets (For Testing Adapters)

1. **DV-MCP** (baseline) - Damn Vulnerable MCP reference implementation
2. **stdio test target** - Simple filesystem MCP (local process)
3. **http/sse test target** - Weather API MCP (remote server)

---

## Test Modules (Placeholder - Future Work)

Module categories:
- Protocol compliance
- Authentication/Authorization
- Resource abuse (DoS)
- Data validation (injection, path traversal)
- Information disclosure
- Session management

*Detailed module specs will be added after connection layer is stable.*

---

## Replay Engine (Future)

- Read NDJSON capture files
- Replay requests with variable substitution
- Support conditional flows
- Generate PoC scripts (Python/curl)

---

## Reporting (Future)

**MVP:** CLI output + JSON report
- Connection summary (success/fail/timeout)
- Message count, latency stats
- Captured errors/warnings

**Later:** Web dashboard, CVSS scoring, remediation guidance

---

## Development Phases

### ✅ Phase 1: Connection Layer (COMPLETED ✅)
- [x] Implement McpClientAdapter (primary adapter using official SDK)
- [x] Implement HttpSseAdapter (legacy raw HTTP adapter)
- [x] NDJSON capture working
- [x] Test against DV-MCP Challenge 1 (SSE transport)
- [x] Test against DV-MCP Challenge 2 (SSE transport)
- [x] Test stdio transport with official MCP Time Server
- [x] Successfully captured credentials leak and tool calls
- [x] Reorganize project structure (src/, examples/, docs/)
- [x] Create package files (LICENSE, pyproject.toml, etc.)

**Status:** Production-ready adapter, tested with 3 different MCP servers

---

### ✅ Phase 2: Security Assessment Framework (COMPLETED!)

**Goal:** Orchestrate test modules and automate vulnerability detection

#### 2A: Core Framework (Tasks T1-T5) ✅
- [x] **T1:** Core Pydantic models (DetectionStatus, Signal, DetectionResult, ServerProfile, AssessmentResult)
- [x] **T2:** Detector base class (`src/modules/base.py`) and auto-discovery registry
- [x] **T3:** TestRunner orchestration (`src/core/runner.py`) with timeout enforcement
- [x] **T4:** Policy engine (scope.yaml, rate limiter, redactor, audit logger)
- [x] **T5:** SafeAdapter wrapper with scope/rate/redaction enforcement

**Results:** 67 unit tests passing, complete safety guardrails implemented

#### 2B: Detectors (Tasks T6) ✅
- [x] **T6.1:** Prompt Injection via Resource Parameters detector (`MCP-2024-PI-001`)
  - Pattern-based sensitive resource detection
  - Signal emission (schema_overpermissive, sensitive_exposure)
  - Standards mapping (CWE-74, OWASP LLM01, CVSS 7.5 HIGH)
  - Successfully detected DV-MCP Challenge 1 with 95% confidence
  - Active PoC generation with unauthorized access demonstrations

- [x] **T6.2:** Credential Exposure Detector (`MCP-2024-CE-001`)
  - Pattern matching for secrets (passwords, API keys, tokens, connection strings)
  - Secret type classification and severity determination
  - Standards mapping (CWE-522, OWASP LLM01, OWASP API2, CVSS 8.2 HIGH)
  - Active PoC generation with redacted credential samples

**Results:** 80 unit tests + 1 integration test passing, 2 detectors operational!

#### 2C: Reporting & CLI (Tasks T7-T9) ✅ COMPLETED
- [x] **T7:** JSON and SARIF report generators
  - JSONReporter: Machine-readable with full evidence
  - SARIFReporter: SARIF 2.1.0 compliant for CI/CD integration
  - Proper enum handling for Signal types

- [x] **T8:** CLI report generator (human-readable structured output)
  - Detailed finding sections with standards mapping
  - Comprehensive PoC sections showing payload/response/leaked secrets
  - Color-coded terminal output (optional)
  - Plain text file output without ANSI codes

- [x] **T9:** Report bundle generation
  - ReportManager orchestrates all report formats
  - Complete assessment bundles with metadata
  - Proper folder organization:
    - `reports/` contains only bundles (report.json, report.txt, report.sarif, audit.jsonl, metadata.json)
    - `captures/` contains original audit logs
  - Audit log integrity tracking (SHA256 hash)

**Results:** Professional multi-format reporting system with actual PoC evidence!

---

### 📋 Phase 3: Additional Detectors (PLANNED)

**Goal:** Complete vulnerability coverage for all DV-MCP challenges

#### Module Roadmap (8 remaining modules):
1. [x] `credential_exposure_detector.py` - Challenge 1 ✅
2. [x] `prompt_injection_resource_params.py` - Challenge 1 ✅
3. [ ] `tool_poisoning_detector.py` - Challenge 2
4. [ ] `excessive_permissions_tester.py` - Challenge 3
5. [ ] `rug_pull_detector.py` - Challenge 4
6. [ ] `tool_shadowing_detector.py` - Challenge 5
7. [ ] `indirect_prompt_injection_tester.py` - Challenge 6
8. [ ] `token_theft_detector.py` - Challenge 7
9. [ ] `code_execution_exploit.py` - Challenge 8
10. [ ] `remote_access_tester.py` - Challenge 9

**Estimated effort:** 1 week (1-2 modules per day)

---

### 📋 Phase 4: Replay & Reporting (PLANNED)

**Goal:** Professional reporting and PoC generation

- [ ] NDJSON replay engine (re-run captured traffic)
- [ ] PoC bundle generation (Python scripts + evidence)
- [ ] HTML/PDF report generation
- [ ] CVSS scoring for findings
- [ ] Remediation recommendations
- [ ] Executive summary generation

---

### 📋 Phase 5: Advanced Features (FUTURE)

- [ ] Proxy support (mitmproxy integration)
- [ ] Web dashboard (Flask/FastAPI)
- [ ] CI/CD integration (GitHub Actions)
- [ ] Plugin system for custom modules
- [ ] Interactive mode (CLI like msfconsole)
- [ ] Database backend for result storage

---

## Notes & Decisions

**Why NDJSON?**
- Line-by-line streaming (no need to load full file)
- Easy to grep/filter
- Language-agnostic
- append-only (safe for concurrent writes)

**Why separate adapters?**
- MCP transports are fundamentally different (process vs HTTP)
- Easier to test in isolation
- Can add new transports (WebSocket, gRPC) without touching core

**Implementation Status:**
1. ✅ Python chosen for rapid prototyping
2. ✅ McpClientAdapter implemented using official MCP SDK
3. ✅ Successfully connected to DV-MCP and captured traffic
4. ✅ NDJSON evidence capture verified

**Example Capture Output:**
```json
{"type": "connection_attempt", "ts": "2025-10-08T05:25:50Z", "data": {"transport": "sse", "config": {"url": "http://localhost:9001/sse"}}}
{"type": "connection_established", "ts": "2025-10-08T05:25:51Z", "data": {"transport": "sse", "server_info": {"name": "Challenge 1 - Basic Prompt Injection", "version": "1.16.0"}, ...}}
{"type": "request", "ts": "2025-10-08T05:25:51Z", "data": {"method": "resources/read", "uri": "internal://credentials"}}
{"type": "response", "ts": "2025-10-08T05:25:51Z", "data": {"uri": "internal://credentials", "contents": [{"text": "Admin Password: super_secret_password123..."}]}}
```

**Completed Milestones (v0.2):**
1. ✅ Core framework with signal-based detection architecture
2. ✅ Complete safety guardrails (scope, rate limiting, redaction, audit logging)
3. ✅ Two operational detectors: Prompt Injection (MCP-2024-PI-001) + Credential Exposure (MCP-2024-CE-001)
4. ✅ Successfully detected DV-MCP Challenge 1 vulnerabilities (95% confidence)
5. ✅ Professional reporting system with 3 formats (JSON, SARIF 2.1.0, CLI/TXT)
6. ✅ Universal PoC generation across all detectors with actual evidence
7. ✅ 80 unit tests + integration test (100% passing)
8. ✅ Standards compliance (CWE, OWASP LLM/API, CVSS, ASVS)

**Next Steps (Phase 3: Additional Detectors):**
1. Implement tool_poisoning_detector.py for DV-MCP Challenge 2
2. Test against all 10 DV-MCP challenges
3. Build threat modeling engine (attack chain detection)
4. Add CLI interface with `mcpsf assess` command

**See:** `WEEKLY_REPORT_2025-10-15.md` for detailed progress report

---

*This document will evolve as we build. All architectural decisions and module specs will be documented here.*
