# MCP Security Framework - System Architecture

**Version:** 0.4.0
**Last Updated:** 2025-11-24
**Audience:** Everyone (developers, security engineers, DevOps)

---

## Table of Contents

1. [Overview](#overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Component Details](#component-details)
4. [Data Flow](#data-flow)
5. [Design Principles](#design-principles)
6. [Technology Stack](#technology-stack)

---

## Overview

The MCP Security Framework (MCPSF) is a **5-phase pipeline** that automatically sandboxes, normalizes, and security-tests MCP servers from any source.

### Key Innovation: AMSAW v2

**Automatic MCP Sandbox And Wrapper (AMSAW v2)** is the infrastructure layer (Phases 1-3) that enables testing ANY MCP server without manual configuration:

- **Before AMSAW v2:** Users had to manually configure Docker, write entry commands, and handle transport differences
- **After AMSAW v2:** Just provide a source → system does everything automatically

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          User Interface                              │
│                                                                      │
│  CLI: python mcpsf.py assess <source>                               │
│  Python API: AssessmentPipeline().run(source)                       │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     PHASE 1: Discovery Engine                        │
│                       (src/core/discovery.py)                        │
│                                                                      │
│  Input:  User-provided source string                                │
│  Output: List[ServerConfig] (language, transport, entry point)      │
│                                                                      │
│  Key Components:                                                     │
│  • SourceDiscovery: Detect source type (npm/github/local/https)     │
│  • AST Analyzers: Parse Python/Node.js code to find MCP servers     │
│  • TransportAnalyzer: Detect stdio vs SSE from code structure       │
│  • HostPortDetector: Extract host/port bindings from AST            │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   PHASE 2: Container Provisioner                     │
│                     (src/core/provisioner.py)                        │
│                                                                      │
│  Input:  ServerConfig                                                │
│  Output: Running Docker container + normalized URL                  │
│                                                                      │
│  Key Components:                                                     │
│  • ContainerProvisioner: Manages Docker lifecycle                   │
│  • DependencyInstaller: uv/npm dependency management                │
│  • CLIDetector: Auto-detects correct CLI syntax                     │
│  • CrashAnalysisLoop: Retries with auto-fixes for common errors     │
│                                                                      │
│  Docker Images Used:                                                 │
│  • mcp-runner-python:latest (Python 3.11 + uv + common libs)        │
│  • mcp-runner-node:latest (Node.js 22 + npm + common packages)      │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    PHASE 3: Universal Bridge                         │
│                        (src/core/bridge.py)                          │
│                                                                      │
│  Input:  Docker container + transport type                          │
│  Output: Normalized HTTP URL                                        │
│                                                                      │
│  Transport Normalization:                                            │
│  • stdio → HTTP: FastAPI bridge wrapping docker exec                │
│  • SSE → HTTP: Reverse proxy with port mapping                      │
│  • Smoke Test: Verify MCP responds to initialize                    │
│                                                                      │
│  Why: Detectors expect uniform HTTP interface                       │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                  PHASE 4: Security Assessment                        │
│              (src/core/runner.py + src/modules/*)                    │
│                                                                      │
│  Input:  Normalized HTTP URL                                        │
│  Output: List[DetectionResult] (vulnerabilities found)              │
│                                                                      │
│  Key Components:                                                     │
│  • TestRunner: Orchestrates detector execution                      │
│  • SafeAdapter: Rate limiting, scope enforcement, redaction         │
│  • McpClientAdapter: MCP SDK protocol handler                       │
│  • 14 Detectors: Vulnerability-specific testing modules             │
│                                                                      │
│  Detectors:                                                          │
│  1. MCP-2024-PI-001: Prompt Injection via Resource Parameters       │
│  2. MCP-2024-TP-001: Tool Poisoning Detector                        │
│  3. MCP-2024-CE-001: Credential Exposure Detector                   │
│  4. MCP-2024-CI-001: Command Injection Detector                     │
│  5. MCP-2024-CEX-001: Code Execution Detector                       │
│  6. ... and 9 more detectors                                        │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    PHASE 5: Report Generation                        │
│                  (src/core/reporters/manager.py)                     │
│                                                                      │
│  Input:  AssessmentResult                                            │
│  Output: Multi-format reports                                       │
│                                                                      │
│  Report Formats:                                                     │
│  • report.json: Machine-readable results                            │
│  • report.sarif: GitHub Security Tab format                         │
│  • report.txt: Human-readable CLI output                            │
│  • audit.jsonl: Detailed request/response log                       │
│  • metadata.json: Assessment metadata                               │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### Phase 1: Discovery Engine

**Purpose:** Automatically detect MCP servers from various sources without user configuration.

**Source Types Supported:**
```python
# npm packages
"@modelcontextprotocol/server-time"
"sqlite-mcp-server"

# GitHub repositories
"https://github.com/modelcontextprotocol/servers/tree/main/src/time"

# Local directories
"./targets/vulnerable/dv-mcp/challenges/easy/challenge1"
"/absolute/path/to/mcp-project"

# Remote URLs (already running)
"https://api.example.com:9001/sse"
"http://localhost:8080/sse"
```

**Detection Strategy:**
1. **Source Type Detection:**
   - npm: Starts with `@` or matches `[a-z0-9-]+`
   - GitHub: Contains `github.com`
   - Local: Path exists on filesystem
   - Remote: Starts with `http://` or `https://`

2. **Language Detection:**
   - Python: Look for `pyproject.toml`, `requirements.txt`, `*.py` files
   - Node.js: Look for `package.json`, `*.js`, `*.ts` files

3. **AST Analysis (Python):**
```python
# Detects this code pattern:
import mcp.server.sse
uvicorn.run(app, host="0.0.0.0", port=9001)

# Extracts:
# - Transport: SSE (from mcp.server.sse import)
# - Host: "0.0.0.0" (from uvicorn.run call)
# - Port: 9001 (from uvicorn.run call)
# - Entry point: ["python", "-m", "module_name"]
```

4. **AST Analysis (Node.js):**
```javascript
// Detects this code pattern:
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

// Extracts:
// - Transport: SSE (from SSEServerTransport import)
// - Entry point: ["node", "dist/index.js"] or ["npx", "-y", "package"]
```

**Output Data Structure:**
```python
@dataclass
class ServerConfig:
    name: str                           # "server-time"
    source_type: str                    # "npm" | "github" | "local" | "https"
    language: str                       # "python" | "nodejs"
    entry_point: List[str]              # ["npx", "-y", "@mcp/server-time"]
    transport: str                      # "stdio" | "sse"
    dependencies: List[str]             # ["fastapi", "uvicorn"]
    env_vars: Dict[str, Optional[str]]  # {"API_KEY": None}
    sse_port: Optional[int]             # 9001
    sse_host: Optional[str]             # "0.0.0.0"
    project_root: Optional[Path]        # /path/to/project
```

---

### Phase 2: Container Provisioner

**Purpose:** Launch MCP server in isolated Docker container with all dependencies.

**Key Features:**
1. **Fat Images (Pre-built):**
   - `mcp-runner-python:latest`: Python 3.11 + uv + common libraries
   - `mcp-runner-node:latest`: Node.js 22 + npm + common packages
   - No build time! Just volume-mount code and install missing deps

2. **Volume Mounting Strategy:**
```bash
# Volume mount project directory
docker run -v /host/project:/app mcp-runner-python

# Install dependencies at runtime (fast!)
docker exec container uv sync          # Python (~5s)
docker exec container npm install      # Node.js (~10s)
```

3. **CLI Auto-Detection:**
```python
# System tries multiple CLI patterns:
python -m module --sse --port 9001 --host 0.0.0.0  # ✅ Works!
python -m module --http --port 9001                # ❌ Fails
python -m module sse                               # ❌ Fails

# Returns working command for later use
```

4. **Crash Analysis Loop:**
```python
for attempt in range(3):
    try:
        start_server()
        break
    except ServerCrashError as e:
        if "ffmpeg" in error:
            install_ffmpeg()
        elif "port already in use" in error:
            kill_old_process()
        elif "host 127.0.0.1" in error:
            inject_host_binding("0.0.0.0")
        else:
            raise  # Unknown error
```

**Output:** Running Docker container with MCP server listening on mapped port.

---

### Phase 3: Universal Bridge

**Purpose:** Normalize all MCP transports to HTTP for uniform detector interface.

**Why Needed:**
- Detectors expect HTTP endpoints
- stdio MCP uses stdin/stdout (not HTTP)
- SSE MCP uses HTTP but might bind to localhost (unreachable from host)

**Bridge Strategies:**

**For stdio Transport:**
```python
# FastAPI bridge wrapping docker exec
@app.post("/message")
async def proxy_message(request: MCPRequest):
    # Run: docker exec container python -m module
    # Send request.json to stdin
    # Read response from stdout
    # Return as HTTP response
```

**For SSE Transport:**
```python
# Simple reverse proxy with port mapping
Container: 127.0.0.1:9001 (unreachable from host)
              ↓
Docker port map: host:53075 -> container:9001
              ↓
Bridge proxy: host:60028 -> host:53075
              ↓
Detectors connect to: http://localhost:60028/sse
```

**Smoke Test:**
```python
# Verify MCP responds correctly
response = requests.post(bridge_url + "/message", json={
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {"protocolVersion": "2024-11-05"}
})
assert response.status_code == 200
assert "serverInfo" in response.json()["result"]
```

**Output:** `http://localhost:<port>/sse` or `http://localhost:<port>/message`

---

### Phase 4: Security Assessment

**Purpose:** Detect vulnerabilities in MCP server using 14 specialized detectors.

**Architecture:**
```
TestRunner (Orchestrator)
    ↓
SafeAdapter (Safety Layer)
    - Rate limiting: Max 10 req/sec
    - Scope enforcement: Only allowed domains/paths
    - Response redaction: Remove API keys, passwords
    ↓
McpClientAdapter (MCP Protocol)
    - Handles MCP handshake
    - Tool/resource/prompt listing
    - Tool execution
    ↓
MCP Server (Target)
```

**Detector Categories:**

| Category | Detectors | Description |
|----------|-----------|-------------|
| **Injection** | PI, II, CI, CEX | Prompt/command/code injection attacks |
| **Data Exposure** | CE, IS | Credential leaks, insecure storage |
| **Access Control** | UA, EP, PA | Authentication, excessive permissions |
| **Tool Attacks** | TP, TS, RUG | Tool poisoning, shadowing, behavior changes |
| **Enumeration** | TE | Information gathering |

**Detector Lifecycle:**
1. **Initialize:** Detector reads ServerProfile (tools, resources, capabilities)
2. **Execute:** Detector performs test (e.g., inject payload, observe response)
3. **Analyze:** Detector checks for vulnerability indicators
4. **Report:** Detector returns DetectionResult with evidence

**Safety Guardrails:**
```python
# SafeAdapter enforces these rules:
- Max 100 tool calls per assessment
- Max 10 requests/second
- Only access domains in scope.yaml
- Redact patterns: API_KEY=*, password:*, Bearer *
```

---

### Phase 5: Report Generation

**Purpose:** Generate multi-format reports for different audiences.

**Report Formats:**

**1. JSON (report.json) - For CI/CD**
```json
{
  "summary": {
    "present": 4,
    "absent": 10,
    "error": 0
  },
  "results": [
    {
      "detector_id": "MCP-2024-PI-001",
      "status": "PRESENT",
      "confidence": 0.95,
      "evidence": {
        "injected_payload": "<malicious>",
        "response_indicators": ["<script>"]
      },
      "standards": {
        "cvss": {
          "score": 8.1,
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "severity": "HIGH"
        },
        "cwe": ["CWE-79", "CWE-94"]
      }
    }
  ]
}
```

**2. SARIF (report.sarif) - For GitHub Security**
```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "MCP Security Framework",
          "version": "0.4.0"
        }
      },
      "results": [
        {
          "ruleId": "MCP-2024-PI-001",
          "level": "error",
          "message": {
            "text": "Prompt Injection via Resource Parameters"
          },
          "locations": [...]
        }
      ]
    }
  ]
}
```

**3. CLI (report.txt) - For Humans**
```
======================================================================
  ASSESSMENT COMPLETE (26.7s)
======================================================================
  Vulnerabilities: 4
  Detectors Run: 14
======================================================================

[HIGH] MCP-2024-PI-001: Prompt Injection via Resource Parameters
  Description: Server accepts unvalidated resource parameters...
  Evidence: Injected "<script>alert(1)</script>" → Reflected in response
  Recommendation: Validate and sanitize all resource parameters

[MEDIUM] MCP-2024-TP-001: Tool Poisoning Detector
  Description: Tool descriptions contain hidden instructions...
```

**4. Audit Log (audit.jsonl) - For Analysis**
```jsonl
{"timestamp": "2025-11-24T12:00:01", "method": "initialize", "request": {...}, "response": {...}}
{"timestamp": "2025-11-24T12:00:02", "method": "tools/list", "request": {...}, "response": {...}}
{"timestamp": "2025-11-24T12:00:03", "method": "tools/call", "tool": "read_file", "args": {"path": "/etc/passwd"}, "response": {...}}
```

---

## Data Flow

### Complete Assessment Flow

```
1. User Input
   python mcpsf.py assess targets/vulnerable/dv-mcp/challenges/easy/challenge1

2. Discovery (5s)
   ✓ Detected source type: local
   ✓ Detected language: Python
   ✓ Detected transport: SSE
   ✓ Detected host: 0.0.0.0, port: 9001
   → ServerConfig(name="dv-mcp", transport="sse", ...)

3. Provisioning (15s)
   ✓ Launched container: 79fc04981de8
   ✓ Installed dependencies: uv sync
   ✓ Started MCP server: http://127.0.0.1:53075/sse
   → Running container + URL

4. Bridge (2s)
   ✓ SSE probe succeeded
   ✓ Reverse proxy: localhost:60028 -> 127.0.0.1:53075
   → Normalized URL: http://localhost:60028/sse

5. Assessment (25s)
   ✓ Loaded 14 detectors
   ✓ Running MCP-2024-PI-001... PRESENT (HIGH)
   ✓ Running MCP-2024-TP-001... ABSENT
   ✓ Running MCP-2024-CE-001... ABSENT
   ... (11 more detectors)
   → AssessmentResult(present=4, absent=10)

6. Reporting (1s)
   ✓ Generated report.json
   ✓ Generated report.sarif
   ✓ Generated report.txt
   ✓ Generated audit.jsonl
   → Reports saved to: reports/dv-mcp_20251124_120045/

7. Cleanup (1s)
   ✓ Stopped container: 79fc04981de8
   ✓ Removed container
   → Cleanup complete

Total Time: 49s
Exit Code: 1 (vulnerabilities found)
```

---

## Design Principles

### 1. Separation of Concerns

- **Discovery:** Doesn't know about Docker
- **Provisioner:** Doesn't know about detectors
- **Bridge:** Doesn't know about vulnerabilities
- **Detectors:** Don't know about sandboxing

Each phase is independently testable.

### 2. Fail-Fast with Retry

- Discovery fails immediately on non-MCP projects
- Provisioner retries up to 3 times with auto-fixes
- Bridge fails fast if smoke test doesn't pass
- Detectors don't retry (results should be deterministic)

### 3. Deterministic Results

- Same source → Same ServerConfig (AST-based, no guessing)
- Same MCP → Same vulnerabilities (no randomness in detectors)
- Reproducible assessments (audit logs capture all traffic)

### 4. Zero Trust Security

- All MCPs run in isolated Docker containers
- SafeAdapter enforces rate limits and scope
- Response redaction prevents credential leaks
- No network access to host filesystem

### 5. Performance First

- Pre-built fat images (no Docker build)
- Volume mounting (no file copying)
- Parallel detector execution where possible
- Aggressive caching (npm packages, dependency installs)

---

## Technology Stack

### Core Languages
- **Python 3.11+** (asyncio, typing, dataclasses)
- **Node.js 22+** (for Node.js MCP support)

### Key Libraries

**Python:**
- `mcp` (MCP SDK)
- `docker-py` (Docker API)
- `fastapi` + `uvicorn` (Bridge server)
- `pytest` (Testing)
- `pydantic` (Data validation)

**Node.js:**
- `@modelcontextprotocol/sdk` (MCP SDK)

### Infrastructure
- **Docker** (Container isolation)
- **uv** (Fast Python dependency management)
- **npm** (Node.js package management)

### Standards
- **MCP Protocol:** v2024-11-05
- **SARIF:** v2.1.0
- **CVSS:** v3.1
- **CWE** (Common Weakness Enumeration)
- **OWASP LLM Top 10 / API Security Top 10**

---

## Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| **Discovery Time** | 5-10s | AST parsing + npm package downloads |
| **Provisioning Time** | 10-20s | Container start + dependency install |
| **Bridge Setup** | 1-3s | Port mapping + smoke test |
| **Assessment Time** | 20-60s | 14 detectors running in sequence |
| **Report Generation** | <1s | JSON/SARIF/CLI generation |
| **Total Time** | 30-90s | End-to-end assessment |

**Bottlenecks:**
- npm package downloads (network-bound)
- Python dependency installation (CPU-bound)
- Some detectors make many requests (rate-limited)

**Optimization Opportunities:**
- Parallel detector execution (currently sequential)
- Dependency caching (Docker volumes)
- npm package caching (local mirror)

---

## Scalability

### Current Limitations
- **Single-threaded:** One assessment at a time
- **Local only:** Runs on single machine
- **No distributed testing:** Can't split detectors across machines

### Future Enhancements
- **Worker pool:** Parallel assessments
- **Remote executors:** Kubernetes-based provisioning
- **Cloud storage:** Centralized report storage

---

## Conclusion

The MCP Security Framework's architecture is designed for:
- **Ease of use:** Zero-config automatic sandboxing
- **Security:** Multi-layer isolation and safety guardrails
- **Extensibility:** Easy to add new detectors and source types
- **Performance:** Fast enough for CI/CD integration
- **Reliability:** Deterministic results and comprehensive error handling

**Next Steps:**
- Read [Wrapper Guide](WRAPPER_GUIDE.md) for AMSAW v2 implementation details
- Read [Detectors Guide](DETECTORS_GUIDE.md) for vulnerability detection specifics
- Read [API Reference](API_REFERENCE.md) for integration examples
