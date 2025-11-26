# AMSAW v2 Wrapper Guide

**Version:** 0.4.0
**Last Updated:** 2025-11-24
**Audience:** Developers, DevOps Engineers

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Phase 1: Discovery Engine](#phase-1-discovery-engine)
4. [Phase 2: Container Provisioner](#phase-2-container-provisioner)
5. [Phase 3: Universal Bridge](#phase-3-universal-bridge)
6. [Docker Images](#docker-images)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Usage](#advanced-usage)

---

## Overview

**AMSAW v2** (Automatic MCP Sandbox And Wrapper) is the infrastructure layer that enables zero-configuration security testing of MCP servers from any source.

### What Problem Does It Solve?

**Before AMSAW v2:**
```bash
# User had to:
1. Clone the MCP repository
2. Install dependencies (Python/Node.js)
3. Figure out the correct command to run
4. Handle transport differences (stdio vs SSE)
5. Expose the server on the correct host/port
6. Deal with missing system dependencies (ffmpeg, etc.)
7. Write Docker configuration manually
```

**After AMSAW v2:**
```bash
# User only needs to:
python mcpsf.py assess @modelcontextprotocol/server-time

# System automatically:
✅ Detects it's an npm package
✅ Downloads and analyzes the code
✅ Provisions a Docker container
✅ Installs all dependencies
✅ Figures out the correct command
✅ Handles transport normalization
✅ Auto-fixes common errors
✅ Runs security tests
```

### Key Principles

1. **Zero Configuration** - Works out of the box
2. **Deterministic** - Same source → Same result
3. **Fast** - 10-20s setup time
4. **Isolated** - All tests run in Docker
5. **Resilient** - Auto-recovers from common errors

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User Input (Source)                      │
│  npm | GitHub | Local | URL                                 │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 1: Discovery Engine (src/core/discovery.py)         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SourceDiscovery.discover(source) → ServerConfig     │   │
│  │                                                      │   │
│  │ Steps:                                               │   │
│  │ 1. Detect source type (npm/github/local/url)        │   │
│  │ 2. Download/clone if needed                         │   │
│  │ 3. Analyze AST (Python/Node.js)                     │   │
│  │ 4. Extract entry point, transport, deps             │   │
│  │ 5. Detect host/port bindings                        │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ ServerConfig
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 2: Container Provisioner (src/core/provisioner.py)  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ ContainerProvisioner.provision(config) → Container  │   │
│  │                                                      │   │
│  │ Steps:                                               │   │
│  │ 1. Pull fat image (mcp-runner-python/node)          │   │
│  │ 2. Volume-mount source code                         │   │
│  │ 3. Install dependencies (uv/npm)                    │   │
│  │ 4. Auto-detect CLI syntax                           │   │
│  │ 5. Start MCP server                                 │   │
│  │ 6. Crash analysis loop (retry with fixes)           │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ Running Container + URL
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Phase 3: Universal Bridge (src/core/bridge.py)            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ UniversalBridge.start() → Normalized HTTP URL       │   │
│  │                                                      │   │
│  │ Transport Normalization:                             │   │
│  │ • stdio → HTTP (FastAPI bridge)                     │   │
│  │ • SSE → HTTP (reverse proxy)                        │   │
│  │ • Smoke test (verify MCP responds)                  │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ Normalized HTTP URL
                         ▼
                   Security Assessment
                (Existing detection engine)
```

---

## Phase 1: Discovery Engine

### Purpose

Automatically detect MCP servers in various source types without manual configuration.

### Source Types

#### 1. npm Packages

**Detection:**
```python
# Pattern: @scope/package or package-name
if source.startswith("@") or re.match(r'^[a-z0-9-]+$', source):
    return "npm"
```

**Process:**
1. Use `npm view <package> dist.tarball` to get download URL
2. Download tarball to temp directory
3. Extract and analyze `package.json`
4. Find entry point (usually `dist/index.js` or `src/index.ts`)
5. AST analysis to detect transport type

**Example:**
```bash
# Input
@modelcontextprotocol/server-time

# Discovery Output
ServerConfig(
    name="server-time",
    source_type="npm",
    language="nodejs",
    entry_point=["npx", "-y", "@modelcontextprotocol/server-time"],
    transport="sse",
    sse_port=3000
)
```

#### 2. GitHub Repositories

**Detection:**
```python
if "github.com" in source:
    return "github"
```

**Process:**
1. Parse GitHub URL to extract owner/repo/path
2. Clone repository (or download specific subdirectory)
3. Detect language (Python or Node.js)
4. Find all potential MCP servers (monorepo support)
5. AST analysis for each server

**Example:**
```bash
# Input
https://github.com/modelcontextprotocol/servers/tree/main/src/time

# Discovery Output
ServerConfig(
    name="time",
    source_type="github",
    language="nodejs",
    entry_point=["node", "dist/index.js"],
    transport="sse",
    project_root="/tmp/mcp-github-xyz/src/time"
)
```

#### 3. Local Directories

**Detection:**
```python
path = Path(source).resolve()
if path.exists() and path.is_dir():
    return "local"
```

**Process:**
1. Resolve relative path to absolute
2. Detect language from files (pyproject.toml, package.json)
3. Find MCP entry points via AST analysis
4. Extract configuration

**Example:**
```bash
# Input
targets/vulnerable/dv-mcp/challenges/easy/challenge1

# Discovery Output
ServerConfig(
    name="dv-mcp",
    source_type="local",
    language="python",
    entry_point=["python", "-m", "challenges.easy.challenge1.server_sse"],
    transport="sse",
    sse_host="0.0.0.0",
    sse_port=9001,
    project_root="/absolute/path/to/project"
)
```

#### 4. Remote URLs (Legacy)

**Detection:**
```python
if source.startswith("http://") or source.startswith("https://"):
    return "https" if source.startswith("https://") else "http"
```

**Process:**
1. No discovery needed - server is already running
2. Return URL directly
3. Skip to Phase 4 (assessment)

### AST Analysis

#### Python Transport Detection

```python
class TransportAnalyzer(ast.NodeVisitor):
    def visit_Import(self, node):
        for alias in node.names:
            if "mcp.server.sse" in alias.name:
                self.sse_score += 10
            elif "mcp.server.stdio" in alias.name:
                self.stdio_score += 10

    def visit_Call(self, node):
        # Detect uvicorn.run(app, host="0.0.0.0", port=9001)
        if self._is_uvicorn_run(node):
            self._extract_host_port_from_call(node)
```

**What it detects:**
- Import statements: `from mcp.server.sse import Server`
- Function calls: `uvicorn.run()`, `app.run()`
- Host/port bindings: `host="127.0.0.1"`, `port=9001`
- Environment variables: `os.getenv("PORT", 9001)`

#### Node.js Transport Detection

```javascript
// Detects these patterns:
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// And port bindings:
app.listen(process.env.PORT || 3000);
server.listen(3000, '0.0.0.0');
```

### Output: ServerConfig

```python
@dataclass
class ServerConfig:
    name: str                           # "server-time"
    source_type: str                    # "npm" | "github" | "local" | "https"
    language: str                       # "python" | "nodejs"
    entry_point: List[str]              # ["npx", "-y", "@mcp/server-time"]
    transport: str                      # "stdio" | "sse"

    # Optional metadata
    dependencies: List[str]             # ["fastapi", "uvicorn"]
    env_vars: Dict[str, Optional[str]]  # {"API_KEY": None}
    sse_port: Optional[int]             # 9001
    sse_host: Optional[str]             # "0.0.0.0"
    project_root: Optional[Path]        # /path/to/project
```

---

## Phase 2: Container Provisioner

### Purpose

Launch MCP server in isolated Docker container with all dependencies installed.

### Fat Images Strategy

Instead of building custom Docker images for each MCP (slow!), we use **fat images** with common dependencies pre-installed:

**mcp-runner-python:latest**
- Python 3.11
- uv (fast dependency manager)
- Common libraries: fastapi, uvicorn, httpx, mcp
- System tools: curl, git, ffmpeg

**mcp-runner-node:latest**
- Node.js 22
- npm
- Common packages: @modelcontextprotocol/sdk
- System tools: curl, git

### Volume Mounting

```python
# Don't copy files - mount them!
volumes = {
    str(project_root): {"bind": "/app", "mode": "rw"}
}

container = docker_client.containers.run(
    image="mcp-runner-python:latest",
    volumes=volumes,
    detach=True,
    network_mode="bridge"
)
```

**Benefits:**
- No build time (was 2-3 minutes)
- Fast iteration (code changes visible immediately)
- Works for all MCPs

### Dependency Installation

#### Python (uv)

```python
# Install dependencies at runtime (fast!)
result = container.exec_run("uv sync", workdir="/app")

# Typical time: 5-10 seconds
```

#### Node.js (npm)

```python
# CRITICAL: Remove host's node_modules first!
container.exec_run("rm -rf /app/node_modules", workdir="/app")

# Install fresh (compiles native modules for Linux)
result = container.exec_run("npm install", workdir="/app")

# Typical time: 10-20 seconds
```

**Why remove node_modules?**
- Host (Windows/macOS) native modules (.node files) are compiled binaries
- Won't work in Linux container
- Must recompile in container

### CLI Auto-Detection

The system tries multiple command patterns to find what works:

```python
def _generate_candidates(self, base_command, transport, help_info):
    candidates = []

    # Try: python -m module sse
    if transport == "sse":
        candidates.append(["python", "-m", module, "sse"])

    # Try: python -m module --sse
    if help_info.get('has_sse_flag'):
        cmd = ["python", "-m", module, "--sse"]

        # Add port if detected
        if help_info.get('port_flag') and help_info.get('default_port'):
            cmd += [help_info['port_flag'], str(help_info['default_port'])]

        # CRITICAL: Add --host 0.0.0.0 for Docker
        if help_info.get('has_host_flag'):
            cmd += ["--host", "0.0.0.0"]

        candidates.append(cmd)

    # Try: python -m module --transport sse
    if help_info.get('has_transport_arg'):
        candidates.append(["python", "-m", module, "--transport", "sse"])

    return candidates
```

**Process:**
1. Run `python -m module --help` to get help text
2. Parse help text to detect available flags
3. Generate candidate commands
4. Try each candidate
5. Return the first one that works

### Crash Analysis Loop

Automatically fixes common errors:

```python
for attempt in range(max_retries):
    try:
        start_server()
        break  # Success!
    except CrashError as e:
        error_msg = str(e)

        # Fix 1: Missing ffmpeg
        if "ffmpeg" in error_msg.lower():
            print("[*] Installing ffmpeg...")
            container.exec_run("apt-get update && apt-get install -y ffmpeg")
            continue

        # Fix 2: Port already in use
        if "address already in use" in error_msg.lower():
            print("[*] Killing old process...")
            container.exec_run(["sh", "-c", "pkill -9 -f python || true"])
            await asyncio.sleep(2)  # Wait for port release
            continue

        # Fix 3: Host binding issue
        if "127.0.0.1" in error_msg:
            print("[*] Injecting --host 0.0.0.0...")
            # Modify command to use 0.0.0.0
            continue

        # Unknown error - give up
        raise
```

### Readiness Detection

Multiple strategies to detect when server is ready:

```python
# Strategy 1: SSE Probe (for SSE servers)
async def _wait_for_sse_ready(self, url, timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                return True
        except:
            pass
        await asyncio.sleep(1)
    return False

# Strategy 2: Log Pattern (for stdio servers)
def _check_log_pattern(self, logs, pattern="Server running"):
    return pattern in logs

# Strategy 3: Port Listening
def _check_port_listening(self, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', port))
    sock.close()
    return result == 0
```

---

## Phase 3: Universal Bridge

### Purpose

Normalize all MCP transports to a uniform HTTP interface for detectors.

### Why Needed?

Detectors expect HTTP endpoints, but MCPs use different transports:

| Transport | Native Interface | Problem |
|-----------|------------------|---------|
| **stdio** | stdin/stdout | Not HTTP |
| **SSE** | HTTP server | May bind to localhost (unreachable from host) |

### stdio → HTTP Bridge

Uses FastAPI to wrap stdin/stdout communication:

```python
from fastapi import FastAPI
from docker import DockerClient

app = FastAPI()

@app.post("/message")
async def proxy_message(request: MCPRequest):
    # 1. Get JSON request
    req_json = request.json()

    # 2. Execute docker exec with stdin
    exec_instance = container.exec_run(
        cmd=["python", "-m", "module"],
        stdin=True,
        stdout=True,
        stream=True
    )

    # 3. Write request to stdin
    exec_instance.socket.send(json.dumps(req_json).encode() + b'\n')

    # 4. Read response from stdout
    response_line = exec_instance.socket.readline()
    response = json.loads(response_line)

    # 5. Return as HTTP response
    return response
```

**Result:**
```
stdio MCP in container
    ↓ (stdin/stdout)
FastAPI bridge (localhost:60123)
    ↓ (HTTP)
Detectors
```

### SSE → HTTP Reverse Proxy

For SSE servers that bind to localhost inside container:

```python
# Container: 127.0.0.1:9001 (unreachable from host)
#     ↓
# Docker port map: host:53075 -> container:9001
#     ↓
# Reverse proxy: host:60028 -> host:53075
#     ↓
# Detectors connect to: http://localhost:60028/sse

import httpx

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy(path: str, request: Request):
    # Forward to container's SSE server
    target_url = f"http://localhost:{container_port}/{path}"

    async with httpx.AsyncClient() as client:
        response = await client.request(
            method=request.method,
            url=target_url,
            headers=dict(request.headers),
            content=await request.body()
        )

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers)
    )
```

### Smoke Test

Verifies MCP responds correctly before assessment:

```python
async def smoke_test(self, url: str) -> bool:
    """Test if MCP responds to initialize request."""
    try:
        response = requests.post(url + "/message", json={
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {
                    "name": "mcpsf-smoketest",
                    "version": "0.4.0"
                }
            },
            "id": 1
        }, timeout=5)

        if response.status_code != 200:
            return False

        result = response.json()

        # Must have serverInfo
        if "result" not in result or "serverInfo" not in result["result"]:
            return False

        print(f"[+] Smoke test passed: {result['result']['serverInfo']['name']}")
        return True

    except Exception as e:
        print(f"[!] Smoke test failed: {e}")
        return False
```

---

## Docker Images

### Building Fat Images

```bash
# Build Python runner
docker build -t mcp-runner-python:latest -f docker/mcp-runner-python.Dockerfile .

# Build Node.js runner
docker build -t mcp-runner-node:latest -f docker/mcp-runner-node.Dockerfile .
```

### Python Dockerfile

```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager)
RUN pip install uv

# Pre-install common MCP dependencies
RUN uv pip install --system \
    fastapi \
    uvicorn \
    httpx \
    mcp

WORKDIR /app

CMD ["/bin/bash"]
```

### Node.js Dockerfile

```dockerfile
FROM node:22-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Pre-install common MCP packages
RUN npm install -g @modelcontextprotocol/sdk

WORKDIR /app

CMD ["/bin/bash"]
```

---

## Troubleshooting

### Common Issues

#### Issue 1: "Cannot determine source type"

**Cause:** Path doesn't exist or not recognized as npm/github/local

**Fix:**
```python
# Use absolute paths
python mcpsf.py assess /absolute/path/to/mcp

# Or resolve relative paths
python mcpsf.py assess $(pwd)/targets/mcp
```

#### Issue 2: "Container failed to start"

**Cause:** Docker not running or image not built

**Fix:**
```bash
# Check Docker
docker ps

# Build images
./scripts/build-fat-images.sh
```

#### Issue 3: "Server not responding on localhost"

**Cause:** Server binding to 127.0.0.1 instead of 0.0.0.0

**Fix:** AMSAW v2 auto-detects and fixes this, but you can verify:

```python
# Check discovery output
[+] Detected host from AST: 127.0.0.1  # Bad!
[*] Injecting --host 0.0.0.0           # Auto-fix
```

#### Issue 4: "Native module error (Node.js)"

**Cause:** Host's node_modules compiled for wrong platform

**Fix:** Already handled automatically:
```python
# System automatically removes host node_modules
container.exec_run("rm -rf /app/node_modules")
# Then reinstalls in Linux container
container.exec_run("npm install")
```

### Debug Mode

Enable verbose logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

pipeline = AssessmentPipeline(interactive=True)
result = await pipeline.run(source="...", profile="balanced")
```

---

## Advanced Usage

### Custom Fat Images

Add your own dependencies:

```dockerfile
FROM mcp-runner-python:latest

# Add custom packages
RUN uv pip install --system \
    tensorflow \
    torch \
    custom-package
```

### Offline Mode

Pre-download npm packages:

```bash
# Download tarball
npm pack @modelcontextprotocol/server-time

# Extract
tar -xzf modelcontextprotocol-server-time-*.tgz

# Assess local directory
python mcpsf.py assess ./package
```

### Custom Container Configuration

```python
from src.core.provisioner import ContainerProvisioner

provisioner = ContainerProvisioner()

# Custom resource limits
container = provisioner.provision(
    config=server_config,
    cpu_quota=50000,      # 50% of one CPU
    mem_limit="512m"      # 512 MB RAM
)
```

### Monorepo Assessment

AMSAW v2 automatically detects multiple MCPs:

```python
# Input: GitHub repo with multiple MCPs
source = "https://github.com/modelcontextprotocol/servers"

# Discovery returns:
[
    ServerConfig(name="time", ...),
    ServerConfig(name="filesystem", ...),
    ServerConfig(name="sqlite", ...)
]

# System assesses each independently
```

---

## Performance Tuning

### Speed Up Dependency Installation

**Use dependency caching:**

```python
# Mount cache volume
volumes = {
    str(project_root): {"bind": "/app", "mode": "rw"},
    "/tmp/pip-cache": {"bind": "/root/.cache/pip", "mode": "rw"},
    "/tmp/npm-cache": {"bind": "/root/.npm", "mode": "rw"}
}
```

### Parallel Assessment

```python
import asyncio
from src.core.pipeline import AssessmentPipeline

async def assess_multiple(sources):
    pipeline = AssessmentPipeline()
    tasks = [pipeline.run(source=s) for s in sources]
    return await asyncio.gather(*tasks)

# Assess 5 MCPs in parallel
sources = ["mcp1", "mcp2", "mcp3", "mcp4", "mcp5"]
results = asyncio.run(assess_multiple(sources))
```

### Resource Limits

```python
# Prevent resource exhaustion
container = provisioner.provision(
    config=server_config,
    cpu_quota=100000,     # 1 CPU max
    mem_limit="1g",       # 1 GB RAM max
    pids_limit=100        # Max 100 processes
)
```

---

## Conclusion

AMSAW v2 transforms MCP security testing from a manual, error-prone process to a fully automated, deterministic system. By combining AST-based discovery, intelligent provisioning, and transport normalization, it enables testing of ANY MCP server with zero configuration.

**Key Takeaways:**
- Fat images + volume mounting = fast provisioning
- AST analysis = deterministic detection
- Crash analysis loop = automatic error recovery
- Universal bridge = consistent detector interface

For implementation details, see source code in `src/core/`.
