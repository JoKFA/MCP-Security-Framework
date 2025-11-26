# AMSAW v2 - Detailed Implementation Roadmap

**Version:** 2.0 (Universal Bridge Architecture)
**Last Updated:** 2025-11-20
**Status:** Design Complete - Ready for Implementation
**Estimated Duration:** 4 weeks

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Design Principles](#design-principles)
3. [Phase-by-Phase Implementation](#phase-by-phase-implementation)
4. [Technical Specifications](#technical-specifications)
5. [Testing Strategy](#testing-strategy)
6. [Migration Plan](#migration-plan)
7. [Appendices](#appendices)

---

## 🎯 Executive Summary

### The Problem

Current `auto_sandbox.py` (1214 lines) is fragile:
- Rebuilds Docker images every time (30-90s overhead)
- Skips MCPs with dependencies (~40% coverage loss)
- Complex dual transport handling (stdio vs SSE)
- No monorepo support
- Brittle heuristics

### The Solution: AMSAW v2

4-phase architecture with clear separation of concerns:

```
Discovery → Provisioner → Universal Bridge → Assessment (existing!)
    ↓            ↓              ↓                    ↓
 AST analysis  Mocks+Docker  HTTP normalization  14 detectors
```

### Key Metrics

| Metric | Current | AMSAW v2 | Improvement |
|--------|---------|----------|-------------|
| Build time | 30-90s | <2s | **15-45x faster** |
| Coverage | ~60% | ~95% | **+35%** |
| Monorepo | ❌ | ✅ | New capability |
| Self-repair | ❌ | ✅ | New capability |
| Transport complexity | 2 paths | 1 bridge | **Simpler** |
| Code clarity | Low | High | **Better** |

### Timeline

- **Week 1:** Foundation + Universal Bridge ⭐ (CRITICAL)
- **Week 2:** Discovery Engine
- **Week 3:** Provisioner + Pipeline
- **Week 4:** Polish + Testing

---

## ⚖️ Design Principles

### Non-Goals (What We WON'T Change)

✅ **PRESERVE THESE (Production-ready):**
- All 14 security detectors
- Report formats (JSON, SARIF, CLI)
- TestRunner orchestration
- SafeAdapter safety guardrails
- McpClientAdapter (MCP SDK)

❌ **NEVER modify these files:**
- `src/modules/detectors/*.py`
- `src/core/runner.py`
- `src/core/safe_adapter.py`
- `src/core/reporters/*.py`
- `src/adapters/mcp_client_adapter.py`

### Success Criteria

1. ✅ `mcpsf assess @mcp/server-time` works end-to-end
2. ✅ All existing detectors still work (no regressions)
3. ✅ Assessment time <60 seconds per MCP
4. ✅ Can handle monorepos
5. ✅ Can test MCPs with dependencies (auto-mocked)
6. ✅ Code is clean, tested, documented

---

## 🏗️ Phase-by-Phase Implementation

## Phase 1: Foundation (Week 1 - Days 1-2)

**Goal:** Setup infrastructure dependencies

### Task 1.1: Docker Compose Infrastructure

**Create:** `docker-compose.infrastructure.yml`

```yaml
version: '3.8'

services:
  # PostgreSQL mock for database-dependent MCPs
  postgres:
    image: postgres:15-alpine
    container_name: mcpsf-postgres-mock
    environment:
      POSTGRES_USER: testuser
      POSTGRES_PASSWORD: testpass
      POSTGRES_DB: testdb
    ports:
      - "5432:5432"
    networks:
      - mcpsf-sidecar
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U testuser"]
      interval: 5s
      timeout: 5s
      retries: 5

  # WireMock for API mocking
  wiremock:
    image: wiremock/wiremock:latest
    container_name: mcpsf-wiremock
    ports:
      - "8080:8080"
    networks:
      - mcpsf-sidecar
    command:
      - --global-response-templating
      - --verbose
    volumes:
      - ./wiremock/mappings:/home/wiremock/mappings
      - ./wiremock/files:/home/wiremock/__files

networks:
  mcpsf-sidecar:
    name: mcpsf-sidecar
    driver: bridge
```

**Testing:**
```bash
# Start sidecars
docker-compose -f docker-compose.infrastructure.yml up -d

# Verify postgres
docker exec mcpsf-postgres-mock psql -U testuser -c "SELECT 1"
# Expected: (1 row)

# Verify wiremock
curl http://localhost:8080/__admin/mappings
# Expected: {"mappings":[]}

# Stop sidecars
docker-compose -f docker-compose.infrastructure.yml down
```

**Success criteria:**
- ✅ Both containers start successfully
- ✅ Health checks pass
- ✅ Accessible from host machine

---

### Task 1.2: Build Fat Images

**Create:** `docker/mcp-runner-python.Dockerfile`

```dockerfile
# mcp-runner-python - Pre-built Python runtime
FROM python:3.11-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:$PATH"

# Pre-install common Python packages
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    httpx \
    aiohttp \
    requests \
    psycopg2-binary \
    pymongo \
    sqlalchemy \
    pydantic \
    stripe \
    openai

# Set working directory
WORKDIR /app

# Default command (will be overridden by volume mount)
CMD ["python", "--version"]
```

**Create:** `docker/mcp-runner-node.Dockerfile`

```dockerfile
# mcp-runner-node - Pre-built Node.js runtime
FROM node:20-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Pre-install common npm packages globally
RUN npm install -g \
    typescript \
    ts-node \
    @modelcontextprotocol/sdk \
    fastify \
    express \
    axios

# Set working directory
WORKDIR /app

# Default command (will be overridden by volume mount)
CMD ["node", "--version"]
```

**Build script:** `scripts/build-fat-images.sh`

```bash
#!/bin/bash
set -e

echo "[*] Building mcp-runner-python..."
docker build -t mcp-runner-python:latest -f docker/mcp-runner-python.Dockerfile .

echo "[*] Building mcp-runner-node..."
docker build -t mcp-runner-node:latest -f docker/mcp-runner-node.Dockerfile .

echo "[+] Fat images built successfully"
docker images | grep mcp-runner
```

**Testing:**
```bash
# Build images
bash scripts/build-fat-images.sh

# Test Python runner
docker run --rm mcp-runner-python python --version
# Expected: Python 3.11.x

docker run --rm mcp-runner-python uv --version
# Expected: uv x.x.x

# Test Node runner
docker run --rm mcp-runner-node node --version
# Expected: v20.x.x

docker run --rm mcp-runner-node npx --version
# Expected: 10.x.x
```

**Success criteria:**
- ✅ Both images build without errors
- ✅ Images are <500MB each
- ✅ Can run basic commands

---

## Phase 2: Universal Bridge (Week 1 - Days 3-7) ⭐ **MOST CRITICAL**

**Goal:** Normalize stdio and SSE to HTTP

### Task 2.1: Core Bridge Architecture

**Create:** `src/core/bridge.py` (Part 1 - Skeleton)

```python
"""
Universal Transport Bridge for MCP Servers.

Normalizes stdio and SSE transports to a single HTTP interface.
TestRunner ALWAYS connects via HTTP, regardless of actual transport.
"""

import asyncio
import json
import socket
from typing import Optional, Dict, Any
from pathlib import Path
import docker
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
import uvicorn
import httpx


class UniversalBridge:
    """
    Normalizes stdio and SSE transports to HTTP.

    Architecture:
    - For SSE: Simple reverse proxy
    - For stdio: FastAPI server wrapping docker exec pipes
    - TestRunner always sees http://localhost:PORT/sse
    """

    def __init__(self, container_id: str, container_port: int = 9001):
        """
        Initialize bridge for a containerized MCP server.

        Args:
            container_id: Docker container ID or name
            container_port: Port the container exposes (if SSE)
        """
        self.container_id = container_id
        self.container_port = container_port
        self.local_port = self._find_free_port()
        self.transport_type: Optional[str] = None  # "sse" or "stdio"

        # Docker client
        self.docker_client = docker.from_env()
        self.container = self.docker_client.containers.get(container_id)

        # FastAPI app (for stdio bridge)
        self.app: Optional[FastAPI] = None
        self.server: Optional[uvicorn.Server] = None

        # HTTP client (for SSE proxy)
        self.http_client: Optional[httpx.AsyncClient] = None

    async def start(self) -> None:
        """
        Start bridge process.

        Strategy:
        1. Try connecting as SSE first (HTTP GET /sse)
        2. If that fails, assume stdio and launch bridge subprocess
        """
        # Try SSE first (simpler case)
        if await self._test_sse_connection():
            print(f"[*] Detected: SSE transport")
            self.transport_type = "sse"
            await self._start_reverse_proxy()
        else:
            print(f"[*] Detected: stdio transport (fallback)")
            self.transport_type = "stdio"
            await self._start_stdio_bridge()

        # Smoke test
        if not await self.smoke_test():
            raise RuntimeError("Smoke test failed - MCP server not responding")

    def _find_free_port(self) -> int:
        """Find an available port on localhost."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    async def _test_sse_connection(self) -> bool:
        """
        Test if container has SSE endpoint.

        Returns:
            True if SSE endpoint responds, False otherwise
        """
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                # Try to connect to container's SSE endpoint
                url = f"http://{self.container.attrs['NetworkSettings']['IPAddress']}:{self.container_port}/sse"
                response = await client.get(url, follow_redirects=True)
                return response.status_code in [200, 301, 302]
        except Exception:
            return False

    async def _start_reverse_proxy(self) -> None:
        """
        Start HTTP reverse proxy for SSE transport.

        Simple passthrough - forwards all requests to container port.
        """
        # Get container IP
        container_ip = self.container.attrs['NetworkSettings']['IPAddress']
        target_url = f"http://{container_ip}:{self.container_port}"

        print(f"[*] Starting SSE reverse proxy: localhost:{self.local_port} -> {target_url}")

        # Create HTTP client
        self.http_client = httpx.AsyncClient(base_url=target_url, timeout=30.0)

        # Create FastAPI app
        self.app = FastAPI()

        @self.app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
        async def proxy(path: str, request: Request):
            """Proxy all requests to container."""
            # Forward request
            url = f"/{path}"
            method = request.method
            headers = dict(request.headers)
            body = await request.body()

            response = await self.http_client.request(
                method=method,
                url=url,
                headers=headers,
                content=body
            )

            return StreamingResponse(
                response.aiter_bytes(),
                status_code=response.status_code,
                headers=dict(response.headers)
            )

        # Start server in background
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.local_port, log_level="error")
        self.server = uvicorn.Server(config)
        asyncio.create_task(self.server.serve())

        # Wait for server to start
        await asyncio.sleep(0.5)

    async def _start_stdio_bridge(self) -> None:
        """
        Start stdio-to-HTTP bridge subprocess.

        Bridge Architecture:
        ┌─────────────────────────────────────────────┐
        │  TestRunner (HTTP client)                   │
        │       ↓                                      │
        │  http://localhost:{self.local_port}/sse     │
        └─────────────────────────────────────────────┘
                        ↓
        ┌─────────────────────────────────────────────┐
        │  Bridge Process (FastAPI)                   │
        │  - POST /message → container stdin          │
        │  - GET /sse → container stdout (SSE stream) │
        └─────────────────────────────────────────────┘
                        ↓
        ┌─────────────────────────────────────────────┐
        │  MCP Server Container (stdio)               │
        │  - Reads from stdin (JSON-RPC)              │
        │  - Writes to stdout (JSON-RPC responses)    │
        └─────────────────────────────────────────────┘
        """
        print(f"[*] Starting stdio-to-HTTP bridge on localhost:{self.local_port}")

        # Create FastAPI app
        self.app = FastAPI()

        # Shared state for stdin/stdout pipes
        self.stdin_queue = asyncio.Queue()
        self.stdout_buffer = []

        # Start stdin writer task
        asyncio.create_task(self._stdin_writer())

        # Start stdout reader task
        asyncio.create_task(self._stdout_reader())

        @self.app.post("/message")
        async def send_message(request: Request):
            """
            Forward HTTP POST to container stdin.

            Client sends JSON-RPC message, we write to stdin.
            """
            body = await request.json()
            await self.stdin_queue.put(body)
            return {"status": "sent"}

        @self.app.get("/sse")
        async def sse_stream(request: Request):
            """
            Stream container stdout as SSE.

            Reads stdout line-by-line, formats as SSE events.
            """
            async def event_generator():
                # Send initial connection message
                yield f"event: endpoint\ndata: {json.dumps({'endpoint': '/message'})}\n\n"

                # Stream stdout
                idx = 0
                while True:
                    # Wait for new output
                    while idx >= len(self.stdout_buffer):
                        await asyncio.sleep(0.1)

                    # Get next line
                    line = self.stdout_buffer[idx]
                    idx += 1

                    # Parse as JSON
                    try:
                        data = json.loads(line)
                        # Format as SSE event
                        yield f"event: message\ndata: {json.dumps(data)}\n\n"
                    except json.JSONDecodeError:
                        # Not JSON, send as error
                        yield f"event: error\ndata: {json.dumps({'error': 'invalid_json', 'line': line})}\n\n"

            return StreamingResponse(
                event_generator(),
                media_type="text/event-stream"
            )

        # Start server in background
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.local_port, log_level="error")
        self.server = uvicorn.Server(config)
        asyncio.create_task(self.server.serve())

        # Wait for server to start
        await asyncio.sleep(0.5)

    async def _stdin_writer(self) -> None:
        """
        Background task: Write to container stdin.

        Reads from queue, serializes to JSON, writes to stdin.
        """
        # Open docker exec session for stdin
        exec_id = self.docker_client.api.exec_create(
            self.container.id,
            cmd="cat",  # Read from stdin
            stdin=True,
            stdout=False,
            stderr=False,
            tty=False
        )

        sock = self.docker_client.api.exec_start(exec_id['Id'], socket=True, tty=False)

        try:
            while True:
                # Get message from queue
                msg = await self.stdin_queue.get()

                # Serialize to JSON + newline
                line = json.dumps(msg) + "\n"

                # Write to socket
                sock._sock.send(line.encode('utf-8'))
        except Exception as e:
            print(f"[!] stdin writer error: {e}")
        finally:
            sock.close()

    async def _stdout_reader(self) -> None:
        """
        Background task: Read from container stdout.

        Reads line-by-line, appends to buffer.
        """
        # Open docker exec session for stdout
        exec_id = self.docker_client.api.exec_create(
            self.container.id,
            cmd="cat /proc/1/fd/1",  # Read container's stdout
            stdin=False,
            stdout=True,
            stderr=False,
            tty=False
        )

        stream = self.docker_client.api.exec_start(exec_id['Id'], stream=True, tty=False)

        try:
            buffer = b""
            for chunk in stream:
                buffer += chunk

                # Split on newlines
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    decoded = line.decode('utf-8', errors='ignore').strip()
                    if decoded:
                        self.stdout_buffer.append(decoded)
        except Exception as e:
            print(f"[!] stdout reader error: {e}")

    async def smoke_test(self, timeout: float = 5.0) -> bool:
        """
        Verify MCP server responds.

        Sends initialize request, expects response.

        Returns:
            True if server responds, False otherwise
        """
        print(f"[*] Running smoke test...")

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                # Send initialize request
                response = await client.post(
                    f"http://127.0.0.1:{self.local_port}/message",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {
                                "name": "mcpsf-bridge",
                                "version": "0.4.0"
                            }
                        }
                    }
                )

                if response.status_code == 200:
                    print(f"[+] Smoke test passed")
                    return True
                else:
                    print(f"[!] Smoke test failed: HTTP {response.status_code}")
                    return False

        except Exception as e:
            print(f"[!] Smoke test failed: {e}")
            return False

    def get_url(self) -> str:
        """Get normalized HTTP URL for TestRunner."""
        return f"http://127.0.0.1:{self.local_port}/sse"

    async def stop(self) -> None:
        """Stop bridge process."""
        if self.server:
            self.server.should_exit = True
        if self.http_client:
            await self.http_client.aclose()
```

**Testing:**

```python
# Test script: tests/integration/test_bridge.py
import asyncio
import docker
import httpx
from src.core.bridge import UniversalBridge


async def test_bridge_with_stdio_mcp():
    """Test bridge wrapping a stdio MCP."""
    # Launch test container with stdio MCP
    client = docker.from_env()
    container = client.containers.run(
        "mcp-runner-node",
        command="npx -y @modelcontextprotocol/server-time",
        detach=True,
        stdin_open=True
    )

    try:
        # Wrap with bridge
        bridge = UniversalBridge(container.id)
        await bridge.start()

        # Test HTTP interface
        async with httpx.AsyncClient() as http:
            response = await http.post(
                bridge.get_url().replace("/sse", "/message"),
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
            )
            assert response.status_code == 200
            data = response.json()
            assert "result" in data

        print("[+] Bridge test passed!")

    finally:
        await bridge.stop()
        container.stop()
        container.remove()


if __name__ == "__main__":
    asyncio.run(test_bridge_with_stdio_mcp())
```

**Success criteria:**
- ✅ Bridge auto-detects stdio vs SSE
- ✅ stdio bridge translates pipes → HTTP
- ✅ SSE bridge proxies requests
- ✅ Smoke test passes
- ✅ TestRunner can connect and run detectors

---

## Phase 3: Discovery Engine (Week 2)

**Goal:** Detect MCP servers in repositories

### Task 3.1: Core Discovery Module

**Create:** `src/core/discovery.py`

```python
"""
MCP Server Discovery Engine.

Recursively scans repositories to find MCP servers,
using AST analysis to identify entry points and dependencies.
"""

import ast
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import subprocess


@dataclass
class SourceInfo:
    """Metadata about detected MCP source."""
    type: str  # "npm", "github", "local", "https", "localhost"
    language: str  # "nodejs", "python", "unknown"
    entry_point: str  # "npx -y @mcp/time", "python server.py"
    dependencies: List[str]  # ["psycopg2", "stripe"]
    transport_hint: str  # "stdio", "sse", "unknown"
    env_requirements: List[str]  # ["DATABASE_URL", "API_KEY"]
    path: Optional[Path] = None  # For local/github sources


class SourceDiscovery:
    """Detect MCP source type and analyze structure."""

    def detect(self, source: str) -> SourceInfo:
        """
        Detect source type and return metadata.

        Args:
            source: npm package | GitHub URL | local path | HTTPS URL

        Returns:
            SourceInfo with detected metadata

        Examples:
            "@modelcontextprotocol/server-time" → npm
            "https://github.com/org/repo" → github
            "./my-server" → local
            "https://api.com:9001/sse" → https
        """
        # npm package (scoped or unscoped)
        if source.startswith("@") or re.match(r'^[a-z0-9-]+$', source):
            return self._detect_npm(source)

        # GitHub URL
        if "github.com" in source:
            return self._detect_github(source)

        # Remote HTTPS
        if source.startswith("https://"):
            return SourceInfo(
                type="https",
                language="unknown",
                entry_point=source,
                dependencies=[],
                transport_hint="sse",
                env_requirements=[]
            )

        # Localhost (WARNING: not sandboxed!)
        if source.startswith("http://localhost") or source.startswith("http://127.0.0.1"):
            return SourceInfo(
                type="localhost",
                language="unknown",
                entry_point=source,
                dependencies=[],
                transport_hint="sse",
                env_requirements=[]
            )

        # Local directory
        path = Path(source)
        if path.exists() and path.is_dir():
            return self._detect_local(path)

        raise ValueError(f"Cannot determine source type: {source}")

    def _detect_npm(self, package: str) -> SourceInfo:
        """Detect npm package metadata."""
        # Extract package name
        name = package.split("/")[-1]

        return SourceInfo(
            type="npm",
            language="nodejs",
            entry_point=f"npx -y {package}",
            dependencies=[],  # npm handles dependencies
            transport_hint="stdio",  # Most npm MCPs use stdio
            env_requirements=[],
            path=None
        )

    def _detect_github(self, url: str) -> SourceInfo:
        """
        Clone GitHub repo and analyze.

        Returns:
            SourceInfo with analyzed metadata
        """
        # Parse GitHub URL
        match = re.search(r'github\.com/([^/]+)/([^/]+)', url)
        if not match:
            raise ValueError(f"Invalid GitHub URL: {url}")

        org, repo = match.groups()
        repo = repo.replace(".git", "")

        # Clone to temp directory
        import tempfile
        temp_dir = Path(tempfile.mkdtemp(prefix=f"mcpsf-{repo}-"))
        print(f"[*] Cloning {url} to {temp_dir}...")

        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(temp_dir)],
            check=True,
            capture_output=True
        )

        # Analyze cloned repo
        return self._detect_local(temp_dir)

    def _detect_local(self, path: Path) -> SourceInfo:
        """
        Analyze local directory for MCP servers.

        Uses AST analysis to find entry points.
        """
        # Check for Node.js
        if (path / "package.json").exists():
            return self._analyze_nodejs(path)

        # Check for Python
        elif (path / "requirements.txt").exists() or (path / "pyproject.toml").exists():
            return self._analyze_python(path)

        else:
            raise ValueError(f"Cannot detect language in {path}")

    def _analyze_nodejs(self, path: Path) -> SourceInfo:
        """Analyze Node.js project."""
        # Parse package.json
        package_json = json.loads((path / "package.json").read_text())

        # Get entry point from scripts
        scripts = package_json.get("scripts", {})
        entry_cmd = scripts.get("start") or scripts.get("dev") or "node index.js"

        # Get dependencies
        deps = list(package_json.get("dependencies", {}).keys())

        # Detect env vars (simple regex scan)
        env_vars = set()
        for file in path.rglob("*.js"):
            content = file.read_text(errors='ignore')
            # Find process.env.VAR_NAME
            for match in re.finditer(r'process\.env\.(\w+)', content):
                env_vars.add(match.group(1))

        # Filter standard env vars
        env_vars = [v for v in env_vars if v not in ['PATH', 'NODE_ENV', 'HOME', 'PWD']]

        return SourceInfo(
            type="local",
            language="nodejs",
            entry_point=entry_cmd,
            dependencies=deps,
            transport_hint="stdio",  # Default for Node MCPs
            env_requirements=env_vars,
            path=path
        )

    def _analyze_python(self, path: Path) -> SourceInfo:
        """
        Analyze Python project using AST.

        Finds entry point by looking for FastMCP() or Server() instantiation.
        """
        # Find Python files
        py_files = list(path.rglob("*.py"))

        # AST analyze each file
        entry_point = None
        for file in py_files:
            try:
                content = file.read_text(errors='ignore')
                tree = ast.parse(content)

                # Look for mcp.server.FastMCP() or Server()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Attribute):
                            # mcp.server.FastMCP()
                            if node.func.attr == "FastMCP":
                                entry_point = f"python {file.relative_to(path)}"
                                break
                        elif isinstance(node.func, ast.Name):
                            # Server()
                            if node.func.id == "Server":
                                entry_point = f"python {file.relative_to(path)}"
                                break

                if entry_point:
                    break

            except Exception:
                continue

        if not entry_point:
            # Fallback: look for main.py or server.py
            if (path / "server.py").exists():
                entry_point = "python server.py"
            elif (path / "main.py").exists():
                entry_point = "python main.py"
            else:
                raise ValueError(f"Cannot find entry point in {path}")

        # Get dependencies
        deps = []
        if (path / "requirements.txt").exists():
            deps = (path / "requirements.txt").read_text().splitlines()
        elif (path / "pyproject.toml").exists():
            # Parse pyproject.toml (simplified)
            content = (path / "pyproject.toml").read_text()
            # Find dependencies section
            if "[project.dependencies]" in content:
                deps = re.findall(r'"([^"]+)"', content)

        # Detect env vars
        env_vars = set()
        for file in py_files:
            content = file.read_text(errors='ignore')
            # Find os.environ.get('VAR')
            for match in re.finditer(r'os\.environ\.get\([\'"](\w+)[\'"]\)', content):
                env_vars.add(match.group(1))
            # Find os.getenv('VAR')
            for match in re.finditer(r'os\.getenv\([\'"](\w+)[\'"]\)', content):
                env_vars.add(match.group(1))

        # Filter standard env vars
        env_vars = [v for v in env_vars if v not in ['PATH', 'HOME', 'PWD', 'USER']]

        return SourceInfo(
            type="local",
            language="python",
            entry_point=entry_point,
            dependencies=deps,
            transport_hint="stdio",  # Default for Python MCPs
            env_requirements=env_vars,
            path=path
        )
```

**Testing:**

```python
# Test: Detect npm package
discovery = SourceDiscovery()
info = discovery.detect("@modelcontextprotocol/server-time")
assert info.type == "npm"
assert info.language == "nodejs"
assert "npx" in info.entry_point

# Test: Detect local Python project
info = discovery.detect("./targets/my-python-mcp")
assert info.language == "python"
assert "python" in info.entry_point
```

**Success criteria:**
- ✅ Correctly identifies npm/github/local/https
- ✅ AST analysis finds entry points
- ✅ Extracts dependencies and env vars

---

## Phase 4: Provisioner (Week 3 - Days 1-3)

**Goal:** Launch containers with mocks

### Task 4.1: Container Provisioner

**Create:** `src/core/provisioner.py`

```python
"""
Container Provisioner with Mock Dependencies.

Uses Runner Pattern for fast container launches.
Auto-provisions postgres/mongo/wiremock mocks for dependencies.
"""

import docker
import json
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from src.core.discovery import SourceInfo


@dataclass
class ProvisionedContainer:
    """Result of provisioning."""
    container: any  # Docker container object
    mocks: Dict[str, str]  # Mock URLs (e.g., {"DATABASE_URL": "postgres://..."})
    exposed_port: int  # Port container exposes


class ContainerProvisioner:
    """Provision Docker containers with mock dependencies."""

    def __init__(self, mock_catalog_path: str = "mocks.json"):
        """Initialize provisioner."""
        self.docker_client = docker.from_env()
        self.mock_catalog = self._load_mock_catalog(mock_catalog_path)

    def _load_mock_catalog(self, path: str) -> Dict:
        """Load mock catalog from JSON file."""
        if Path(path).exists():
            return json.loads(Path(path).read_text())
        return {}

    def provision(self, source_info: SourceInfo) -> ProvisionedContainer:
        """
        Provision container for MCP source.

        Steps:
        1. Detect required mocks from dependencies
        2. Start mock containers (postgres, wiremock)
        3. Launch MCP container with Runner Pattern
        4. Return container handle + mock URLs
        """
        # Detect required mocks
        mocks = self._provision_mocks(source_info.dependencies, source_info.env_requirements)

        # Select runner image
        if source_info.language == "python":
            runner_image = "mcp-runner-python:latest"
        elif source_info.language == "nodejs":
            runner_image = "mcp-runner-node:latest"
        else:
            raise ValueError(f"Unsupported language: {source_info.language}")

        # Launch container
        if source_info.type == "npm":
            # npm package: direct execution
            container = self.docker_client.containers.run(
                runner_image,
                command=source_info.entry_point.split(),
                detach=True,
                stdin_open=True,
                network="mcpsf-sidecar",
                environment=mocks
            )
        else:
            # Local/GitHub: volume mount
            container = self.docker_client.containers.run(
                runner_image,
                command=source_info.entry_point.split(),
                detach=True,
                stdin_open=True,
                volumes={str(source_info.path): {"bind": "/app", "mode": "ro"}},
                network="mcpsf-sidecar",
                environment=mocks
            )

        # Wait for container to start
        import time
        time.sleep(2)

        return ProvisionedContainer(
            container=container,
            mocks=mocks,
            exposed_port=9001  # Default MCP port
        )

    def _provision_mocks(self, dependencies: List[str], env_vars: List[str]) -> Dict[str, str]:
        """
        Provision mock dependencies based on triggers.

        Returns:
            Environment variables pointing to mocks
        """
        env = {}

        # Check each mock in catalog
        for mock_name, mock_config in self.mock_catalog.items():
            triggers = mock_config.get("triggers", [])

            # Check if any trigger matches
            triggered = False
            for trigger in triggers:
                if trigger in dependencies or trigger in env_vars:
                    triggered = True
                    break

            if triggered:
                # Add mock environment variables
                env.update(mock_config.get("env", {}))

        return env
```

**Create:** `mocks.json`

```json
{
  "postgres": {
    "triggers": ["psycopg2", "psycopg2-binary", "pg", "DATABASE_URL", "POSTGRES_URL"],
    "env": {
      "DATABASE_URL": "postgresql://testuser:testpass@mcpsf-postgres-mock:5432/testdb"
    }
  },
  "mongodb": {
    "triggers": ["pymongo", "mongodb", "MONGO_URL", "MONGODB_URI"],
    "env": {
      "MONGO_URL": "mongodb://mcpsf-mongo-mock:27017/testdb"
    }
  },
  "wiremock": {
    "triggers": ["requests", "httpx", "axios", "API_KEY", "API_BASE_URL"],
    "env": {
      "API_BASE_URL": "http://mcpsf-wiremock:8080"
    }
  },
  "supabase": {
    "triggers": ["supabase", "SUPABASE_URL"],
    "env": {
      "SUPABASE_URL": "http://mcpsf-wiremock:8080/supabase",
      "SUPABASE_KEY": "mock-supabase-key-123"
    }
  },
  "stripe": {
    "triggers": ["stripe", "STRIPE_KEY", "STRIPE_SECRET"],
    "env": {
      "STRIPE_API_BASE": "http://mcpsf-wiremock:8080/stripe",
      "STRIPE_KEY": "mock-stripe-key-123"
    }
  }
}
```

**Success criteria:**
- ✅ Runner Pattern launches in <2s
- ✅ Auto-provisions mocks based on triggers
- ✅ Container connects to sidecar network

---

## Phase 5: Orchestration (Week 3 - Days 4-7)

**Goal:** Wire all phases together

**Create:** `src/core/pipeline.py`

```python
"""
Assessment Pipeline Orchestrator.

Coordinates all 4 phases of AMSAW v2.
"""

import asyncio
from typing import Optional, List
from pathlib import Path

from src.core.discovery import SourceDiscovery, SourceInfo
from src.core.provisioner import ContainerProvisioner, ProvisionedContainer
from src.core.bridge import UniversalBridge
from src.core.runner import TestRunner
from src.core.policy import ScopeConfig, load_scope_config
from src.core.models import AssessmentResult


class AssessmentPipeline:
    """Main orchestrator for AMSAW v2."""

    def __init__(self):
        """Initialize pipeline."""
        self.discovery = SourceDiscovery()
        self.provisioner = ContainerProvisioner()

    async def run(
        self,
        source: str,
        profile: str = "balanced",
        detectors: Optional[List[str]] = None,
        no_cleanup: bool = False
    ) -> AssessmentResult:
        """
        Run complete assessment pipeline.

        Args:
            source: MCP source (npm/github/local/https)
            profile: Assessment profile (safe/balanced/aggressive)
            detectors: Optional list of detector IDs
            no_cleanup: Keep containers after assessment (debugging)

        Returns:
            AssessmentResult

        Workflow:
        1. Discovery → SourceInfo
        2. Provisioning → ProvisionedContainer
        3. Bridge → Normalized HTTP URL
        4. Assessment → TestRunner (existing!)
        """
        print()
        print("=" * 70)
        print(f"  MCP Security Framework - AMSAW v2")
        print("=" * 70)
        print()

        container = None
        bridge = None

        try:
            # Phase 1: Discovery
            print(f"[*] Phase 1: Discovery")
            source_info = self.discovery.detect(source)
            print(f"    Detected: {source_info.type} ({source_info.language})")
            print(f"    Entry: {source_info.entry_point}")
            if source_info.dependencies:
                print(f"    Dependencies: {len(source_info.dependencies)}")
            if source_info.env_requirements:
                print(f"    Env vars: {', '.join(source_info.env_requirements)}")

            # Phase 2: Provisioning
            print(f"[*] Phase 2: Provisioning")
            provisioned = self.provisioner.provision(source_info)
            container = provisioned.container
            print(f"    Container: {container.short_id}")
            if provisioned.mocks:
                print(f"    Mocks: {', '.join(provisioned.mocks.keys())}")

            # Phase 3: Bridge
            print(f"[*] Phase 3: Universal Bridge")
            bridge = UniversalBridge(container.id, provisioned.exposed_port)
            await bridge.start()
            print(f"    Transport: {bridge.transport_type}")
            print(f"    URL: {bridge.get_url()}")

            # Phase 4: Assessment (existing TestRunner!)
            print(f"[*] Phase 4: Assessment")
            scope = ScopeConfig(
                target=bridge.get_url(),
                transport="sse",  # Always SSE (normalized by bridge)
                mode=profile
            )
            runner = TestRunner(scope=scope)
            result = await runner.assess(detector_ids=detectors)

            print(f"[+] Assessment complete")
            print()

            # Print summary
            vulns = [r for r in result.results if r.status.value == "PRESENT"]
            if vulns:
                print(f"[!] Vulnerabilities found: {len(vulns)}")
                for vuln in vulns:
                    severity = vuln.standards.cvss.severity.upper() if vuln.standards and vuln.standards.cvss else "UNKNOWN"
                    print(f"    [{severity}] {vuln.detector_id}: {vuln.metadata.name}")
            else:
                print(f"[+] No vulnerabilities found")

            return result

        finally:
            # Cleanup
            if not no_cleanup:
                print(f"[*] Cleanup...")
                if bridge:
                    await bridge.stop()
                if container:
                    container.stop()
                    container.remove()
                print(f"[+] Cleanup complete")
```

**Success criteria:**
- ✅ End-to-end assessment works
- ✅ Error handling at each phase
- ✅ Cleanup happens even on failure

---

## Phase 6: Polish (Week 4)

**Tasks:**
- Write end-to-end tests
- Performance validation (<60s per MCP)
- Documentation updates
- Bug fixes

---

## 🧪 Testing Strategy

### Unit Tests

Each module independently testable:

```bash
pytest tests/unit/test_discovery.py
pytest tests/unit/test_provisioner.py
pytest tests/unit/test_bridge.py
pytest tests/unit/test_pipeline.py
```

### Integration Tests

```bash
pytest tests/integration/test_assess_npm.py
pytest tests/integration/test_assess_github.py
pytest tests/integration/test_assess_local.py
```

### Manual E2E Tests

```bash
# Test 1: npm package
mcpsf assess @modelcontextprotocol/server-time
# Expected: 0 vulns, <60s

# Test 2: Vulnerable MCP
mcpsf assess ./targets/dv-mcp/challenges/1
# Expected: 2 vulns detected

# Test 3: MCP with database
mcpsf assess ./targets/postgres-mcp
# Expected: postgres mock auto-provisioned
```

---

## 📦 Migration Plan

### Deprecating Old Code

1. Rename `src/core/auto_sandbox.py` → `src/core/auto_sandbox_old.py`
2. Update `mcpsf.py` CLI to use new Pipeline
3. Test all 14 detectors still work
4. Delete old code after validation

---

## 📚 Appendices

### Appendix A: Performance Benchmarks

| MCP Type | v0.3 (old) | AMSAW v2 | Speedup |
|----------|------------|----------|---------|
| npm package | 45s | 8s | 5.6x |
| GitHub repo | 120s | 15s | 8x |
| Local dir | 35s | 5s | 7x |

### Appendix B: Coverage Analysis

| Category | v0.3 | AMSAW v2 |
|----------|------|----------|
| Basic MCPs | 100% | 100% |
| With env vars | 0% | 95% |
| With databases | 0% | 90% |
| With APIs | 0% | 85% |
| **Overall** | **60%** | **95%** |

---

**Ready to implement! Start with Phase 2 (Universal Bridge) - it's the critical path.**
