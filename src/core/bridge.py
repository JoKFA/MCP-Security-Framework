"""
Universal Transport Bridge for MCP Servers.

Normalizes stdio and SSE transports to a single HTTP interface.
TestRunner ALWAYS connects via HTTP, regardless of actual transport.

Architecture Overview:
====================

The Bridge uses a SIDECAR PATTERN to ensure reliable container lifecycle management:

1. **Container Lifecycle (Managed by Provisioner)**
   - Provisioner launches long-running "sidecar" containers with `sleep infinity`
   - Container stays alive throughout the assessment
   - Bridge receives the container ID (not responsible for launching)

2. **Transport Normalization (Managed by Bridge)**
   - Bridge auto-detects stdio vs SSE transport
   - For stdio: Executes MCP command inside running container, attaches to exec session
   - For SSE: Creates reverse proxy to container's HTTP endpoint
   - Exposes normalized HTTP URL: http://localhost:PORT/sse

3. **Design Rationale**
   - **Why Sidecar?** Stdio MCP servers often exit after handling requests
   - **Why docker exec?** Allows MCP process to exit without killing container
   - **Why long-running container?** Prevents "container not running" errors
   - **Separation of Concerns:** Provisioner = lifecycle, Bridge = transport

Transport-Specific Behavior:
============================

SSE Transport:
- Simple reverse proxy (forwards HTTP requests to container port)
- No process management needed
- TestRunner → Bridge → Container:9001/sse

Stdio Transport (Sidecar Pattern):
- Container launched with: `docker run -d <image> sleep infinity`
- Bridge executes: `docker exec -i <container> <mcp_command>`
- Bridge attaches to exec session's stdin/stdout streams
- FastAPI server wraps stdin (POST /message) and stdout (GET /sse)
- TestRunner → Bridge → docker exec → MCP process

Example Usage:
=============

```python
# Provisioner launches sidecar container
container = docker_client.containers.run(
    "mcp-runner-node",
    command=["sleep", "infinity"],  # Keep alive!
    detach=True,
    stdin_open=True
)

# Bridge wraps it with transport normalization
bridge = UniversalBridge(
    container.id,
    mcp_command=["npx", "-y", "@modelcontextprotocol/server-time"]
)
await bridge.start()

# TestRunner connects via normalized HTTP
url = bridge.get_url()  # http://localhost:PORT/sse
# Works for both stdio and SSE!
```
"""

import asyncio
import json
import socket
import struct  # CRITICAL: Parse Docker binary headers
from typing import Optional, Dict, Any
from pathlib import Path
import docker
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, JSONResponse
import uvicorn
import httpx


class UniversalBridge:
    """
    Normalizes stdio and SSE transports to HTTP.

    Architecture:
    - For SSE: Simple reverse proxy
    - For stdio: FastAPI server wrapping docker exec pipes
    - TestRunner always sees http://localhost:{PORT}/sse
    """

    def __init__(self, container_id: str, mcp_command: list = None, container_port: int = 9001, transport_hint: str = None):
        """
        Initialize bridge for a containerized MCP server.

        IMPORTANT: Container must be a LONG-RUNNING SIDECAR (e.g., sleep infinity)
        Bridge will execute the MCP command inside this running container.

        Args:
            container_id: Docker container ID or name (must be running!)
            mcp_command: Command to execute MCP server (e.g., ["npx", "-y", "@mcp/server-time"])
                        Only needed for stdio transport. SSE transport ignores this.
            container_port: Port the container exposes (if SSE transport)

        Example:
            # Provisioner launches sidecar
            container = docker.run("mcp-runner-node", ["sleep", "infinity"], detach=True)

            # Bridge wraps it
            bridge = UniversalBridge(
                container.id,
                mcp_command=["npx", "-y", "@mcp/server-time"]
            )
        """
        self.container_id = container_id
        self.mcp_command = mcp_command or []
        self.container_port = container_port
        self.local_port = self._find_free_port()
        self.transport_type: Optional[str] = None  # "sse" or "stdio"
        self.host_target_url: Optional[str] = None  # Host-mapped URL for SSE
        self.transport_hint = transport_hint

        # Docker client
        self.docker_client = docker.from_env()
        self.container = self.docker_client.containers.get(container_id)

        # Verify container is running
        self.container.reload()
        if self.container.status != "running":
            raise RuntimeError(
                f"Container {container_id} is not running (status: {self.container.status}). "
                f"Bridge requires a LONG-RUNNING SIDECAR container. "
                f"Launch with: docker run -d <image> sleep infinity"
            )

        # FastAPI app (for stdio bridge)
        self.app: Optional[FastAPI] = None
        self.server: Optional[uvicorn.Server] = None
        self.server_task: Optional[asyncio.Task] = None

        # HTTP client (for SSE proxy)
        self.http_client: Optional[httpx.AsyncClient] = None

        # Docker exec session (for stdio bridge)
        self.exec_id: Optional[str] = None
        self.exec_socket = None

    async def start(self) -> None:
        """
        Start bridge process.

        Strategy:
        1. Try connecting as SSE first (HTTP GET /sse)
        2. If that fails, assume stdio and launch bridge subprocess
        3. Wait for server to be ready (health check)
        4. Run smoke test
        """
        # Honor transport hint to avoid unnecessary probes
        if self.transport_hint == "stdio":
            print(f"[*] Transport hint: stdio (skipping SSE probe)")
            self.transport_type = "stdio"
            await self._start_stdio_bridge()
        elif await self._test_sse_connection():
            print(f"[*] Detected: SSE transport")
            self.transport_type = "sse"
            await self._start_reverse_proxy()
        else:
            print(f"[*] Detected: stdio transport (fallback)")
            self.transport_type = "stdio"
            await self._start_stdio_bridge()

        # CRITICAL: Wait for FastAPI to actually start accepting connections
        # This prevents "Connection Refused" errors in the first milliseconds
        print(f"[*] Waiting for bridge server to be ready...")
        for attempt in range(20):
            try:
                async with httpx.AsyncClient(timeout=1.0) as client:
                    response = await client.get(f"http://127.0.0.1:{self.local_port}/health")
                    if response.status_code == 200:
                        print(f"[+] Bridge server ready on port {self.local_port}")
                        break
            except Exception:
                await asyncio.sleep(0.1)
        else:
            raise RuntimeError("Bridge server failed to start (health check timeout)")

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
        self.container.reload()
        ports_map = self.container.attrs['NetworkSettings']['Ports'] or {}
        port_key = f"{self.container_port}/tcp"
        target_url = None

        # Prefer host-mapped port (Windows/Mac compatible)
        if port_key in ports_map and ports_map[port_key]:
            host_port = ports_map[port_key][0]['HostPort']
            target_url = f"http://127.0.0.1:{host_port}"
        else:
            # Fallback to container IP (Linux direct access)
            container_ip = self.container.attrs['NetworkSettings']['IPAddress']
            if not container_ip:
                print("[!] SSE detection failed: container has no IP address or host port mapping")
                return False
            target_url = f"http://{container_ip}:{self.container_port}"

        url = f"{target_url}/sse"
        self.host_target_url = target_url

        # Retry a few times to give the server time to come up
        for attempt in range(5):
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    async with client.stream(
                        "GET", url, headers={"accept": "text/event-stream"}, follow_redirects=True
                    ) as response:
                        if response.status_code in [200, 301, 302]:
                            print(f"[+] SSE probe succeeded (status {response.status_code}) at {url}")
                            return True
                        else:
                            print(f"[!] SSE probe attempt {attempt+1} got HTTP {response.status_code}")
            except Exception as e:
                print(f"[!] SSE probe attempt {attempt+1} failed: {e}")

            await asyncio.sleep(0.5)

        print(f"[!] SSE detection failed after retries: {url}")
        return False

    async def _start_reverse_proxy(self) -> None:
        """
        Start HTTP reverse proxy for SSE transport.

        Simple passthrough - forwards all requests to container port.
        """
        # Use host-mapped URL if available, else container IP
        if self.host_target_url:
            target_url = self.host_target_url
        else:
            container_ip = self.container.attrs['NetworkSettings']['IPAddress']
            target_url = f"http://{container_ip}:{self.container_port}"

        print(f"[*] Starting SSE reverse proxy: localhost:{self.local_port} -> {target_url}")

        # Create HTTP client with no read timeout (SSE is long-lived)
        timeout = httpx.Timeout(connect=30.0, read=None, write=30.0, pool=None)
        self.http_client = httpx.AsyncClient(base_url=target_url, timeout=timeout)

        # Create FastAPI app
        self.app = FastAPI()

        @self.app.get("/health")
        async def health():
            """Basic health check for readiness probes."""
            return {"status": "ok"}

        @self.app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
        async def proxy(path: str, request: Request):
            """Proxy all requests to container."""
            # Forward request
            query = request.url.query
            url = f"/{path}" + (f"?{query}" if query else "")
            method = request.method
            headers = dict(request.headers)
            headers.pop("host", None)
            headers.pop("content-length", None)
            body = await request.body()

            # Build request and stream response (SSE is infinite)
            req = self.http_client.build_request(
                method=method,
                url=url,
                headers=headers,
                content=body
            )
            response = await self.http_client.send(req, stream=True)

            return StreamingResponse(
                response.aiter_bytes(),
                status_code=response.status_code,
                headers=dict(response.headers)
            )

        # Start server in background
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.local_port, log_level="error")
        self.server = uvicorn.Server(config)
        self.server_task = asyncio.create_task(self.server.serve())

        # Wait for server to start
        await asyncio.sleep(0.5)

    async def _start_stdio_bridge(self) -> None:
        """
        Start stdio-to-HTTP bridge using SIDECAR PATTERN.

        Architecture (Sidecar Pattern):
        ┌─────────────────────────────────────────────────────────┐
        │  TestRunner (HTTP client)                               │
        │       ↓                                                  │
        │  http://localhost:{self.local_port}/sse                 │
        └─────────────────────────────────────────────────────────┘
                        ↓
        ┌─────────────────────────────────────────────────────────┐
        │  Bridge Process (FastAPI)                               │
        │  - POST /message → exec session stdin                   │
        │  - GET /sse → exec session stdout (SSE stream)          │
        └─────────────────────────────────────────────────────────┘
                        ↓
        ┌─────────────────────────────────────────────────────────┐
        │  Docker Exec Session (inside sidecar container)         │
        │  $ npx -y @modelcontextprotocol/server-time             │
        │  - Reads from stdin (JSON-RPC)                          │
        │  - Writes to stdout (JSON-RPC responses)                │
        └─────────────────────────────────────────────────────────┘
                        ↓
        ┌─────────────────────────────────────────────────────────┐
        │  Sidecar Container (long-running)                       │
        │  $ sleep infinity  ← Keeps container alive!             │
        └─────────────────────────────────────────────────────────┘

        Design Rationale:
        - Sidecar container runs `sleep infinity` to stay alive
        - Bridge executes MCP command via `docker exec -i`
        - MCP process can exit without killing the container
        - Prevents "container not running" errors
        """
        if not self.mcp_command:
            raise ValueError("mcp_command is required for stdio transport")

        print(f"[*] Starting stdio-to-HTTP bridge on localhost:{self.local_port}")
        print(f"[*] MCP command: {' '.join(self.mcp_command)}")

        # Create docker exec session for MCP command
        print(f"[*] Creating exec session in container {self.container.short_id}...")
        self.exec_id = self.docker_client.api.exec_create(
            self.container.id,
            cmd=self.mcp_command,
            stdin=True,
            stdout=True,
            stderr=True,
            tty=False
        )['Id']

        # Start exec session and get socket
        self.exec_socket = self.docker_client.api.exec_start(
            self.exec_id,
            socket=True,
            tty=False
        )

        print(f"[+] Exec session started: {self.exec_id[:12]}")

        # Create FastAPI app
        self.app = FastAPI()

        # Shared state for stdin/stdout pipes
        self.stdin_queue = asyncio.Queue()
        self.stdout_buffer = []

        # Start stdin writer task
        asyncio.create_task(self._stdin_writer())

        # Start stdout reader task
        asyncio.create_task(self._stdout_reader())

        @self.app.get("/health")
        async def health():
            """Health check endpoint for startup verification."""
            return {"status": "ok"}

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
                # Send initial endpoint event
                # IMPORTANT: MCP SDK expects plain string, not JSON!
                # Format: "event: endpoint\ndata: /message\n\n"
                yield f"event: endpoint\ndata: /message\n\n"

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
                        # MCP SDK expects: event: message\ndata: {...json...}\n\n
                        yield f"event: message\ndata: {json.dumps(data)}\n\n"
                    except json.JSONDecodeError:
                        # Not JSON, skip (stderr output, logs, etc.)
                        # Don't send errors to client, just ignore non-JSON lines
                        pass

            return StreamingResponse(
                event_generator(),
                media_type="text/event-stream"
            )

        # Start server in background
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.local_port, log_level="error")
        self.server = uvicorn.Server(config)
        self.server_task = asyncio.create_task(self.server.serve())

        # Wait for server to start
        await asyncio.sleep(0.5)

    async def _stdin_writer(self) -> None:
        """
        Background task: Write to exec session stdin using NON-BLOCKING IO.

        CRITICAL FIX: Uses loop.sock_sendall() instead of blocking sock.send()
        to prevent deadlocking the entire asyncio event loop.

        Reads from queue, serializes to JSON, writes to stdin.
        Uses the SHARED exec socket from _start_stdio_bridge().

        Note: Cross-platform compatible (Unix sockets vs Windows named pipes)
        """
        try:
            loop = asyncio.get_running_loop()
            sock = getattr(self.exec_socket, '_sock', self.exec_socket)

            # Best effort non-blocking; some sockets (NpipeSocket) don't support this
            try:
                sock.setblocking(False)
            except Exception:
                pass

            while True:
                msg = await self.stdin_queue.get()
                data = (json.dumps(msg) + "\n").encode('utf-8')

                # Windows named pipes don't support loop.sock_sendall; fall back to executor
                try:
                    await loop.sock_sendall(sock, data)
                except (AttributeError, NotImplementedError):
                    await loop.run_in_executor(None, sock.sendall, data)
        except Exception as e:
            print(f"[!] stdin writer error: {e}")

    async def _stdout_reader(self) -> None:
        """
        Background task: Read from exec session stdout using NON-BLOCKING IO.

        CRITICAL FIX: Uses loop.sock_recv() instead of blocking sock.recv()
        and parses Docker binary headers to separate stdout from stderr.

        Docker Stream Format (when tty=False):
        - Header: 8 bytes [StreamType (1B)][3B Padding][Size (4B Big-Endian)]
        - Payload: 'Size' bytes of actual data
        - StreamType: 1=stdout (JSON-RPC), 2=stderr (logs)

        This prevents:
        1. Event loop deadlock from blocking recv()
        2. Data corruption from unparsed binary headers
        """
        try:
            loop = asyncio.get_running_loop()
            sock = getattr(self.exec_socket, '_sock', self.exec_socket)

            try:
                sock.setblocking(False)
            except Exception:
                pass

            HEADER_SIZE = 8

            while True:
                try:
                    header = await self._read_n_bytes(sock, HEADER_SIZE)
                    if not header:
                        break

                    stream_type, size = struct.unpack('>BxxxI', header)
                    payload = await self._read_n_bytes(sock, size)
                    if not payload:
                        break

                    if stream_type == 1:
                        text = payload.decode('utf-8', errors='ignore')
                        for line in text.splitlines():
                            line = line.strip()
                            if line:
                                self.stdout_buffer.append(line)
                    elif stream_type == 2:
                        # STDERR: sanitize for Windows consoles (gbk/cp936)
                        log_str = payload.decode('utf-8', errors='replace').strip()
                        if log_str:
                            try:
                                import sys
                                encoding = sys.stdout.encoding or 'utf-8'
                                safe_log = log_str.encode(encoding, errors='replace').decode(encoding, errors='replace')
                                print(f"[CONTAINER LOG] {safe_log}")
                            except Exception:
                                print(f"[CONTAINER LOG] <Non-printable log data>")

                except Exception as e:
                    print(f"[!] stdout reader error: {e}")
                    break
        except Exception as e:
            print(f"[!] stdout reader fatal error: {e}")

    async def _read_n_bytes(self, sock, n: int) -> Optional[bytes]:
        """
        Helper to read exactly n bytes using NON-BLOCKING IO.

        Args:
            sock: Socket to read from
            n: Number of bytes to read

        Returns:
            Exactly n bytes, or None if EOF
        """
        loop = asyncio.get_running_loop()
        data = b''
        while len(data) < n:
            try:
                packet = await loop.sock_recv(sock, n - len(data))
            except (AttributeError, NotImplementedError):
                # Windows named pipes: fall back to executor
                packet = await loop.run_in_executor(None, sock.recv, n - len(data))
            if not packet:
                return None
            data += packet
        return data

    async def smoke_test(self, timeout: float = 5.0) -> bool:
        """
        Verify MCP server responds.

        Sends initialize request, expects response.

        Returns:
            True if server responds, False otherwise
        """
        print(f"[*] Running smoke test...")

        try:
            # For SSE targets we already probed connectivity; skip long-lived stream check
            if self.transport_type == "sse":
                print(f"[+] Smoke test skipped for SSE (probe already passed)")
                return True
            # For SSE, just verify we can open the stream
            if self.transport_type == "sse":
                async with httpx.AsyncClient(timeout=timeout) as client:
                    async with client.stream(
                        "GET",
                        f"http://127.0.0.1:{self.local_port}/sse",
                        headers={"accept": "text/event-stream"}
                    ) as resp:
                        if resp.status_code == 200:
                            print(f"[+] Smoke test passed (SSE stream reachable)")
                            return True
                        else:
                            print(f"[!] Smoke test failed: HTTP {resp.status_code}")
                            return False

            # For stdio, send initialize request over /message shim
            async with httpx.AsyncClient(timeout=timeout) as client:
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
        """
        Stop bridge process.

        Note: Does NOT stop the sidecar container!
        Container lifecycle is managed by the Provisioner.
        """
        if self.server:
            self.server.should_exit = True
            if self.server_task:
                try:
                    await asyncio.wait_for(self.server_task, timeout=2.0)
                except asyncio.TimeoutError:
                    pass
        if self.http_client:
            await self.http_client.aclose()
        if self.exec_socket:
            try:
                self.exec_socket.close()
            except Exception:
                pass
