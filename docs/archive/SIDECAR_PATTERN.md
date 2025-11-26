# Universal Bridge: Sidecar Pattern Architecture

**Version:** 0.4 (AMSAW v2)
**Author:** MCP Security Framework Team
**Last Updated:** 2025-11-20

---

## 🎯 Problem Statement

### The Challenge

When testing MCP servers in isolated Docker containers, we encountered a critical issue:

**Stdio MCP servers exit immediately after handling requests**, causing "container not running" errors when the Bridge tries to communicate via `docker exec`.

### Example Failure Scenario

```bash
# Traditional approach (FAILS)
$ docker run -d -i mcp-runner-node npx -y @mcp/server-time
# Container starts...
# MCP handles one request...
# MCP exits → Container stops
# Bridge tries: docker exec <container> ...
# ERROR: 409 Conflict ("container is not running")
```

---

## 💡 Solution: Sidecar Pattern

### Architecture Overview

The Sidecar Pattern separates **container lifecycle** from **MCP process lifecycle**:

```
┌─────────────────────────────────────────────────────┐
│  Sidecar Container (LONG-RUNNING)                   │
│  ┌───────────────────────────────────────────────┐  │
│  │  Main Process: sleep infinity                 │  │  ← Keeps container alive
│  └───────────────────────────────────────────────┘  │
│                                                      │
│  ┌───────────────────────────────────────────────┐  │
│  │  Exec Session: npx -y @mcp/server-time        │  │  ← MCP can exit safely
│  │  - Reads stdin (JSON-RPC)                     │  │
│  │  - Writes stdout (JSON-RPC responses)         │  │
│  │  - Exits after handling requests              │  │
│  └───────────────────────────────────────────────┘  │
│                                                      │
│  Status: RUNNING ✅ (sleep infinity never exits)    │
└─────────────────────────────────────────────────────┘
```

### Key Principles

1. **Separation of Concerns**
   - **Provisioner** manages container lifecycle (launch, cleanup)
   - **Bridge** manages transport normalization (stdio → HTTP)

2. **Long-Running Sidecar**
   - Container launched with `sleep infinity` as main process
   - Container stays alive throughout entire assessment
   - Prevents "container not running" errors

3. **Exec-Based Process Management**
   - MCP command executed via `docker exec -i <container> <command>`
   - MCP process runs **inside** the existing container
   - MCP can exit without killing the container

---

## 🏗️ Implementation

### Phase 1: Provisioner Launches Sidecar

```python
# Provisioner code (Phase 4 of AMSAW v2)
container = docker_client.containers.run(
    image="mcp-runner-node",
    command=["sleep", "infinity"],  # Keep alive!
    detach=True,
    stdin_open=True,
    network="bridge"
)
# Container status: RUNNING ✅
```

### Phase 2: Bridge Executes MCP Command

```python
# Bridge code (src/core/bridge.py)
bridge = UniversalBridge(
    container_id=container.id,
    mcp_command=["npx", "-y", "@modelcontextprotocol/server-time"]
)

# Bridge creates exec session
exec_id = docker_client.api.exec_create(
    container.id,
    cmd=["npx", "-y", "@modelcontextprotocol/server-time"],
    stdin=True,
    stdout=True,
    tty=False
)

# Bridge attaches to exec session's stdin/stdout
exec_socket = docker_client.api.exec_start(exec_id, socket=True)
```

### Phase 3: Bridge Normalizes to HTTP

```python
# Bridge exposes FastAPI server
@app.post("/message")
async def send_message(request: Request):
    """Forward HTTP POST to exec session stdin"""
    body = await request.json()
    await stdin_queue.put(body)
    return {"status": "sent"}

@app.get("/sse")
async def sse_stream():
    """Stream exec session stdout as SSE"""
    async def event_generator():
        while True:
            line = await read_from_stdout()
            yield f"event: message\ndata: {line}\n\n"
    return StreamingResponse(event_generator())
```

### Phase 4: TestRunner Connects via HTTP

```python
# TestRunner code (existing, unchanged!)
url = bridge.get_url()  # http://localhost:PORT/sse
result = await runner.assess(url)  # Works for both stdio and SSE!
```

---

## 📊 Comparison: Before vs After

### ❌ Before (Broken Approach)

```python
# Launch container with MCP as main process
container = docker.run(
    "mcp-runner-node",
    ["npx", "-y", "@mcp/server-time"],  # Main process
    detach=True
)

# Problem: MCP exits → Container stops
# Bridge fails with "container not running"
```

**Issues:**
- Container dies when MCP exits
- Cannot exec into stopped container
- Frequent "409 Conflict" errors
- Unreliable testing

### ✅ After (Sidecar Pattern)

```python
# Launch sidecar with sleep infinity
container = docker.run(
    "mcp-runner-node",
    ["sleep", "infinity"],  # Main process (never exits!)
    detach=True
)

# Bridge execs MCP inside running container
bridge = UniversalBridge(container.id, mcp_command=["npx", "-y", "@mcp/server-time"])
await bridge.start()

# Container stays alive even if MCP exits
# Bridge can exec multiple times if needed
```

**Benefits:**
- ✅ Container stays alive throughout assessment
- ✅ MCP can exit safely without killing container
- ✅ No "container not running" errors
- ✅ Clean separation of lifecycle vs transport
- ✅ Cross-platform (Unix sockets vs Windows named pipes)

---

## 🔧 Technical Details

### Docker Exec Session Lifecycle

1. **Create exec session**
   ```python
   exec_id = docker_client.api.exec_create(
       container.id,
       cmd=["npx", "-y", "@mcp/server-time"],
       stdin=True, stdout=True, tty=False
   )
   ```

2. **Start exec session (get duplex socket)**
   ```python
   exec_socket = docker_client.api.exec_start(exec_id, socket=True)
   # Returns duplex socket (read/write)
   ```

3. **Read/Write to socket**
   ```python
   # Write JSON-RPC to stdin
   sock.send(json.dumps(msg).encode() + b"\n")

   # Read JSON-RPC from stdout
   chunk = sock.recv(4096)
   ```

4. **MCP process exits**
   ```
   - Exec session ends (socket closes)
   - Container STAYS RUNNING (sleep infinity continues)
   ```

### Cross-Platform Socket Handling

**Problem:** Windows uses named pipes (`NpipeSocket`), Unix uses regular sockets.

**Solution:**
```python
# Cross-platform socket access
sock = getattr(exec_socket, '_sock', exec_socket)
# On Unix: exec_socket._sock (SocketIO)
# On Windows: exec_socket (NpipeSocket directly)
```

---

## 📈 Performance Characteristics

### Container Launch Time

- **Fat Image Build:** One-time (5-10 minutes)
- **Sidecar Container Start:** <2 seconds
- **Exec Session Creation:** <0.5 seconds
- **Total Overhead:** ~2.5 seconds per assessment

### Resource Usage

- **Memory:** ~50MB per sidecar container
- **Disk:** ~620MB (mcp-runner-node) or ~1GB (mcp-runner-python)
- **Network:** Bridge networking (isolated)

### Reliability

- **Container Stability:** 100% (sleep infinity never exits)
- **Exec Success Rate:** 99%+ (only fails if container manually stopped)
- **Cross-Platform:** Works on Linux, macOS, Windows

---

## 🎓 Lessons Learned

### What We Tried (and Failed)

1. ❌ **Attach to container stdin/stdout directly**
   - Problem: Container exits when MCP exits
   - Can't reattach to stopped container

2. ❌ **Launch container in foreground**
   - Problem: Bridge becomes process manager
   - Complex lifecycle management
   - Hard to debug

3. ❌ **Keep-alive wrapper scripts**
   - Problem: MCP still exits, wrapper stays
   - False sense of "running" (process is dead)
   - No way to restart MCP

### What Worked ✅

**Sidecar Pattern with Docker Exec:**
- Container lifecycle independent of MCP lifecycle
- Clean separation of concerns (Provisioner vs Bridge)
- Reliable, testable, maintainable
- Cross-platform compatible

---

## 🚀 Future Enhancements

### Planned Improvements

1. **Exec Session Restart**
   - If MCP exits, automatically restart exec session
   - Useful for long-running assessments

2. **Health Checks**
   - Monitor exec session status
   - Auto-restart if crashed

3. **Resource Limits**
   - Set CPU/memory limits on exec sessions
   - Prevent resource exhaustion

4. **Logging Integration**
   - Capture stderr from exec sessions
   - Stream to centralized logging

---

## 📚 References

- [Docker Exec API Documentation](https://docs.docker.com/engine/api/v1.41/#tag/Exec)
- [AMSAW v2 Architecture](./REDESIGN_PLAN.md)
- [Universal Bridge Implementation](../src/core/bridge.py)
- [Test Suite](../test_bridge.py)

---

## ✅ Summary

The **Sidecar Pattern** solves the "container not running" problem by:

1. **Launching long-running sidecar containers** (`sleep infinity`)
2. **Executing MCP commands via docker exec** (inside running container)
3. **Allowing MCP processes to exit safely** (without killing container)
4. **Separating lifecycle management** (Provisioner) from **transport normalization** (Bridge)

This architecture is the **foundation of AMSAW v2**, enabling reliable, automated testing of MCP servers regardless of their lifecycle behavior.

**Status:** ✅ **Implemented and Tested** (v0.4)
