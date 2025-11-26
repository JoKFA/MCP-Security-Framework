# Simplified Sandbox Architecture - Learning from Malware Analysis

**Date:** 2025-11-19
**Purpose:** Redesign MCPSF with automatic sandboxing, eliminating CLI complexity

---

## Core Principle: "Sandbox by Default"

**Malware sandboxes (Cuckoo, Joe Sandbox, ANY.RUN) don't ask users "Do you want sandbox?"**
**They just always sandbox. Safety is non-negotiable.**

### What We Learned

| Tool | Command | Behavior |
|------|---------|----------|
| Cuckoo | `cuckoo submit malware.exe` | Always runs in isolated VM |
| Joe Sandbox | `joe-sandbox analyze sample.pdf` | Always cloud-isolated |
| ANY.RUN | Upload file → automatic | Always sandboxed |

**Key insight:** User submits sample → System handles safety automatically

---

## Proposed MCPSF Architecture

### **ONE Command Only**
```bash
mcpsf assess <mcp-source> [options]
```

**No separate "sandbox" command!** The system automatically decides:

| Input Type | System Behavior | User Sees |
|------------|----------------|-----------|
| npm package<br>`@modelcontextprotocol/server-time` | 1. Build container<br>2. Run isolated<br>3. Test<br>4. Destroy | "Building... Testing... Done" |
| GitHub URL<br>`https://github.com/org/mcp` | 1. Clone to temp<br>2. Build container<br>3. Run isolated<br>4. Test<br>5. Destroy | "Cloning... Building... Testing... Done" |
| Local directory<br>`./my-mcp-server` | 1. Copy to temp<br>2. Build container<br>3. Run isolated<br>4. Test<br>5. Destroy | "Building... Testing... Done" |
| Remote HTTPS URL<br>`https://api.example.com:9001/sse` | 1. Direct connection<br>2. Test | "Connecting... Testing... Done" |
| Local running server<br>`http://localhost:9001/sse` | ⚠️ **WARNING**<br>"Local server detected. Not sandboxed!"<br>Continue? (y/N) | User confirms risk |

**User never types "sandbox" - it's automatic!**

---

## Architecture: Two-Mode Design

### Mode 1: Automatic Sandboxing (Default)
```
User input → Detect type → Build container → Test → Destroy → Report
```

### Mode 2: Direct Connection (Explicit Opt-in)
```
User input (HTTPS) → Direct test → Report
User input (localhost) → Warning → User confirms → Test → Report
```

---

## Why This Works

### 1. **Safety First**
- Default behavior is ALWAYS safe
- User can't accidentally run untrusted code on their machine
- Matches malware sandbox mental model

### 2. **Zero Configuration**
```bash
# User wants to test an MCP from npm
mcpsf assess @modelcontextprotocol/server-time

# System automatically:
# - Detects: npm package
# - Builds: Docker container with Node.js
# - Runs: Container on random port
# - Tests: All detectors
# - Destroys: Container
# - Reports: Findings

# User sees:
[*] Detected: npm package @modelcontextprotocol/server-time
[*] Building container... ━━━━━━━━━━━━━━━━ 100%
[*] Starting server... OK
[*] Running assessment (12 detectors)... ━━━━━━━━━━━━━━━━ 100%
[+] Assessment complete: 0 vulnerabilities found
[*] Cleanup... OK

Save configuration for later? (Y/n): n
```

**No YAML, no Docker knowledge, no manual setup!**

### 3. **Cloud-Ready Architecture**
```
┌─────────────────────────────────────────────────────────────┐
│                    MCPSF Client (CLI)                        │
│  - Input parsing                                             │
│  - Source type detection                                     │
│  - Report display                                            │
└─────────────────────────────────────────────────────────────┘
                              │
                 ┌────────────┴─────────────┐
                 │                          │
                 ▼                          ▼
┌──────────────────────────┐  ┌──────────────────────────────┐
│  Local Executor          │  │  Cloud Executor (Future)      │
│  (Docker on user's PC)   │  │  (API: api.mcpsf.io)          │
│                          │  │                                │
│  + Fast (local)          │  │  + No Docker install needed    │
│  + No API key needed     │  │  + No disk space used          │
│  - Requires Docker       │  │  + Faster builds (cache)       │
│  - Uses disk space       │  │  - Requires API key            │
│  - Slow first build      │  │  - Network latency             │
└──────────────────────────┘  └──────────────────────────────┘
```

**CLI decides:** Local Docker available? Use it. Otherwise, use cloud API.

---

## Cloud Sandbox Architecture (Future)

Learning from Joe Sandbox Cloud / ANY.RUN:

```
┌─────────────────────────────────────────────────────────────┐
│                  MCPSF Cloud API (api.mcpsf.io)              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  POST /api/v1/assess                                         │
│  {                                                           │
│    "source": "@modelcontextprotocol/server-time",          │
│    "profile": "balanced"                                    │
│  }                                                          │
│                                                              │
│  → Returns: {"job_id": "abc123"}                            │
│                                                              │
│  GET /api/v1/jobs/abc123                                    │
│  → Returns: {"status": "running", "progress": 45}           │
│                                                              │
│  GET /api/v1/jobs/abc123/report                             │
│  → Returns: Full assessment report                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│            Kubernetes Cluster (Isolated Workers)             │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Worker 1   │  │  Worker 2   │  │  Worker 3   │         │
│  │  Building   │  │  Testing    │  │  Idle       │         │
│  │  Image...   │  │  MCP...     │  │             │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                              │
│  Features:                                                   │
│  - Network isolation (per job)                               │
│  - Resource limits (CPU/memory/timeout)                      │
│  - Cached base images (faster builds)                        │
│  - Parallel execution (100+ concurrent)                      │
│  - Auto-scaling                                              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Benefits of Cloud Approach

**For Users:**
- ✅ No Docker installation required
- ✅ No disk space used (images stored in cloud)
- ✅ Faster builds (shared cache)
- ✅ Works on any OS (even mobile!)
- ✅ Can analyze 100+ MCPs in parallel

**For Security:**
- ✅ Complete isolation (Kubernetes network policies)
- ✅ No risk to user's machine
- ✅ Can use honeypot networks (detect malicious MCPs calling home)
- ✅ Centralized threat intelligence

**For Performance:**
- ✅ Faster builds (warm cache, fast network)
- ✅ Parallel execution (100+ workers)
- ✅ No local resource consumption

---

## Revised CLI Design

### **Single Assess Command**

```bash
mcpsf assess <source> [options]

Arguments:
  source                MCP source to assess:
                        - npm package: @modelcontextprotocol/server-time
                        - GitHub repo: https://github.com/org/mcp-server
                        - Local path: ./my-mcp-server
                        - Remote URL: https://api.example.com:9001/sse

Options:
  --profile PROFILE     Assessment profile (safe/balanced/aggressive) [default: balanced]
  --detectors LIST      Comma-separated detector IDs to run [default: all]
  --output DIR          Output directory for reports [default: ./reports]
  --no-cleanup          Keep container after assessment (for debugging)
  --executor EXEC       Force executor (local/cloud) [default: auto]
  --save-as ID          Save configuration for later reuse
  --env KEY=VALUE       Environment variables for MCP (can repeat)

Examples:
  # Assess npm package (auto-sandboxed)
  mcpsf assess @modelcontextprotocol/server-time

  # Assess GitHub repo (auto-sandboxed)
  mcpsf assess https://github.com/modelcontextprotocol/servers/tree/main/src/time

  # Assess local directory (auto-sandboxed)
  mcpsf assess ./my-mcp-server

  # Assess remote HTTPS server (direct connection)
  mcpsf assess https://api.example.com:9001/sse

  # Assess with environment variables
  mcpsf assess @mcp/weather --env OPENAI_API_KEY=sk-...

  # Save configuration for reuse
  mcpsf assess @mcp/time --save-as time-server

  # Use cloud executor (no local Docker needed)
  mcpsf assess @mcp/time --executor cloud

  # Aggressive profile
  mcpsf assess ./my-server --profile aggressive
```

### **Simplified Management Commands**

```bash
# List saved configurations (from --save-as)
mcpsf list

# Show saved configuration
mcpsf show <id>

# Delete saved configuration
mcpsf delete <id>

# List available detectors
mcpsf detectors

# Show version
mcpsf version
```

**That's it! No "targets", no "registry", no "batch", no "sandbox"!**

---

## Implementation Plan

### Phase 1: Local Executor (Week 1-2)

**File:** `src/core/auto_sandbox.py` (400 lines)

```python
"""
Automatic MCP Sandboxing - Transparent isolation.

Detects source type and automatically builds/runs isolated containers.
User never sees "sandbox" - it's just how the tool works.
"""

class AutoSandbox:
    """
    Automatic sandbox executor.

    User provides MCP source → System handles isolation automatically.
    """

    async def assess(self, source: str, profile: str = "balanced", **kwargs):
        """
        Assess MCP with automatic sandboxing.

        Args:
            source: MCP source (npm/github/local/https)
            profile: Assessment profile
            **kwargs: Additional options

        Flow:
            1. Detect source type
            2. If code → Build container, run isolated, test, destroy
            3. If URL → Direct connection (already isolated)
            4. Return report
        """
        # 1. Detect source type
        source_type = self._detect_source(source)

        # 2. Auto-sandbox if needed
        if source_type in ["npm", "github", "local"]:
            return await self._sandboxed_assess(source, source_type, profile, **kwargs)
        elif source_type == "https":
            return await self._direct_assess(source, profile, **kwargs)
        elif source_type == "localhost":
            # Warning: localhost not sandboxed!
            if not self._confirm_localhost_risk():
                raise AssessmentCancelled("User declined localhost assessment")
            return await self._direct_assess(source, profile, **kwargs)

    async def _sandboxed_assess(self, source, source_type, profile, **kwargs):
        """Run assessment in isolated container."""
        print(f"[*] Detected: {source_type}")

        # Generate Dockerfile
        dockerfile, context = self._generate_dockerfile(source, source_type)

        # Build image
        image_tag = self._build_image(dockerfile, context)

        # Find free port
        port = self._find_free_port()

        # Start container
        container = self._start_container(image_tag, port, kwargs.get("env", {}))

        try:
            # Wait for ready
            url = f"http://localhost:{port}/sse"
            await self._wait_for_ready(url)

            # Probe server
            probe_result = await probe_mcp_server(url)

            # Run assessment
            result = await self._run_assessment(url, profile, kwargs.get("detectors"))

            # Optionally save config
            if kwargs.get("save_as"):
                self._save_config(kwargs["save_as"], probe_result, source)

            return result

        finally:
            # Always cleanup (unless --no-cleanup)
            if not kwargs.get("no_cleanup"):
                self._stop_container(container)
                self._remove_image(image_tag)

    def _detect_source(self, source: str) -> str:
        """Detect source type from input string."""
        if source.startswith("@") or re.match(r'^[a-z0-9-]+/[a-z0-9-]+$', source):
            return "npm"
        if "github.com" in source:
            return "github"
        if source.startswith("https://"):
            return "https"
        if source.startswith("http://localhost") or source.startswith("http://127.0.0.1"):
            return "localhost"
        if Path(source).exists():
            return "local"
        raise ValueError(f"Unknown source type: {source}")

    def _generate_dockerfile(self, source: str, source_type: str) -> Tuple[str, Path]:
        """Generate Dockerfile based on source type."""
        # AUTO-DETECT from package.json, requirements.txt, etc.
        # Returns (dockerfile_content, build_context_path)
        pass

    def _confirm_localhost_risk(self) -> bool:
        """Warn user about localhost assessment risk."""
        print()
        print("⚠️  WARNING: Assessing localhost server without isolation!")
        print("    The MCP server is running on your machine with full access.")
        print("    This is NOT sandboxed and could be dangerous.")
        print()
        response = input("Continue anyway? (y/N): ")
        return response.lower() == "y"
```

### Phase 2: Cloud Executor (Week 3-4)

**File:** `src/core/cloud_executor.py` (300 lines)

```python
"""
Cloud-based MCP assessment executor.

Submits jobs to MCPSF Cloud API for remote sandboxing.
No local Docker required!
"""

class CloudExecutor:
    """
    Cloud executor using MCPSF API.

    Benefits:
    - No Docker installation needed
    - No disk space used
    - Faster builds (warm cache)
    - Parallel execution
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("MCPSF_API_KEY")
        self.base_url = "https://api.mcpsf.io/v1"

    async def assess(self, source: str, profile: str = "balanced", **kwargs):
        """Submit assessment job to cloud."""
        # 1. Submit job
        job = await self._submit_job(source, profile, kwargs)

        print(f"[*] Job submitted: {job['id']}")
        print(f"[*] Status: {self.base_url}/jobs/{job['id']}")

        # 2. Poll for completion
        while True:
            status = await self._get_job_status(job["id"])

            if status["state"] == "completed":
                break
            elif status["state"] == "failed":
                raise AssessmentFailed(status["error"])

            print(f"[*] Progress: {status['progress']}% - {status['step']}")
            await asyncio.sleep(2)

        # 3. Download report
        report = await self._download_report(job["id"])

        print(f"[+] Assessment complete")

        return report

    async def _submit_job(self, source, profile, options):
        """Submit job to API."""
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/assess",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "source": source,
                    "profile": profile,
                    "detectors": options.get("detectors"),
                    "env": options.get("env", {})
                }
            ) as resp:
                return await resp.json()
```

### Phase 3: Auto-Executor Selection (Week 5)

**File:** `src/core/executor_factory.py` (100 lines)

```python
"""
Automatic executor selection.

Chooses between local Docker and cloud API based on:
- Docker availability
- User preference (--executor flag)
- API key presence
"""

def create_executor(executor_type: Optional[str] = None) -> Executor:
    """
    Create appropriate executor.

    Priority:
    1. Explicit --executor flag
    2. Check Docker availability → Use local
    3. Check API key → Use cloud
    4. Error: No executor available
    """
    if executor_type == "local":
        if not is_docker_available():
            raise ExecutorError("Docker not available. Install Docker or use --executor cloud")
        return AutoSandbox()

    if executor_type == "cloud":
        if not has_api_key():
            raise ExecutorError("MCPSF_API_KEY not set. Get key at https://mcpsf.io/api")
        return CloudExecutor()

    # Auto-detect (default)
    if is_docker_available():
        print("[*] Using local Docker executor")
        return AutoSandbox()

    if has_api_key():
        print("[*] Using cloud executor (no local Docker found)")
        return CloudExecutor()

    raise ExecutorError(
        "No executor available!\n"
        "Options:\n"
        "  1. Install Docker: https://docs.docker.com/get-docker/\n"
        "  2. Get API key: https://mcpsf.io/api and set MCPSF_API_KEY"
    )
```

---

## Comparison: Old vs New

| Feature | Phase 6 Design | New Design |
|---------|---------------|------------|
| **Commands** | `assess`, `sandbox`, `targets`, `batch`, `registry` | `assess`, `list`, `show`, `delete`, `detectors` |
| **User setup** | Create YAML configs | Zero config |
| **Sandboxing** | Optional (user decides) | Automatic (always safe) |
| **Mental model** | "Target registry" | "Submit sample" (like malware tools) |
| **Docker knowledge** | Required | Hidden (transparent) |
| **Cloud support** | Not planned | Built-in fallback |
| **CLI complexity** | High (8+ subcommands) | Low (5 commands total) |

---

## Migration from Phase 6

### Keep These Files (90% reusable!)
- ✅ `src/core/lifecycle.py` - Container management (perfect!)
- ✅ `src/core/probe.py` - Auto-detection (perfect!)
- ✅ `src/core/models.py` (core models only)
- ✅ `src/core/runner.py` - Assessment engine
- ✅ `src/modules/` - All detectors

### Delete These Files
- ❌ `src/core/batch_runner.py` - Not needed
- ❌ `src/core/target_registry.py` - Too complex
- ❌ `src/core/reporters/batch_reporter.py` - Not needed
- ❌ Phase 6 CLI commands (targets/registry/batch)

### Create These Files
- ✨ `src/core/auto_sandbox.py` - Automatic sandboxing
- ✨ `src/core/cloud_executor.py` - Cloud API client
- ✨ `src/core/executor_factory.py` - Auto-selection
- ✨ `mcpsf.py` - Simplified CLI (5 commands)

### Net Change
```
Delete: ~1500 lines (batch/registry complexity)
Add:    ~800 lines (auto-sandbox + cloud)
────────────────────────────────────────────
Result: -700 lines, infinitely better UX
```

---

## Summary: Why This Is Better

### 1. **Matches User Mental Model**
"I want to test this MCP" → Just paste the source
No thinking about "sandbox vs non-sandbox"

### 2. **Matches Industry Standards**
Malware sandboxes: Submit sample → Get report
We do the same: Submit MCP → Get report

### 3. **Cloud-Ready from Day 1**
Local executor (Docker) and cloud executor (API) are interchangeable
User doesn't care which one runs - they just get results

### 4. **Simpler Code**
Phase 6: 2500 lines of registry/batch complexity
New design: 1800 lines of auto-sandbox simplicity

### 5. **Better Security**
Default behavior is ALWAYS safe (isolated)
User has to explicitly opt-in to risky localhost testing

---

## Next Steps

**Recommended: Incremental Implementation**

1. **Week 1:** Build `auto_sandbox.py` with npm support only
2. **Week 2:** Test with 5 real npm MCP packages
3. **Week 3:** Add GitHub/local directory support
4. **Week 4:** Implement cloud executor (optional)
5. **Week 5:** Clean up Phase 6 code

**Or: Proof of Concept First**

1. Build minimal `auto_sandbox.py` (200 lines)
2. Test with ONE npm package end-to-end
3. Show working demo
4. Get feedback
5. Expand if successful

What do you think? Should I start implementing the auto_sandbox.py with this simplified design?
