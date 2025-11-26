# Phase 6 Code Audit & Sandbox Architecture Plan

**Date:** 2025-11-19
**Purpose:** Analyze Phase 6 implementation to determine what's useful for true Sandbox mode vs what to abandon

---

## Executive Summary

**Original Phase 6 Goal (misunderstood):** "Make it easy to test MCP servers"
**What Was Built:** Target registry + batch orchestration (assumes user prepares servers)
**What User Actually Wanted:** Zero-config sandbox (system prepares servers automatically)

**Key Finding:** ~60% of Phase 6 code IS useful for Sandbox mode!
**Recommendation:** Refactor Phase 6 into Sandbox foundation, abandon batch-specific parts

---

## Phase 6 Code Inventory

### ✅ KEEP - Highly Valuable for Sandbox

#### 1. **src/core/lifecycle.py** (292 lines) - ⭐ CORE COMPONENT
**Why Keep:**
- Already implements Docker sandbox execution (lines 108-136)
- Has `SandboxConfig` with image/cmd/network/mounts/ports
- Graceful shutdown with force kill
- Healthcheck waiting (endpoint/port/log pattern)
- Setup commands execution (e.g., `npm install`)

**What This Solves for Sandbox:**
```python
# lifecycle.py already supports this!
launch_config = LaunchConfig(
    sandbox=SandboxConfig(
        type="docker",
        image="node:20",
        cmd="npx",
        args=["-y", "@modelcontextprotocol/server-time"],
        network="none",  # Network isolation
        ports=["9001:9001"]
    )
)
managed = ManagedServer(launch_config, ...)
await managed.start()  # Builds container, starts server, waits for ready
# ... test ...
await managed.stop()  # Cleanup
```

**Reusability:** 🟢 95% - Almost perfect for Sandbox mode!
**Changes Needed:**
- Add auto-image-selection logic (detect package.json → use node:20)
- Add auto-port-allocation (find free port)
- Already has everything else!

---

#### 2. **src/core/probe.py** (292 lines) - ⭐ CORE COMPONENT
**Why Keep:**
- Auto-detects server capabilities (tools/resources/prompts)
- Generates intelligent tags
- Extracts server metadata (name/version)
- `to_target_profile()` method for saving configs

**What This Solves for Sandbox:**
```python
# After launching in container, probe it
result = await probe_mcp_server("http://localhost:9001/sse")
print(f"Server: {result.server_name}")
print(f"Tools: {len(result.tools)}")
print(f"Resources: {len(result.resources)}")

# Option: Save for later reuse
profile = result.to_target_profile("my-server")
profile.save("targets/profiles/my-server.yaml")
```

**Reusability:** 🟢 100% - Perfect as-is!
**Changes Needed:** None - works perfectly for Sandbox

---

#### 3. **src/core/models.py** - Partial (LaunchConfig, SandboxConfig, TransportConfig)
**Keep These Models:**
- ✅ `SandboxConfig` (lines 493-503) - Docker/podman config
- ✅ `LaunchConfig` (lines 451-513) - Server launch config
- ✅ `TransportConfig` (lines 416-450) - SSE/stdio config
- ✅ `HealthcheckConfig` (lines 366-381) - Ready detection
- ✅ `ProbeResult` (in probe.py) - Auto-detection results

**Abandon These Models:**
- ❌ `TargetProfile` (lines 600-785) - Too complex for Sandbox
- ❌ `TargetRef` (lines 518-547) - Registry-specific
- ❌ `ProfileOverride` (lines 584-598) - Batch-specific
- ❌ `ScopeOverride` (lines 573-583) - Batch-specific
- ❌ `ReportingConfig` (lines 553-571) - Batch-specific

**Reusability:** 🟡 40% - Keep core models, drop registry models
**Changes Needed:**
- Create new `SandboxProfile` (simpler than TargetProfile)
- Remove registry coupling

---

### ⚠️ MAYBE KEEP - Conditional Value

#### 4. **src/core/target_registry.py** (292 lines) - Registry System
**Current Purpose:** Centralized YAML-based target management for batch ops

**Sandbox Use Case:**
```bash
# User runs sandbox mode
mcpsf sandbox @modelcontextprotocol/server-time

# System asks: "Save this for later?"
→ Save as target? (Y/n): y
→ Target ID: time-server
✓ Saved to targets/profiles/time-server.yaml

# Later: Reuse without re-sandboxing
mcpsf assess --target time-server
```

**Decision:** 🟡 **KEEP but simplify**
- Remove batch-specific features (groups, selectors like `tag=X`)
- Keep basic CRUD (create, read, update, delete targets)
- Becomes "saved sandbox configs" storage

**Reusability:** 🟡 50% - Simplify heavily
**Changes Needed:**
- Remove `select_targets()` DSL (batch-specific)
- Remove groups system (batch-specific)
- Keep `get_target()`, `add_target()`, `list_targets()`

---

#### 5. **mcpsf.py** - CLI Integration
**Current State:** Implements `targets init`, `targets list`, `targets show`, `assess --target-id`

**Sandbox Needs:**
```bash
mcpsf sandbox <source> [options]          # New command
mcpsf sandbox --save-as <id>              # Save after testing
mcpsf list-sandboxes                      # Show saved configs
mcpsf assess --sandbox <id>               # Reuse sandbox
```

**Decision:** 🟡 **KEEP assess --target, DROP batch command**
- Keep `targets list/show` (useful for saved sandboxes)
- Keep `assess --target <id>` (reuse saved sandboxes)
- Remove `targets init --interactive` (replace with `sandbox --interactive`)
- Don't implement `batch` command (not needed yet)

**Reusability:** 🟡 60% - Keep target management parts
**Changes Needed:**
- Add `sandbox` command
- Simplify `targets` subcommands

---

### ❌ ABANDON - Not Useful for Sandbox

#### 6. **src/core/batch_runner.py** (515 lines) - Batch Orchestration
**Purpose:** Parallel multi-target assessment with resume/skip logic

**Why Abandon:**
- Sandbox mode is single-target (one MCP at a time)
- Batch operations are advanced use case (defer to Phase 7)
- Complex state tracking (`.batch_state.json`) not needed for sandbox
- Semaphore-based parallelism not needed for single target

**Decision:** ❌ **DELETE - Not needed for Sandbox**

**Savings:** 515 lines of unnecessary code

---

#### 7. **src/core/reporters/batch_reporter.py** - Batch Reporting
**Purpose:** Aggregate findings across multiple targets

**Why Abandon:**
- Sandbox reports one target at a time (use existing reporters)
- Batch summaries (`summary.json`, `summary.html`) not needed
- Master index not needed for single-target workflow

**Decision:** ❌ **DELETE - Not needed for Sandbox**

---

#### 8. **targets/groups/*.txt** - Group Management
**Purpose:** Predefined target groups for batch selection

**Why Abandon:**
- Batch-specific feature
- Sandbox mode doesn't need groups

**Decision:** ❌ **DELETE - Not needed for Sandbox**

---

#### 9. **targets/.batch_state.json** - Resume State Tracking
**Purpose:** Resume interrupted batch runs

**Why Abandon:**
- Sandbox runs are short (<5 min per MCP)
- If interrupted, just re-run (containers are ephemeral)

**Decision:** ❌ **DELETE - Not needed for Sandbox**

---

## Phase 6 Reusability Summary

| Component | Lines | Status | Reusability | For Sandbox |
|-----------|-------|--------|-------------|-------------|
| lifecycle.py | 292 | ✅ KEEP | 🟢 95% | Start/stop containers |
| probe.py | 292 | ✅ KEEP | 🟢 100% | Auto-detect servers |
| models.py (core) | ~200 | ✅ KEEP | 🟢 90% | LaunchConfig, SandboxConfig |
| models.py (registry) | ~400 | ❌ DROP | 🔴 10% | TargetProfile too complex |
| target_registry.py | 292 | ⚠️ SIMPLIFY | 🟡 50% | Save sandbox configs |
| mcpsf.py (targets) | ~300 | ⚠️ SIMPLIFY | 🟡 60% | Manage saved sandboxes |
| batch_runner.py | 515 | ❌ DELETE | 🔴 5% | Not needed |
| batch_reporter.py | ~200 | ❌ DELETE | 🔴 0% | Not needed |
| **TOTAL** | **~2500** | | **🟡 ~60%** | **~1500 lines reusable** |

---

## Recommended Architecture: Sandbox Mode

### New File: `src/core/sandbox.py` (400 lines estimated)

```python
"""
Zero-config MCP Server Sandbox - Automatic build, test, teardown.

User provides:
  - npm package (@modelcontextprotocol/server-time)
  - GitHub repo (https://github.com/org/mcp-server)
  - Local directory (./my-mcp-server)

System automatically:
  1. Detects MCP type (Node.js/Python)
  2. Generates Dockerfile
  3. Builds Docker image
  4. Starts container with port mapping
  5. Probes server configuration
  6. Runs security assessment
  7. Destroys container
  8. (Optional) Saves config for reuse
"""

from typing import Optional, Tuple, Dict
from pathlib import Path
import re
import asyncio
import docker  # Docker SDK for Python

from src.core.lifecycle import ManagedServer
from src.core.probe import probe_mcp_server, ProbeResult
from src.core.runner import TestRunner
from src.core.models import LaunchConfig, SandboxConfig, TransportConfig, ScopeConfig


class SandboxOrchestrator:
    """
    Zero-config MCP sandbox orchestrator.

    Handles the full lifecycle:
    - Source detection (npm/github/local/docker)
    - Dockerfile generation
    - Container build and launch
    - Assessment
    - Cleanup
    - (Optional) Save for reuse
    """

    def __init__(self, docker_client: Optional[docker.DockerClient] = None):
        self.docker = docker_client or docker.from_env()

    async def sandbox(
        self,
        source: str,
        profile: str = "balanced",
        save_as: Optional[str] = None,
        interactive: bool = False
    ) -> SandboxResult:
        """
        Run zero-config sandbox assessment.

        Args:
            source: MCP source (npm package/github/local path)
            profile: Assessment profile (safe/balanced/aggressive)
            save_as: Optional target ID to save config
            interactive: Ask questions for edge cases

        Returns:
            SandboxResult with assessment findings + container info
        """
        # 1. Detect source type
        source_type, source_info = self._detect_source(source)
        print(f"[*] Detected: {source_type}")

        # 2. Generate Dockerfile (auto-detect from package.json, etc.)
        dockerfile, context_dir = await self._generate_dockerfile(
            source_type, source_info, interactive
        )

        # 3. Build Docker image
        image_tag = f"mcpsf-sandbox-{source_info['name']}:latest"
        print(f"[*] Building image: {image_tag}")
        image = self._build_image(dockerfile, context_dir, image_tag)

        # 4. Allocate free port
        port = self._find_free_port()
        print(f"[*] Allocated port: {port}")

        # 5. Create LaunchConfig with sandbox
        launch_config = LaunchConfig(
            enabled=True,
            sandbox=SandboxConfig(
                type="docker",
                image=image_tag,
                network="none",  # Network isolation by default
                ports=[f"{port}:9001"],  # Map to container's 9001
                env=source_info.get("env", {})
            ),
            ready_check="port",
            port=port,
            wait_for_ready=True,
            ready_timeout_s=30
        )

        # 6. Start container
        transport = TransportConfig(type="sse", url=f"http://localhost:{port}/sse")
        managed = ManagedServer(launch_config, transport, target_id=source_info["name"])

        try:
            await managed.start()
            print(f"[+] Container started")

            # 7. Probe server
            probe_result = await probe_mcp_server(transport.url, timeout=15)
            print(f"[+] Probed: {probe_result.server_name}")

            # 8. Run assessment
            scope = ScopeConfig(
                target=transport.url,
                transport="sse",
                profile=profile
            )
            runner = TestRunner(scope=scope)
            assessment = await runner.assess()

            print(f"[+] Assessment complete")

            # 9. Save if requested
            if save_as:
                self._save_sandbox_config(save_as, probe_result, launch_config)
                print(f"[+] Saved as: {save_as}")

            return SandboxResult(
                assessment=assessment,
                probe=probe_result,
                image_tag=image_tag,
                port=port,
                source_type=source_type
            )

        finally:
            # 10. Cleanup
            await managed.stop()
            print(f"[+] Container stopped")

            # Optional: Remove image (or keep for cache)
            # self.docker.images.remove(image_tag)

    def _detect_source(self, source: str) -> Tuple[str, Dict]:
        """
        Detect source type and extract metadata.

        Returns:
            (source_type, source_info)

        Examples:
            "@modelcontextprotocol/server-time" → ("npm", {"package": "...", "name": "..."})
            "https://github.com/org/repo" → ("github", {"url": "...", "name": "..."})
            "./my-server" → ("local", {"path": "...", "name": "..."})
        """
        # npm package
        if source.startswith("@") or re.match(r'^[a-z0-9-]+$', source):
            return ("npm", {
                "package": source,
                "name": source.split("/")[-1]
            })

        # GitHub URL
        if "github.com" in source:
            match = re.search(r'github\.com/([^/]+)/([^/]+)', source)
            if match:
                org, repo = match.groups()
                return ("github", {
                    "url": source,
                    "org": org,
                    "repo": repo.replace(".git", ""),
                    "name": repo.replace(".git", "")
                })

        # Local path
        path = Path(source)
        if path.exists():
            return ("local", {
                "path": str(path.absolute()),
                "name": path.name
            })

        raise ValueError(f"Unknown source type: {source}")

    async def _generate_dockerfile(
        self,
        source_type: str,
        source_info: Dict,
        interactive: bool
    ) -> Tuple[str, Path]:
        """
        Generate Dockerfile based on source type.

        Returns:
            (dockerfile_content, context_directory)
        """
        if source_type == "npm":
            # Simple npm package sandbox
            dockerfile = f"""
FROM node:20-slim

# Install package globally
RUN npx -y {source_info['package']}

# Expose default MCP SSE port
EXPOSE 9001

# Run server
CMD ["npx", "-y", "{source_info['package']}"]
"""
            # Use temp directory as context
            context_dir = Path(f"/tmp/mcpsf-sandbox-{source_info['name']}")
            context_dir.mkdir(parents=True, exist_ok=True)

            return (dockerfile, context_dir)

        elif source_type == "github":
            # Clone repo and build
            dockerfile = f"""
FROM node:20

WORKDIR /app

# Clone repository
RUN git clone {source_info['url']} .

# Install dependencies
RUN npm install

# Build if needed
RUN npm run build || true

EXPOSE 9001

# Run server (detect from package.json)
CMD ["npm", "start"]
"""
            context_dir = Path(f"/tmp/mcpsf-sandbox-{source_info['name']}")
            context_dir.mkdir(parents=True, exist_ok=True)

            return (dockerfile, context_dir)

        elif source_type == "local":
            # Copy local directory into container
            dockerfile = """
FROM node:20

WORKDIR /app

COPY . .

RUN npm install
RUN npm run build || true

EXPOSE 9001

CMD ["npm", "start"]
"""
            context_dir = Path(source_info['path'])

            return (dockerfile, context_dir)

        else:
            raise ValueError(f"Unsupported source type: {source_type}")

    def _build_image(self, dockerfile: str, context_dir: Path, tag: str) -> str:
        """Build Docker image from Dockerfile."""
        # Write Dockerfile to context
        dockerfile_path = context_dir / "Dockerfile.mcpsf"
        dockerfile_path.write_text(dockerfile)

        # Build image
        image, logs = self.docker.images.build(
            path=str(context_dir),
            dockerfile="Dockerfile.mcpsf",
            tag=tag,
            rm=True
        )

        # Print build logs
        for line in logs:
            if 'stream' in line:
                print(line['stream'].strip())

        return tag

    def _find_free_port(self) -> int:
        """Find an available port."""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def _save_sandbox_config(
        self,
        target_id: str,
        probe_result: ProbeResult,
        launch_config: LaunchConfig
    ) -> None:
        """Save sandbox config as reusable target."""
        from src.core.target_registry import TargetRegistry

        # Convert to TargetProfile (simplified)
        profile = probe_result.to_target_profile(target_id)
        profile.transport.launch = launch_config

        # Save to registry
        profile_path = Path(f"targets/profiles/{target_id}.yaml")
        profile.save(profile_path)

        registry = TargetRegistry.load()
        registry.add_target(
            target_id=target_id,
            profile_path=f"profiles/{target_id}.yaml",
            enabled=True,
            description=f"Sandbox config for {probe_result.server_name}"
        )
        registry.save()


@dataclass
class SandboxResult:
    """Result from sandbox assessment."""
    assessment: AssessmentResult
    probe: ProbeResult
    image_tag: str
    port: int
    source_type: str
```

---

## Updated CLI Commands

### New `mcpsf sandbox` Command
```bash
# Zero-config sandbox testing
mcpsf sandbox @modelcontextprotocol/server-time                    # npm package
mcpsf sandbox https://github.com/org/mcp-server                   # GitHub repo
mcpsf sandbox ./my-mcp-server                                     # Local directory

# With options
mcpsf sandbox @modelcontextprotocol/server-time --profile aggressive
mcpsf sandbox ./my-server --save-as my-server                     # Save for reuse
mcpsf sandbox @mcp/server --interactive                           # Ask questions

# Reuse saved sandbox
mcpsf assess --target my-server                                   # From registry
```

### Simplified `mcpsf targets` Commands
```bash
# List saved sandboxes
mcpsf targets list

# Show sandbox config
mcpsf targets show <id>

# Delete saved sandbox
mcpsf targets delete <id>
```

---

## Migration Plan

### Step 1: Cleanup (Delete Unused Code)
- ❌ Delete `src/core/batch_runner.py` (515 lines)
- ❌ Delete `src/core/reporters/batch_reporter.py` (~200 lines)
- ❌ Delete batch-specific models from `models.py` (~400 lines)
- ❌ Delete `targets/groups/` directory
- ❌ Remove `targets init --interactive` from `mcpsf.py`

**Savings:** ~1100 lines of code

### Step 2: Implement Sandbox (New Code)
- ✅ Create `src/core/sandbox.py` (~400 lines)
- ✅ Add `mcpsf sandbox` command to `mcpsf.py` (~100 lines)
- ✅ Add Dockerfile auto-generation logic (~200 lines)
- ✅ Integrate with existing lifecycle.py, probe.py (no changes needed!)

**New Code:** ~700 lines

### Step 3: Simplify Registry (Refactor)
- ⚠️ Remove `select_targets()` DSL from `target_registry.py` (~100 lines)
- ⚠️ Remove groups support (~50 lines)
- ⚠️ Keep basic CRUD operations

**Net Change:** -150 lines

### Net LOC Change
```
Phase 6 code:      ~2500 lines
Delete unused:     -1100 lines
Add sandbox:       +700 lines
Simplify registry: -150 lines
─────────────────────────────
Final:             ~1950 lines (-22% code reduction!)
```

---

## How Sandbox Reaches the Goal

### Original Goal
> "User inputs required data for MCP to run, system tests it automatically"

### How Sandbox Achieves This

**Example 1: npm package**
```bash
$ mcpsf sandbox @modelcontextprotocol/server-time

[*] Detected: npm
[*] Building image: mcpsf-sandbox-server-time:latest
Step 1/4 : FROM node:20-slim
Step 2/4 : RUN npx -y @modelcontextprotocol/server-time
Step 3/4 : EXPOSE 9001
Step 4/4 : CMD ["npx", "-y", "@modelcontextprotocol/server-time"]
[+] Image built successfully
[*] Allocated port: 35821
[*] Launching server...
[+] Container started
[+] Probed: MCP Time Server v1.0.0
[*] Running security assessment (balanced profile)...
[+] Assessment complete

════════════════════════════════════════════════════════════════
  ASSESSMENT RESULTS
════════════════════════════════════════════════════════════════
[+] Server: MCP Time Server v1.0.0
[+] Tools: 2 (get_current_time, get_timezone)
[+] Resources: 0
[+] Vulnerabilities: 0
[+] Status: CLEAN

[+] Container stopped

Save this configuration for later? (Y/n): y
Target ID: time-server
[+] Saved as: time-server

→ Next time: mcpsf assess --target time-server
```

**User Input Required:** Just the npm package name
**System Automated:** Everything else!

---

**Example 2: GitHub repo (interactive mode)**
```bash
$ mcpsf sandbox https://github.com/org/custom-mcp --interactive

[*] Detected: github
[*] Cloning repository...
[?] This MCP requires environment variables. Provide them now? (y/N): y
[?] Enter OPENAI_API_KEY: sk-***
[?] Enter DATABASE_URL: (press Enter to skip):

[*] Building image...
[*] Launching container...
[+] Assessment complete
[+] Vulnerabilities found: 2 (1 HIGH, 1 MEDIUM)

Save this configuration? (Y/n): n
[+] Container destroyed
```

**User Input Required:** GitHub URL + optional env vars
**System Automated:** Clone, build, test, cleanup!

---

## Conclusion

### What to Keep from Phase 6
- ✅ **lifecycle.py** - Already has Docker sandbox support!
- ✅ **probe.py** - Auto-detection works perfectly
- ✅ **Core models** - LaunchConfig, SandboxConfig, TransportConfig
- ⚠️ **target_registry.py** - Simplify to "saved sandboxes" storage
- ⚠️ **mcpsf.py targets** - Keep basic list/show/delete

### What to Delete
- ❌ **batch_runner.py** - Not needed for Sandbox
- ❌ **batch_reporter.py** - Not needed for Sandbox
- ❌ **Batch-specific models** - TargetProfile too complex
- ❌ **Groups system** - Batch-specific

### What to Build
- ✨ **sandbox.py** - Zero-config orchestrator
- ✨ **mcpsf sandbox** - New CLI command
- ✨ **Dockerfile auto-generation** - Detect from package.json/requirements.txt

### Result
**60% of Phase 6 code is reusable for Sandbox!**
The misunderstanding was in the complexity (YAML configs, batch mode), not the foundation.

**With refactoring:**
- Delete ~1100 lines of batch-specific code
- Add ~700 lines of sandbox-specific code
- Net result: 22% less code, 100% better UX

**The good news:** lifecycle.py already does Docker sandboxing! We just need to add auto-generation on top.
