# Auto-Sandbox Implementation Guide

**Last Updated:** 2025-11-19
**Status:** Ready for Implementation
**Goal:** Zero-config automatic MCP sandboxing with transparent Docker isolation

---

## 🎯 The Vision

**User Experience:**
```bash
# User wants to test an MCP from npm
mcpsf assess @modelcontextprotocol/server-time

# System automatically:
# 1. Detects: npm package
# 2. Builds: Docker container with Node.js
# 3. Runs: Container on random port (isolated)
# 4. Tests: All security detectors
# 5. Destroys: Container
# 6. Reports: Results

# User sees:
[*] Detected: npm package @modelcontextprotocol/server-time
[*] Building container... ━━━━━━━━━━━━━━━━ 100%
[*] Starting server... OK
[*] Running assessment (12 detectors)...
[+] Assessment complete: 0 vulnerabilities found
[*] Cleanup complete

Total time: 45 seconds
```

**No Docker knowledge. No YAML files. No manual setup. Just works.**

---

## 🏗️ Architecture Overview

### Design Principle: "Sandbox by Default"

Inspired by malware analysis tools (Cuckoo, Joe Sandbox, ANY.RUN):
- **They don't ask** "Do you want sandbox?"
- **They just always sandbox** - safety is non-negotiable
- **One simple command** - user submits sample, gets report

### Our Approach

**ONE command:**
```bash
mcpsf assess <source> [options]
```

**System automatically decides:**

| Input | Detection | Behavior |
|-------|-----------|----------|
| `@modelcontextprotocol/server-time` | npm package | Build container → Test → Destroy |
| `https://github.com/org/mcp-server` | GitHub repo | Clone → Build container → Test → Destroy |
| `./my-mcp-server` | Local directory | Copy → Build container → Test → Destroy |
| `https://api.example.com:9001/sse` | Remote HTTPS | Direct connection (already isolated) |
| `http://localhost:9001/sse` | Localhost | ⚠️ Warning → User confirms → Direct test |

**User never sees "sandbox" - it's automatic!**

---

## 📦 What We Already Have (Phase 6 Reusable Code)

### ✅ Reusable Components (~1500 lines, 90% ready!)

#### 1. **src/core/lifecycle.py** (292 lines) - ⭐ CORE COMPONENT

**Already implements Docker sandbox execution!**

Key features:
- Docker container launch with `SandboxConfig`
- Network isolation (`--network none`)
- Port mapping
- Volume mounts
- Environment variable injection
- Graceful shutdown (SIGTERM → SIGKILL)
- Multiple ready-check methods (healthcheck/port/log pattern)
- Setup commands (`npm install`, etc.)

**Example usage (already works!):**
```python
from src.core.lifecycle import ManagedServer
from src.core.models import LaunchConfig, SandboxConfig, TransportConfig

launch = LaunchConfig(
    enabled=True,
    sandbox=SandboxConfig(
        type="docker",
        image="node:20-slim",
        cmd="npx",
        args=["-y", "@modelcontextprotocol/server-time"],
        network="none",  # Isolation!
        ports=["9001:9001"]
    ),
    ready_check="port",
    port=9001,
    wait_for_ready=True
)

transport = TransportConfig(type="sse", url="http://localhost:9001/sse")
server = ManagedServer(launch, transport, target_id="test")

await server.start()  # Launches Docker container, waits for ready
# ... do testing ...
await server.stop()   # Graceful cleanup
```

**What's missing:** Just the Dockerfile auto-generation!

---

#### 2. **src/core/probe.py** (292 lines) - ⭐ CORE COMPONENT

**Auto-detects MCP server capabilities after launch**

```python
from src.core.probe import probe_mcp_server

result = await probe_mcp_server("http://localhost:9001/sse", timeout=15)

print(f"Server: {result.server_name}")           # "MCP Time Server"
print(f"Version: {result.server_version}")       # "1.0.0"
print(f"Tools: {len(result.tools)}")             # 2
print(f"Resources: {len(result.resources)}")     # 0
print(f"Tags: {result.suggested_tags}")          # ["time", "utilities"]
```

**100% reusable - no changes needed!**

---

#### 3. **src/core/runner.py** - TestRunner (Assessment Engine)

**Runs all security detectors against MCP server**

```python
from src.core.runner import TestRunner
from src.core.policy import ScopeConfig

scope = ScopeConfig(
    target="http://localhost:9001/sse",
    transport="sse",
    profile="balanced"
)

runner = TestRunner(scope=scope)
result = await runner.assess()

print(f"Vulnerabilities: {len([r for r in result.results if r.status.value == 'PRESENT'])}")
```

**100% reusable - no changes needed!**

---

#### 4. **src/core/models.py** - Core Models

**Pydantic models we need:**
- ✅ `LaunchConfig` - Server launch configuration
- ✅ `SandboxConfig` - Docker sandbox settings
- ✅ `TransportConfig` - SSE/stdio configuration
- ✅ `HealthcheckConfig` - Ready detection
- ✅ `ScopeConfig` - Assessment scope
- ✅ `AssessmentResult` - Test results

**What to delete:**
- ❌ `TargetProfile` (too complex for our use)
- ❌ `TargetRef`, `ProfileOverride`, `ScopeOverride` (registry-specific)
- ❌ `BatchResult`, `TargetFailure` (batch-specific)

---

#### 5. **src/modules/** - All 12 Security Detectors

**100% reusable - no changes needed!**

All detectors work the same way:
```python
detector = SomeDetector(adapter=adapter)
result = await detector.run()
```

---

#### 6. **src/core/reporters/** - Report Generators

**Reusable reporters:**
- ✅ `json_reporter.py` - Machine-readable JSON
- ✅ `sarif_reporter.py` - SARIF 2.1.0 for CI/CD
- ✅ `cli_reporter.py` - Human-readable terminal output

**What to delete:**
- ❌ `batch_reporter.py` - Batch-specific

---

### ❌ Delete These Files (Batch/Registry Complexity)

**Not needed for auto-sandbox:**
- ❌ `src/core/batch_runner.py` (~515 lines) - Parallel orchestration
- ❌ `src/core/target_registry.py` (~292 lines) - YAML registry
- ❌ `src/core/reporters/batch_reporter.py` (~200 lines)
- ❌ `targets/groups/` directory
- ❌ Most of `mcpsf.py` CLI (targets/registry/batch commands)

**Total deletion: ~1500 lines of unnecessary complexity**

---

## 🛠️ What We Need to Build

### New File: `src/core/auto_sandbox.py` (~400 lines)

**Purpose:** Automatic source detection + Dockerfile generation + orchestration

**Key responsibilities:**
1. Detect source type (npm/github/local/https/localhost)
2. Generate appropriate Dockerfile
3. Build Docker image
4. Allocate free port
5. Launch container via existing `ManagedServer`
6. Probe server via existing `probe_mcp_server()`
7. Run assessment via existing `TestRunner`
8. Cleanup (destroy container)

**Implementation outline:**

```python
"""
Automatic MCP Sandboxing - Zero-config transparent isolation.

This module provides the main entry point for automatic MCP assessment
with transparent Docker sandboxing. User never sees Docker - it just works.
"""

import asyncio
import re
import socket
import tempfile
import docker
from pathlib import Path
from typing import Tuple, Dict, Optional, List
from dataclasses import dataclass

from src.core.lifecycle import ManagedServer
from src.core.probe import probe_mcp_server
from src.core.runner import TestRunner
from src.core.models import (
    LaunchConfig,
    SandboxConfig,
    TransportConfig,
    ScopeConfig,
    AssessmentResult
)


class AutoSandbox:
    """
    Automatic MCP sandbox orchestrator.

    Provides zero-config assessment with transparent Docker isolation.
    User submits MCP source → System handles everything automatically.
    """

    def __init__(self):
        """Initialize auto-sandbox."""
        self.docker_client = docker.from_env()

    async def assess(
        self,
        source: str,
        profile: str = "balanced",
        detectors: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        no_cleanup: bool = False
    ) -> AssessmentResult:
        """
        Assess MCP with automatic sandboxing.

        Args:
            source: MCP source (npm/github/local/https/localhost)
            profile: Assessment profile (safe/balanced/aggressive)
            detectors: Optional list of detector IDs to run
            env: Optional environment variables for MCP
            no_cleanup: Keep container after assessment (debugging)

        Returns:
            AssessmentResult

        Raises:
            SourceDetectionError: Cannot determine source type
            DockerError: Docker not available
            AssessmentError: Assessment failed
        """
        # 1. Detect source type
        source_type = self._detect_source(source)
        print(f"[*] Detected: {source_type}")

        # 2. Auto-sandbox if needed
        if source_type in ["npm", "github", "local"]:
            return await self._sandboxed_assess(
                source, source_type, profile, detectors, env, no_cleanup
            )
        elif source_type == "https":
            return await self._direct_assess(source, profile, detectors)
        elif source_type == "localhost":
            # Warning: localhost not sandboxed!
            if not self._confirm_localhost_risk():
                raise AssessmentCancelled("User declined localhost assessment")
            return await self._direct_assess(source, profile, detectors)

    async def _sandboxed_assess(
        self,
        source: str,
        source_type: str,
        profile: str,
        detectors: Optional[List[str]],
        env: Optional[Dict[str, str]],
        no_cleanup: bool
    ) -> AssessmentResult:
        """
        Run assessment in isolated Docker container.

        This is the core sandboxing logic - uses existing lifecycle.py!
        """
        # 1. Generate Dockerfile
        print(f"[*] Generating Dockerfile...")
        dockerfile, context_dir, detected_info = self._generate_dockerfile(source, source_type)

        # 2. Build image
        image_tag = f"mcpsf-sandbox-{detected_info['name']}:latest"
        print(f"[*] Building container...")
        self._build_image(dockerfile, context_dir, image_tag)

        # 3. Allocate free port
        port = self._find_free_port()
        print(f"[*] Allocated port: {port}")

        # 4. Create launch config (uses existing LaunchConfig + SandboxConfig!)
        launch = LaunchConfig(
            enabled=True,
            sandbox=SandboxConfig(
                type="docker",
                image=image_tag,
                network="none",  # Isolation!
                ports=[f"{port}:9001"],
                env=env or {}
            ),
            ready_check="port",
            port=port,
            wait_for_ready=True,
            ready_timeout_s=60
        )

        # 5. Create transport config
        transport = TransportConfig(type="sse", url=f"http://localhost:{port}/sse")

        # 6. Launch container (uses existing ManagedServer!)
        server = ManagedServer(launch, transport, target_id=detected_info["name"])

        try:
            print(f"[*] Starting server...")
            await server.start()
            print(f"[+] Server ready")

            # 7. Probe server (uses existing probe_mcp_server!)
            probe_result = await probe_mcp_server(transport.url, timeout=15)
            print(f"[+] Detected: {probe_result.server_name} v{probe_result.server_version}")

            # 8. Run assessment (uses existing TestRunner!)
            print(f"[*] Running assessment...")
            scope = ScopeConfig(
                target=transport.url,
                transport="sse",
                profile=profile
            )
            runner = TestRunner(scope=scope)
            result = await runner.assess(detector_ids=detectors)

            print(f"[+] Assessment complete")

            return result

        finally:
            # 9. Cleanup (unless debugging)
            if not no_cleanup:
                print(f"[*] Cleanup...")
                await server.stop()
                self.docker_client.images.remove(image_tag, force=True)
                print(f"[+] Cleanup complete")

    async def _direct_assess(
        self,
        url: str,
        profile: str,
        detectors: Optional[List[str]]
    ) -> AssessmentResult:
        """
        Direct assessment (no sandboxing) for remote HTTPS servers.

        Remote servers are already isolated by network boundary.
        """
        print(f"[*] Connecting to remote server...")

        scope = ScopeConfig(
            target=url,
            transport="sse",
            profile=profile
        )
        runner = TestRunner(scope=scope)
        result = await runner.assess(detector_ids=detectors)

        return result

    def _detect_source(self, source: str) -> str:
        """
        Detect source type from input string.

        Returns:
            "npm" | "github" | "local" | "https" | "localhost"

        Examples:
            "@modelcontextprotocol/server-time" → "npm"
            "https://github.com/org/repo" → "github"
            "./my-server" → "local"
            "https://api.com:9001/sse" → "https"
            "http://localhost:9001/sse" → "localhost"
        """
        # npm package (scoped or unscoped)
        if source.startswith("@") or re.match(r'^[a-z0-9-]+$', source):
            return "npm"

        # GitHub URL
        if "github.com" in source:
            return "github"

        # Remote HTTPS
        if source.startswith("https://"):
            return "https"

        # Localhost (WARNING: not sandboxed!)
        if source.startswith("http://localhost") or source.startswith("http://127.0.0.1"):
            return "localhost"

        # Local directory
        path = Path(source)
        if path.exists() and path.is_dir():
            return "local"

        raise SourceDetectionError(f"Cannot determine source type: {source}")

    def _generate_dockerfile(
        self,
        source: str,
        source_type: str
    ) -> Tuple[str, Path, Dict]:
        """
        Generate Dockerfile based on source type.

        This is the AUTO-MAGIC part - detects package.json, requirements.txt, etc.

        Returns:
            (dockerfile_content, build_context_path, detected_info)

        detected_info = {
            "name": "server-time",
            "language": "nodejs",
            "version": "1.0.0"
        }
        """
        if source_type == "npm":
            return self._generate_npm_dockerfile(source)
        elif source_type == "github":
            return self._generate_github_dockerfile(source)
        elif source_type == "local":
            return self._generate_local_dockerfile(source)

    def _generate_npm_dockerfile(self, package: str) -> Tuple[str, Path, Dict]:
        """
        Generate Dockerfile for npm package.

        Strategy: Use npx to install and run package in container.
        """
        # Extract package name (remove scope if present)
        name = package.split("/")[-1]

        dockerfile = f"""
FROM node:20-slim

# Install package globally using npx
RUN npx -y {package}

# Expose default MCP SSE port
EXPOSE 9001

# Run server
CMD ["npx", "-y", "{package}"]
"""

        # Use temp directory as build context
        context_dir = Path(tempfile.mkdtemp(prefix=f"mcpsf-{name}-"))

        detected_info = {
            "name": name,
            "language": "nodejs",
            "package": package
        }

        return (dockerfile, context_dir, detected_info)

    def _generate_github_dockerfile(self, url: str) -> Tuple[str, Path, Dict]:
        """
        Generate Dockerfile for GitHub repository.

        Strategy:
        1. Clone repo to temp directory
        2. Detect language (package.json → Node.js, requirements.txt → Python)
        3. Generate appropriate Dockerfile
        """
        # Parse GitHub URL
        match = re.search(r'github\.com/([^/]+)/([^/]+)', url)
        if not match:
            raise SourceDetectionError(f"Invalid GitHub URL: {url}")

        org, repo = match.groups()
        repo = repo.replace(".git", "")

        # Clone to temp directory
        context_dir = Path(tempfile.mkdtemp(prefix=f"mcpsf-{repo}-"))
        print(f"[*] Cloning {url}...")

        import subprocess
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(context_dir)],
            check=True,
            capture_output=True
        )

        # Detect language
        if (context_dir / "package.json").exists():
            # Node.js project
            dockerfile = """
FROM node:20

WORKDIR /app
COPY . .

RUN npm install
RUN npm run build || true

EXPOSE 9001
CMD ["npm", "start"]
"""
            language = "nodejs"

        elif (context_dir / "requirements.txt").exists():
            # Python project
            dockerfile = """
FROM python:3.10-slim

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 9001
CMD ["python", "server.py"]
"""
            language = "python"

        else:
            raise SourceDetectionError(f"Cannot detect language in {url}")

        detected_info = {
            "name": repo,
            "language": language,
            "url": url
        }

        return (dockerfile, context_dir, detected_info)

    def _generate_local_dockerfile(self, path: str) -> Tuple[str, Path, Dict]:
        """
        Generate Dockerfile for local directory.

        Similar to GitHub, but context is already local.
        """
        context_dir = Path(path).absolute()

        # Detect language
        if (context_dir / "package.json").exists():
            # Node.js project
            dockerfile = """
FROM node:20

WORKDIR /app
COPY . .

RUN npm install
RUN npm run build || true

EXPOSE 9001
CMD ["npm", "start"]
"""
            language = "nodejs"

        elif (context_dir / "requirements.txt").exists():
            # Python project
            dockerfile = """
FROM python:3.10-slim

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 9001
CMD ["python", "server.py"]
"""
            language = "python"

        else:
            raise SourceDetectionError(f"Cannot detect language in {path}")

        detected_info = {
            "name": context_dir.name,
            "language": language,
            "path": str(context_dir)
        }

        return (dockerfile, context_dir, detected_info)

    def _build_image(self, dockerfile: str, context_dir: Path, tag: str) -> None:
        """
        Build Docker image from Dockerfile.

        Uses Docker SDK for Python.
        """
        # Write Dockerfile to context
        dockerfile_path = context_dir / "Dockerfile.mcpsf"
        dockerfile_path.write_text(dockerfile)

        # Build image with progress
        try:
            image, logs = self.docker_client.images.build(
                path=str(context_dir),
                dockerfile="Dockerfile.mcpsf",
                tag=tag,
                rm=True,
                quiet=False
            )

            # Print build logs (optional: can be suppressed)
            for line in logs:
                if 'stream' in line:
                    msg = line['stream'].strip()
                    if msg:
                        print(f"    {msg}")

        except docker.errors.BuildError as e:
            raise DockerBuildError(f"Failed to build image: {e}")

    def _find_free_port(self) -> int:
        """Find an available port on localhost."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def _confirm_localhost_risk(self) -> bool:
        """
        Warn user about localhost assessment risk.

        Localhost servers are NOT sandboxed - they run on user's machine.
        """
        print()
        print("⚠️  WARNING: Assessing localhost server without isolation!")
        print("    The MCP server is running on your machine with full access.")
        print("    This is NOT sandboxed and could be dangerous.")
        print()
        response = input("Continue anyway? (y/N): ")
        return response.lower() == "y"


# Exceptions
class SourceDetectionError(Exception):
    """Cannot determine source type."""
    pass


class DockerBuildError(Exception):
    """Docker image build failed."""
    pass


class AssessmentCancelled(Exception):
    """User cancelled assessment."""
    pass
```

---

### Updated CLI: `mcpsf.py` (~300 lines, simplified!)

**Replace entire file with simplified version:**

```python
#!/usr/bin/env python3
"""
MCP Security Framework (mcpsf) - Command Line Interface

Automatic MCP security testing with transparent sandboxing.
"""

import sys
import asyncio
import argparse
from pathlib import Path

from src.core.auto_sandbox import AutoSandbox
from src.modules.registry import DetectorRegistry


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="MCP Security Framework - Automatic security testing for MCP servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Assess npm package (auto-sandboxed)
  mcpsf assess @modelcontextprotocol/server-time

  # Assess GitHub repo (auto-sandboxed)
  mcpsf assess https://github.com/modelcontextprotocol/servers/tree/main/src/time

  # Assess local directory (auto-sandboxed)
  mcpsf assess ./my-mcp-server

  # Assess remote HTTPS server (direct connection)
  mcpsf assess https://api.example.com:9001/sse

  # With options
  mcpsf assess @mcp/time --profile aggressive
  mcpsf assess ./my-server --env OPENAI_API_KEY=sk-...
  mcpsf assess @mcp/time --detectors MCP-2024-PI-001,MCP-2024-CE-001
"""
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # === ASSESS command ===
    assess_parser = subparsers.add_parser("assess", help="Assess MCP server")
    assess_parser.add_argument(
        "source",
        help="MCP source (npm package / GitHub URL / local path / HTTPS URL)"
    )
    assess_parser.add_argument(
        "--profile",
        choices=["safe", "balanced", "aggressive"],
        default="balanced",
        help="Assessment profile (default: balanced)"
    )
    assess_parser.add_argument(
        "--detectors",
        help="Comma-separated detector IDs to run (default: all)"
    )
    assess_parser.add_argument(
        "--output",
        type=Path,
        default=Path("./reports"),
        help="Output directory for reports (default: ./reports)"
    )
    assess_parser.add_argument(
        "--env",
        action="append",
        help="Environment variable KEY=VALUE (can repeat)"
    )
    assess_parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Keep container after assessment (debugging)"
    )

    # === DETECTORS command ===
    subparsers.add_parser("detectors", help="List available detectors")

    # === VERSION command ===
    subparsers.add_parser("version", help="Show version")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Route to handlers
    if args.command == "assess":
        return asyncio.run(assess_command(args))
    elif args.command == "detectors":
        return detectors_command()
    elif args.command == "version":
        return version_command()


async def assess_command(args):
    """Run assessment command."""
    print()
    print("=" * 70)
    print("  MCP Security Framework v0.4.0")
    print("  Automatic Security Testing with Transparent Sandboxing")
    print("=" * 70)
    print()

    # Parse environment variables
    env = {}
    if args.env:
        for env_pair in args.env:
            key, value = env_pair.split("=", 1)
            env[key] = value

    # Parse detectors
    detectors = None
    if args.detectors:
        detectors = [d.strip() for d in args.detectors.split(",")]

    # Create auto-sandbox
    sandbox = AutoSandbox()

    try:
        # Run assessment
        result = await sandbox.assess(
            source=args.source,
            profile=args.profile,
            detectors=detectors,
            env=env,
            no_cleanup=args.no_cleanup
        )

        # Generate reports
        args.output.mkdir(parents=True, exist_ok=True)

        from src.core.reporters.manager import ReportManager
        from src.core.policy import ScopeConfig

        scope = ScopeConfig(target=args.source, transport="sse", profile=args.profile)
        report_mgr = ReportManager(scope=scope, output_dir=args.output)
        report_mgr.generate_all_reports(result)

        print()
        print("=" * 70)
        print("  ASSESSMENT COMPLETE")
        print("=" * 70)

        # Count vulnerabilities
        vulns = [r for r in result.results if r.status.value == "PRESENT"]
        if vulns:
            print(f"[!] Vulnerabilities found: {len(vulns)}")
            for vuln in vulns:
                severity = vuln.standards.cvss.severity.upper() if vuln.standards and vuln.standards.cvss else "UNKNOWN"
                print(f"    [{severity}] {vuln.detector_id}: {vuln.metadata.name}")
            print()
            print(f"Reports saved to: {args.output}")
            return 1  # Exit code 1 = vulnerabilities found
        else:
            print(f"[+] No vulnerabilities found")
            print(f"Reports saved to: {args.output}")
            return 0  # Exit code 0 = clean

    except Exception as e:
        print(f"\n[!] Assessment failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


def detectors_command():
    """List available detectors."""
    print()
    print("=" * 70)
    print("  Available Security Detectors")
    print("=" * 70)
    print()

    registry = DetectorRegistry()
    registry.load_detectors()
    detectors = registry.get_all_detectors()

    print(f"{'ID':<30} {'Name':<40} {'Severity':<10}")
    print("-" * 85)

    for detector in detectors:
        meta = detector.metadata
        print(f"{meta.id:<30} {meta.name:<40} {meta.severity_default:<10}")

    print()
    print(f"Total: {len(detectors)} detectors")
    print()

    return 0


def version_command():
    """Show version."""
    print("MCP Security Framework v0.4.0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

---

## 🧪 Testing Plan

### Test 1: npm Package (Easiest)
```bash
mcpsf assess @modelcontextprotocol/server-time

Expected:
- Detects: npm
- Builds Node.js container
- Runs server
- Tests it
- Clean = 0 vulnerabilities
```

### Test 2: GitHub Repo
```bash
mcpsf assess https://github.com/modelcontextprotocol/servers/tree/main/src/time

Expected:
- Detects: github
- Clones repo
- Builds Node.js container
- Runs server
- Tests it
```

### Test 3: Local Directory
```bash
mcpsf assess ./targets/mcp_servers/src/time

Expected:
- Detects: local
- Builds container from local code
- Tests it
```

### Test 4: Remote HTTPS (Direct)
```bash
mcpsf assess https://some-remote-mcp.example.com:9001/sse

Expected:
- Detects: https
- Direct connection (no container)
- Tests remote server
```

### Test 5: Localhost (Warning)
```bash
mcpsf assess http://localhost:9001/sse

Expected:
- Detects: localhost
- Shows WARNING
- Asks user confirmation
- If yes → tests directly
```

---

## 📝 Summary

### What We're Building
```
User: mcpsf assess @mcp/time

System:
1. Detects "npm package"
2. Generates Dockerfile (FROM node:20, RUN npx...)
3. Builds image
4. Starts container (uses lifecycle.py)
5. Probes server (uses probe.py)
6. Runs tests (uses runner.py + all detectors)
7. Generates reports (uses reporters/)
8. Destroys container
9. Shows results

User sees: "0 vulnerabilities found in 45 seconds"
```

### Files to Create
- ✨ `src/core/auto_sandbox.py` (~400 lines) - Main implementation
- ✨ `mcpsf.py` (~300 lines) - Simplified CLI

### Files to Delete
- ❌ `src/core/batch_runner.py`
- ❌ `src/core/target_registry.py`
- ❌ `src/core/reporters/batch_reporter.py`
- ❌ Batch-specific models in `models.py`
- ❌ Old CLI commands (targets/registry/batch)

### Files to Keep (No Changes!)
- ✅ `src/core/lifecycle.py` - Docker container management
- ✅ `src/core/probe.py` - Server auto-detection
- ✅ `src/core/runner.py` - Assessment engine
- ✅ `src/modules/` - All detectors
- ✅ `src/core/reporters/` (except batch_reporter.py)

### Result
- **90% code reuse** from Phase 6!
- **Zero-config UX** - just works
- **Automatic sandboxing** - always safe
- **Simple CLI** - 3 commands total

---

## 🚀 Implementation Steps

1. **Create `src/core/auto_sandbox.py`** with all the logic above
2. **Update `mcpsf.py`** with simplified CLI
3. **Delete batch/registry files** to clean up
4. **Test with npm package** (@modelcontextprotocol/server-time)
5. **Test with GitHub repo** (if step 4 works)
6. **Test with local directory** (if step 5 works)
7. **Done!**

---

**Next session should start here and implement `auto_sandbox.py` first!**
