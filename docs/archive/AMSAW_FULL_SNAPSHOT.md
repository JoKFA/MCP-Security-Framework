# AMSAW Code Snapshot

Generated for cross-AI context sharing. Contains verbatim code from key AMSAW modules and related helpers/tests (read-only mirror).


## src/core/pipeline.py
`$lang"""
Assessment Pipeline for AMSAW v2.

Orchestrates the full assessment flow from source to report.

Architecture:
============

This is the MAIN ENTRY POINT for AMSAW v2. It wires together:
- Phase 1: Discovery Engine
- Phase 2: Provisioner
- Phase 3: Universal Bridge
- Phase 4: TestRunner (existing!)

Flow:
    User Input (source string)
          �?
    Discovery Engine �?ServerConfig
          �?
    Provisioner �?ProvisionedContainer
          �?
    Universal Bridge �?Normalized HTTP URL
          �?
    TestRunner �?AssessmentResult
          �?
    Reports (JSON, SARIF, CLI)

Design Principles:
==================

1. **Error Handling at Each Phase**
   - Discovery fails �?Clear error message
   - Provisioning fails �?Cleanup and report
   - Bridge fails �?Cleanup and report
   - Assessment fails �?Still generate partial report

2. **Guaranteed Cleanup**
   - Use try/finally blocks
   - Always stop containers
   - Always cleanup temp directories
   - Even on Ctrl+C

3. **Progress Reporting**
   - Print clear status messages
   - Show which phase is running
   - Report timing information

4. **Backwards Compatible**
   - Can still assess remote HTTPS URLs directly
   - Falls back to old behavior for localhost
   - Doesn't break existing workflows
"""

import asyncio
from typing import Optional, List
from pathlib import Path

from src.core.discovery import SourceDiscovery, ServerConfig, SourceDetectionError, MCPNotFoundError
from src.core.provisioner import ContainerProvisioner, ProvisionedContainer
from src.core.bridge import UniversalBridge
from src.core.runner import TestRunner
from src.core.policy import ScopeConfig
from src.core.models import AssessmentResult


class AssessmentPipeline:
    """
    Orchestrates end-to-end MCP assessment.

    This is the main entry point for AMSAW v2.

    Usage:
        pipeline = AssessmentPipeline()
        result = await pipeline.run("@modelcontextprotocol/server-time")
        # Returns: AssessmentResult
    """

    def __init__(self, interactive: bool = True):
        """
        Initialize Assessment Pipeline.

        Args:
            interactive: If True, prompt user for credentials. If False, auto-provision mocks.
        """
        self.discovery = SourceDiscovery()
        self.provisioner = ContainerProvisioner(interactive=interactive)

    async def run(
        self,
        source: str,
        profile: str = "balanced",
        detectors: Optional[List[str]] = None
    ) -> AssessmentResult:
        """
        Run full assessment pipeline.

        Args:
            source: MCP source (npm/github/local/https)
            profile: Assessment profile (safe/balanced/aggressive)
            detectors: Optional list of detector IDs to run

        Returns:
            AssessmentResult from TestRunner

        Raises:
            SourceDetectionError: Cannot determine source type
            MCPNotFoundError: No MCP SDK found
            AssessmentError: Assessment failed
        """
        import time
        start_time = time.time()

        print("=" * 70)
        print("  AMSAW v2 - Automatic MCP Security Assessment")
        print("=" * 70)
        print()

        container = None
        bridge = None
        runner = None
        provisioned = None

        try:
            # Phase 1: Discovery
            print("[Phase 1] Discovery Engine")
            print("-" * 70)
            configs = self.discovery.discover(source)
            if not configs:
                raise MCPNotFoundError(f"No MCP servers found in: {source}")

            config = configs[0]  # Use first config
            print(f"[+] Found: {config.name}")
            print(f"[+] Language: {config.language}")
            print(f"[+] Transport: {config.transport}")
            print()

            # Phase 2: Provisioner
            print("[Phase 2] Container Provisioner")
            print("-" * 70)
            provisioned = await self.provisioner.provision(config)

            if provisioned.container_id:
                print(f"[+] Container: {provisioned.container_id[:12]}")
                print(f"[+] Image: {provisioned.image}")
                if provisioned.mocks:
                    print(f"[+] Mocks: {', '.join(provisioned.mocks.keys())}")
                print()

                # Phase 3: Universal Bridge
                print("[Phase 3] Universal Bridge")
                print("-" * 70)
                bridge = UniversalBridge(
                    provisioned.container_id,
                    mcp_command=provisioned.mcp_command,
                    container_port=config.sse_port or 9001,
                    transport_hint=config.transport
                )
                await bridge.start()
                url = bridge.get_url()
                print(f"[+] Bridge URL: {url}")
                print(f"[+] Transport: {bridge.transport_type}")
                print()

            else:
                # Remote HTTPS server - no container needed
                url = source
                print(f"[+] Remote server: {url}")
                print()

            # Phase 4: TestRunner (existing code!)
            print("[Phase 4] Security Assessment")
            print("-" * 70)
            scope = ScopeConfig(
                target=url,
                transport=config.transport,
                mode=profile
            )
            runner = TestRunner(scope=scope)
            result = await runner.assess(detector_ids=detectors)

            elapsed = time.time() - start_time
            print()
            print("=" * 70)
            print(f"  Assessment Complete ({elapsed:.1f}s)")
            print("=" * 70)
            print(f"  Vulnerabilities: {result.summary.get('present', 0)}")
            # Calculate total detectors run by summing all status counts
            total_detectors = sum(result.summary.values())
            print(f"  Detectors Run: {total_detectors}")
            print("=" * 70)
            print()

            return result

        except Exception as e:
            print()
            print("=" * 70)
            # Encode/decode to avoid console crashes on Windows with Unicode banners
            error_msg = str(e).encode("utf-8", errors="replace").decode("utf-8", errors="replace")
            error_msg = error_msg.encode("cp1252", errors="replace").decode("cp1252", errors="replace")
            print(f"  Assessment Failed: {error_msg}")
            print("=" * 70)
            raise

        finally:
            # Cleanup (ALWAYS runs!)
            print()
            print("[Cleanup] Stopping services...")

            if runner:
                try:
                    await runner.cleanup()
                except Exception as e:
                    print(f"[!] Warning: Runner cleanup failed: {e}")

            if bridge:
                try:
                    await bridge.stop()
                except Exception as e:
                    print(f"[!] Warning: Bridge cleanup failed: {e}")

            if provisioned and provisioned.container_id:
                try:
                    container = self.provisioner.docker_client.containers.get(
                        provisioned.container_id
                    )
                    container.stop(timeout=2)
                    container.remove()
                    print(f"[+] Container {provisioned.container_id[:12]} removed")
                except Exception as e:
                    print(f"[!] Warning: Container cleanup failed: {e}")

            try:
                await self.provisioner.cleanup()
            except Exception as e:
                print(f"[!] Warning: Provisioner cleanup failed: {e}")

            print("[+] Cleanup complete")
            print()

`\n## src/core/discovery.py
`$lang"""
Source Discovery Engine for AMSAW v2.

Detects MCP servers from various source types and extracts configuration.

Architecture:
============

Input: User provides a "source" string
  - npm package: "@modelcontextprotocol/server-time"
  - GitHub URL: "https://github.com/modelcontextprotocol/servers/tree/main/src/time"
  - Local path: "./targets/dv-mcp/challenges/1"
  - HTTPS URL: "https://api.example.com:9001/sse"

Output: List[ServerConfig]
  - name: "server-time"
  - source_type: "npm" | "github" | "local" | "https"
  - language: "python" | "nodejs"
  - entry_point: ["npx", "-y", "@mcp/server-time"] or ["python", "-m", "server"]
  - transport: "stdio" | "sse"
  - dependencies: ["fastapi", "uvicorn"] (for auto-provisioning)
  - env_vars: {"DATABASE_URL": None} (required env vars)

Design Principles:
==================

1. **AST-Based Detection** (not heuristics!)
   - Parse Python/Node.js AST to find actual entry points
   - Look for MCP SDK imports/usage
   - Determine transport type from code

2. **Monorepo Support**
   - Return List[ServerConfig] (can detect multiple MCPs in one repo)
   - Each config is independent

3. **Fast Failure**
   - If can't detect language �?raise error
   - If no MCP SDK found �?raise error
   - Don't waste time on non-MCP projects

4. **Deterministic**
   - Same source always produces same ServerConfig
   - No randomness, no guessing
"""

import ast
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ServerConfig:
    """
    Configuration for a single MCP server.

    This is what the Provisioner needs to launch a container.
    """
    name: str
    source_type: str  # "npm" | "github" | "local" | "https"
    language: str  # "python" | "nodejs"
    entry_point: List[str]  # Command to run MCP (e.g., ["npx", "-y", "@mcp/server-time"])
    transport: str  # "stdio" | "sse"

    # Optional metadata
    dependencies: List[str] = field(default_factory=list)
    env_vars: Dict[str, Optional[str]] = field(default_factory=dict)
    sse_port: Optional[int] = None
    project_root: Optional[Path] = None
    # New optional fields to support extended strategies without breaking callers
    strategy: str = "source"
    image_ref: Optional[str] = None


class SourceDiscovery:
    """
    Discovers MCP servers from various source types.

    Usage:
        discovery = SourceDiscovery()
        configs = discovery.discover("@modelcontextprotocol/server-time")
        # Returns: [ServerConfig(name="server-time", ...)]
    """

    def discover(self, source: str) -> List[ServerConfig]:
        """
        Discover MCP server(s) from source.

        Args:
            source: npm package, GitHub URL, local path, or HTTPS URL

        Returns:
            List[ServerConfig] (can be multiple for monorepos)

        Raises:
            SourceDetectionError: Cannot determine source type
            MCPNotFoundError: No MCP SDK found in source
        """
        source_type = self._detect_source_type(source)
        print(f"[*] Detected source type: {source_type}")

        if source_type == "npm":
            return [self._analyze_npm_package(source)]
        elif source_type == "github":
            return self._analyze_github_repo(source)
        elif source_type == "local":
            return self._analyze_local_path(source)
        elif source_type in ["https", "http", "localhost"]:
            return [self._analyze_remote_url(source)]
        else:
            raise SourceDetectionError(f"Unknown source type: {source_type}")

    def _detect_source_type(self, source: str) -> str:
        """
        Detect source type from input string.

        Returns:
            "npm" | "github" | "local" | "https" | "http"
        """
        # npm package (scoped or unscoped)
        if source.startswith("@") or re.match(r'^[a-z0-9-]+$', source):
            return "npm"

        # GitHub URL
        if "github.com" in source:
            return "github"

        # HTTP/HTTPS URL
        if source.startswith("http://") or source.startswith("https://"):
            parsed = urlparse(source)
            host = parsed.hostname or ""
            # Distinguish localhost from remote
            if host in {"localhost", "127.0.0.1"}:
                return "localhost"
            return "https" if source.startswith("https://") else "http"

        # Local directory
        path = Path(source)
        if path.exists() and path.is_dir():
            return "local"

        raise SourceDetectionError(f"Cannot determine source type: {source}")

    def _analyze_npm_package(self, package: str) -> ServerConfig:
        """
        Analyze npm package.

        Strategy:
        - Most npm MCP packages use stdio transport
        - Entry point is always: npx -y <package>
        - No AST analysis needed (package is self-contained)

        Returns:
            ServerConfig for npm package
        """
        # Extract package name (remove scope if present)
        name = package.split("/")[-1]

        return ServerConfig(
            name=name,
            source_type="npm",
            language="nodejs",
            entry_point=["npx", "-y", package],
            transport="stdio",  # npm packages default to stdio
            dependencies=[],  # npx handles dependencies
            env_vars={}
        )

    def _analyze_github_repo(self, url: str) -> List[ServerConfig]:
        """
        Analyze GitHub repository.

        Strategy:
        1. Clone repo root to temp directory (handles /tree/<branch>/<path>)
        2. Detect language (Python or Node.js)
        3. Run AST analysis to find MCP servers
        4. Return List[ServerConfig] (can be multiple for monorepos)

        Returns:
            List[ServerConfig] (one or more servers)
        """
        # Parse GitHub URL
        match = re.search(r'github\.com/([^/]+)/([^/]+)', url)
        if not match:
            raise SourceDetectionError(f"Invalid GitHub URL: {url}")

        org, repo = match.groups()
        repo = repo.replace(".git", "")

        branch = None
        sub_path = None
        if "/tree/" in url:
            # Example: .../tree/main/src/time -> branch=main, sub_path=src/time
            suffix = url.split("/tree/", 1)[1]
            parts = suffix.split("/", 1)
            branch = parts[0] if parts else None
            sub_path = parts[1] if len(parts) > 1 else None

        # Clone to temp directory (default branch or specified branch)
        temp_dir = Path(tempfile.mkdtemp(prefix=f"mcpsf-{repo}-"))
        clone_url = f"https://github.com/{org}/{repo}.git"
        print(f"[*] Cloning {clone_url} to {temp_dir} (branch: {branch or 'default'})...")

        clone_cmd = ["git", "clone", "--depth", "1"]
        if branch:
            clone_cmd.extend(["--branch", branch])
        clone_cmd.extend([clone_url, str(temp_dir)])

        try:
            subprocess.run(
                clone_cmd,
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            raise SourceDetectionError(f"Failed to clone {clone_url}: {e.stderr.decode()}")

        # If a sub-path was requested, analyze that directory if it exists
        if sub_path:
            candidate = temp_dir / sub_path
            if candidate.exists() and candidate.is_dir():
                print(f"[*] Using subdirectory for analysis: {candidate}")
                return self._analyze_local_path(str(candidate))
            else:
                print(f"[!] Subpath '{sub_path}' not found in cloned repo; analyzing repo root instead.")

        # Analyze cloned repo
        return self._analyze_local_path(str(temp_dir))

    def _analyze_local_path(self, path: str) -> List[ServerConfig]:
        """
        Analyze local directory.

        Strategy:
        1. Detect language (Python or Node.js)
        2. Search up directory tree for package.json or pyproject.toml
        3. Run AST analysis to find MCP servers
        4. Return List[ServerConfig]

        Returns:
            List[ServerConfig] (one or more servers)
        """
        current_path = Path(path).absolute()
        project_root = None

        # Search up directory tree for config files (max 5 levels up)
        for _ in range(5):
            if (current_path / "package.json").exists():
                package_json_path = current_path / "package.json"
                try:
                    with open(package_json_path, "r") as f:
                        pkg_meta = json.load(f)
                except Exception:
                    pkg_meta = {}

                deps = pkg_meta.get("dependencies", {})
                dev_deps = pkg_meta.get("devDependencies", {})
                all_deps = {**deps, **dev_deps}
                has_sdk = "@modelcontextprotocol/sdk" in all_deps
                name_has_mcp = "mcp" in pkg_meta.get("name", "").lower()
                desc_has_mcp = "mcp" in pkg_meta.get("description", "").lower()

                # If package.json suggests MCP (SDK or metadata), treat as Node MCP
                if has_sdk or name_has_mcp or desc_has_mcp:
                    project_root = current_path
                    return self._analyze_nodejs_project(project_root)

                # Otherwise, if a Python project exists alongside, analyze as Python MCP
                if (current_path / "pyproject.toml").exists() or (current_path / "requirements.txt").exists():
                    project_root = current_path
                    return self._analyze_python_project(project_root, entry_script=Path(path))

                # No MCP hints found
                raise MCPNotFoundError(f"No MCP SDK or metadata hints found in {current_path}")
            elif (current_path / "pyproject.toml").exists() or (current_path / "requirements.txt").exists():
                project_root = current_path
                return self._analyze_python_project(project_root, entry_script=Path(path))

            # Move up one directory
            parent = current_path.parent
            if parent == current_path:  # Reached root
                break
            current_path = parent

        raise SourceDetectionError(f"Cannot detect language in {path} (no package.json or pyproject.toml found)")

    def _analyze_python_project(self, project_root: Path, entry_script: Path = None) -> List[ServerConfig]:
        """
        Analyze Python project using AST.

        Strategy:
        1. Find all .py files (or use provided entry_script)
        2. Parse AST to look for MCP SDK imports
        3. Determine transport type (stdio vs SSE)
        4. Extract entry point from pyproject.toml or __main__.py

        Args:
            project_root: Root directory of the project
            entry_script: Specific script to analyze (for subdirectories)

        Returns:
            List[ServerConfig]
        """
        configs = []

        # Read pyproject.toml for entry points
        pyproject_path = project_root / "pyproject.toml"
        entry_points = {}
        if pyproject_path.exists():
            import tomllib
            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
                scripts = data.get("project", {}).get("scripts", {})
                entry_points = scripts

        # Find Python files with MCP SDK usage
        mcp_files = []

        # If entry_script provided, use it directly
        if entry_script and entry_script.is_file() and entry_script.suffix == ".py":
            try:
                with open(entry_script, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=str(entry_script))

                has_mcp = self._has_mcp_import(tree)
                if has_mcp:
                    transport = self._detect_python_transport(tree)
                    mcp_files.append((entry_script, transport))
            except Exception as e:
                print(f"[!] Warning: Failed to parse {entry_script}: {e}")

        # Otherwise, search for .py files
        if not mcp_files:
            search_root = entry_script if entry_script and entry_script.is_dir() else project_root
            for py_file in search_root.rglob("*.py"):
                # Skip virtualenv and cache
                if any(part in {"venv", ".venv", "__pycache__", "site-packages"} for part in py_file.parts):
                    continue

                # Parse AST
                try:
                    with open(py_file, "r", encoding="utf-8") as f:
                        tree = ast.parse(f.read(), filename=str(py_file))

                    # Look for MCP imports
                    has_mcp = self._has_mcp_import(tree)
                    if has_mcp:
                        transport = self._detect_python_transport(tree)
                        mcp_files.append((py_file, transport))
                except Exception:
                    continue

        if not mcp_files:
            raise MCPNotFoundError(f"No MCP SDK found in {entry_script or project_root}")

        # Create configs from detected files
        for py_file, transport in mcp_files:
            # Determine entry point
            if entry_points:
                # Use first entry point that looks like a server
                script_name = None
                for name in entry_points.keys():
                    if "mcp" in name.lower() or "server" in name.lower():
                        script_name = name
                        break
                if not script_name:
                    script_name = list(entry_points.keys())[0]

                entry_point = [script_name]
            else:
                # Use module path or direct file execution
                try:
                    # Try to get relative path
                    py_file_abs = py_file.absolute()
                    project_root_abs = project_root.absolute()
                    rel_path = py_file_abs.relative_to(project_root_abs)
                    module = str(rel_path.with_suffix("")).replace("/", ".").replace("\\", ".")
                    if module.startswith("src."):
                        module = module[4:]
                    entry_point = ["python", "-m", module]
                except ValueError:
                    # File is outside project_root, use direct execution
                    rel_path = py_file_abs.relative_to(py_file_abs.parent.parent)
                    entry_point = ["python", str(rel_path)]

            # Detect SSE port if using SSE transport
            sse_port = None
            if transport == "sse":
                sse_port = self._detect_python_sse_port(py_file)

            configs.append(ServerConfig(
                name=project_root.name,
                source_type="local",
                language="python",
                entry_point=entry_point,
                transport=transport,
                dependencies=[],  # TODO: Parse from requirements.txt
                env_vars={},
                sse_port=sse_port,
                project_root=project_root
            ))

        # CRITICAL: Prioritize SSE servers over stdio servers
        # Many MCPs have both server.py (stdio) and server_sse.py (SSE)
        # SSE is easier to test and more reliable for automated assessment
        sse_configs = [c for c in configs if c.transport == "sse"]
        if sse_configs:
            return [sse_configs[0]]

        return configs[:1]  # Return first config only (avoid duplicates)

    def _analyze_nodejs_project(self, project_root: Path) -> List[ServerConfig]:
        """
        Analyze Node.js project using package.json.

        Strategy:
        1. Read package.json
        2. Look for MCP SDK in dependencies
        3. Extract entry point from bin or main
        4. Detect transport from code

        Returns:
            List[ServerConfig]
        """
        package_json_path = project_root / "package.json"
        with open(package_json_path, "r") as f:
            pkg = json.load(f)

        # Check for MCP SDK (relaxed)
        deps = pkg.get("dependencies", {})
        dev_deps = pkg.get("devDependencies", {})
        all_deps = {**deps, **dev_deps}

        has_official_sdk = "@modelcontextprotocol/sdk" in all_deps
        name_has_mcp = "mcp" in pkg.get("name", "").lower()
        desc_has_mcp = "mcp" in pkg.get("description", "").lower()

        if not (has_official_sdk or name_has_mcp or desc_has_mcp):
            raise MCPNotFoundError(f"No MCP SDK found in {project_root}")
        if not has_official_sdk:
            print(f"[!] Warning: MCP SDK not declared in dependencies for {project_root}, proceeding based on metadata")

        # Extract entry point
        entry_point = None
        if "bin" in pkg:
            bin_val = pkg["bin"]
            if isinstance(bin_val, dict):
                entry_point = list(bin_val.keys())[0]  # Use first bin
            else:
                entry_point = bin_val
        elif "main" in pkg:
            entry_point = pkg["main"]
        else:
            entry_point = "index.js"

        # Detect transport
        transport = self._detect_nodejs_transport(project_root)

        return [ServerConfig(
            name=pkg.get("name", project_root.name),
            source_type="local",
            language="nodejs",
            entry_point=["node", entry_point],
            transport=transport,
            dependencies=[],
            env_vars={},
            project_root=project_root
        )]

    def _analyze_remote_url(self, url: str) -> ServerConfig:
        """
        Analyze remote HTTPS URL.

        For remote URLs, we assume:
        - Transport is SSE (remote servers use HTTP)
        - No local analysis needed
        - Direct connection

        Returns:
            ServerConfig for remote URL
        """
        parsed = urlparse(url)
        host = parsed.hostname or "unknown"

        return ServerConfig(
            name=host,
            source_type="https",
            language="unknown",  # Don't know language for remote
            entry_point=[],  # No entry point for remote
            transport="sse",  # Remote servers use SSE/HTTP
            dependencies=[],
            env_vars={},
            sse_port=parsed.port or 443
        )

    def _has_mcp_import(self, tree: ast.AST) -> bool:
        """Check if AST has MCP SDK import."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "mcp" in alias.name:
                        return True
            elif isinstance(node, ast.ImportFrom):
                if node.module and "mcp" in node.module:
                    return True
        return False

    def _detect_python_transport(self, tree: ast.AST) -> str:
        """
        Detect transport type from Python AST using structural signals.

        We score evidence for stdio vs SSE and pick the higher score.
        Default is stdio (safer fallback).
        """
        analyzer = TransportAnalyzer()
        analyzer.visit(tree)
        print(f"[*] Transport Analysis - Stdio Score: {analyzer.stdio_score}, SSE Score: {analyzer.sse_score}")
        if analyzer.sse_score > analyzer.stdio_score:
            return "sse"
        return "stdio"

    def _detect_python_sse_port(self, py_file: Path) -> int:
        """
        Detect the port used by the Python SSE server.

        Looks for common patterns in the code:
        - self.port = 9002
        - port = 9001
        - uvicorn.run(..., port=9003)

        Args:
            py_file: Path to Python file to analyze

        Returns:
            Port number (default: 9001 if not detected)
        """
        try:
            if not py_file.exists():
                return 9001

            text = py_file.read_text(encoding="utf-8", errors="ignore")

            # Look for common port assignment patterns
            patterns = [
                r'self\.port\s*=\s*(\d+)',      # self.port = 9002
                r'port\s*=\s*(\d+)',            # port = 9001 (variable assignment)
                r'uvicorn\.run\([^)]*port\s*=\s*(\d+)',  # uvicorn.run(..., port=9003)
                r'PORT\s*=\s*(\d+)',            # PORT = 9001 (constant)
            ]

            for pattern in patterns:
                match = re.search(pattern, text)
                if match:
                    detected_port = int(match.group(1))
                    print(f"[+] Detected SSE port: {detected_port} (from {py_file.name})")
                    return detected_port

            # Default to 9001
            return 9001

        except Exception as e:
            print(f"[!] Warning: Failed to detect port from {py_file}: {e}")
            return 9001

    def _detect_nodejs_transport(self, project_root: Path) -> str:
        """Detect transport type from Node.js code."""
        # Simple heuristic: look for express/fastify in dependencies
        package_json_path = project_root / "package.json"
        with open(package_json_path, "r") as f:
            pkg = json.load(f)

        deps = pkg.get("dependencies", {})
        if "express" in deps or "fastify" in deps:
            return "sse"
        return "stdio"


# Exceptions
class SourceDetectionError(Exception):
    """Cannot determine source type."""
    pass


class MCPNotFoundError(Exception):
    """No MCP SDK found in source."""
    pass


class TransportAnalyzer(ast.NodeVisitor):
    """
    Analyze Python AST to score likelihood of stdio vs SSE transport.

    Scoring:
    - Stdio signals (+10): FastMCP(), StdioServerTransport, mcp.run()
    - SSE signals (+10): FastAPI/Starlette, SseServerTransport
    - uvicorn.run: +5 SSE
    - transport arg: transport="sse" (+20), transport="stdio" (+20)
    """

    def __init__(self):
        self.stdio_score = 0
        self.sse_score = 0

    def visit_Call(self, node):
        name = self._get_func_name(node)
        if name:
            # Stdio indicators
            if "FastMCP" in name:
                self.stdio_score += 10
            if "mcp.run" in name:
                self.stdio_score += 10
            if "StdioServerTransport" in name:
                self.stdio_score += 10

            # SSE indicators
            if "FastAPI" in name or "Starlette" in name:
                self.sse_score += 10
            if "SseServerTransport" in name:
                self.sse_score += 10
            if "uvicorn.run" in name:
                self.sse_score += 5

            # Transport arg hints
            for kw in node.keywords:
                if kw.arg == "transport" and isinstance(kw.value, ast.Constant):
                    if kw.value.value == "sse":
                        self.sse_score += 20
                    elif kw.value.value == "stdio":
                        self.stdio_score += 20

        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if "fastapi" in alias.name or "starlette" in alias.name:
                self.sse_score += 2
            if "uvicorn" in alias.name:
                self.sse_score += 2
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            if "mcp.server.fastmcp" in node.module:
                self.stdio_score += 2
            if "mcp.server.sse" in node.module:
                self.sse_score += 5
            if "mcp.server.stdio" in node.module:
                self.stdio_score += 5
        self.generic_visit(node)

    def _get_func_name(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

`\n## src/core/provisioner.py
`$lang"""
Container Provisioner for AMSAW v2.

Launches sidecar containers with auto-provisioned mocks.

Architecture:
============

The Provisioner is responsible for:
1. Launching long-running sidecar containers (sleep infinity)
2. Auto-provisioning mocks (PostgreSQL, WireMock, etc.)
3. Volume-mounting code (Runner Pattern - no docker build!)
4. Crash analysis loop (auto-recover from startup errors)

Design Principles:
==================

1. **Runner Pattern (No Docker Build!)**
   - Volume-mount code into pre-built fat images
   - Install dependencies at runtime (uv/npm are fast!)
   - No Dockerfile generation, no image building
   - Launch in <2 seconds

2. **Auto-Provisioning Mocks**
   - Detect dependencies (postgres, mongo, stripe, etc.)
   - Start mock containers automatically
   - Inject connection strings via env vars
   - Clean up mocks after assessment

3. **Crash Analysis Loop**
   - Launch container, check if it crashes
   - Read logs to detect missing dependencies
   - Auto-provision missing mocks
   - Retry up to 3 times

4. **Clean Separation**
   - Provisioner manages container lifecycle
   - Bridge manages transport normalization
   - TestRunner manages security testing
"""

import asyncio
import docker
import time
import shlex
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import httpx

from src.core.discovery import ServerConfig


@dataclass
class ProvisionedContainer:
    """
    A provisioned container ready for the Bridge.

    This is what the Provisioner returns after successfully launching a container.
    """
    container_id: str
    image: str
    language: str
    mcp_command: List[str]
    transport: str
    mocks: Dict[str, str] = None  # Mock service name �?connection string

    def __post_init__(self):
        if self.mocks is None:
            self.mocks = {}


class ContainerProvisioner:
    """
    Provisions sidecar containers for MCP assessment.

    Usage:
        provisioner = ContainerProvisioner()
        container = await provisioner.provision(server_config)
        # Returns: ProvisionedContainer(container_id="abc123", ...)
    """

    def __init__(self, interactive: bool = True):
        """
        Initialize Container Provisioner.

        Args:
            interactive: If True, prompt user for credentials. If False, auto-provision mocks.
        """
        self.docker_client = docker.from_env()
        self.mock_containers: List[docker.models.containers.Container] = []
        self.interactive = interactive

    async def provision(self, config: ServerConfig) -> ProvisionedContainer:
        """
        Provision a sidecar container for the given ServerConfig.

        Strategy:
        1. Select fat image (mcp-runner-python or mcp-runner-node)
        2. Launch sidecar container (sleep infinity)
        3. Volume-mount code (if local/github)
        4. Auto-provision mocks (if needed)
        5. Return ProvisionedContainer

        Args:
            config: ServerConfig from Discovery Engine

        Returns:
            ProvisionedContainer ready for Bridge

        Raises:
            ProvisioningError: Failed to provision container
        """
        print(f"[*] Provisioning container for: {config.name}")

        # Select fat image
        if config.language == "python":
            image = "mcp-runner-python:latest"
        elif config.language == "nodejs":
            image = "mcp-runner-node:latest"
        else:
            # For remote HTTPS servers, no container needed
            return ProvisionedContainer(
                container_id="",
                image="",
                language="",
                mcp_command=[],
                transport=config.transport
            )

        # Prepare volume mounts (Runner Pattern)
        volumes = {}
        if config.project_root:
            # Volume-mount code into container
            volumes[str(config.project_root.absolute())] = {
                'bind': '/app',
                'mode': 'rw'
            }

        # Prepare environment variables
        environment = {}

        # Prompt user for credentials/env vars first (if interactive), then auto-provision mocks if needed
        if config.dependencies:
            if self.interactive:
                user_env = await self._prompt_for_credentials(config.dependencies, config.name)
                environment.update(user_env)
            else:
                user_env = {}

            # Only provision mocks for dependencies not provided by user
            mocks = await self._provision_mocks(config.dependencies, user_env)
            environment.update(mocks)

        # Launch sidecar container
        print(f"[*] Launching sidecar container: {image}")

        # If using SSE transport, publish the SSE port to host
        ports = None
        if config.transport == "sse":
            target_port = config.sse_port or 9001
            ports = {f"{target_port}/tcp": None}  # None -> random host port

        container = self.docker_client.containers.run(
            image,
            command=["sleep", "infinity"],  # Keep alive!
            detach=True,
            stdin_open=True,
            volumes=volumes if volumes else None,
            environment=environment if environment else None,
            ports=ports,
            network_mode="bridge"
        )

        print(f"[+] Sidecar container launched: {container.short_id}")

        # Install dependencies at runtime (Runner Pattern)
        if config.project_root:
            await self._install_dependencies(container, config)

        # CRITICAL: For SSE servers, detect CLI and update config BEFORE starting server
        if config.transport == "sse" and config.entry_point:
            # Pre-detect CLI to get correct port before starting server
            updated_entry, updated_port = self._detect_cli_before_start(container, config)
            if updated_entry:
                config.entry_point = updated_entry
            if updated_port and updated_port != (config.sse_port or 9001):
                print(f"[!] Port mismatch detected: container expects {config.sse_port or 9001} but server uses {updated_port}")
                print(f"[!] Recreating container with correct port...")
                # Stop and remove current container
                container.stop()
                container.remove()
                # Update config and recreate
                config.sse_port = updated_port
                ports = {f"{updated_port}/tcp": None}
                container = self.docker_client.containers.run(
                    image,
                    command=["sleep", "infinity"],
                    detach=True,
                    stdin_open=True,
                    volumes=volumes if volumes else None,
                    environment=environment if environment else None,
                    ports=ports,
                    network_mode="bridge"
                )
                print(f"[+] Sidecar container recreated with port {updated_port}: {container.short_id}")
                # Reinstall dependencies
                if config.project_root:
                    await self._install_dependencies(container, config)

            await self._start_sse_server(container, config)

        return ProvisionedContainer(
            container_id=container.id,
            image=image,
            language=config.language,
            mcp_command=config.entry_point,
            transport=config.transport,
            mocks=environment
        )

    async def _install_dependencies(
        self,
        container: docker.models.containers.Container,
        config: ServerConfig
    ) -> None:
        """
        Install dependencies at runtime using uv (Python) or npm (Node.js).

        This is the RUNNER PATTERN - no docker build needed!
        """
        if config.language == "python":
            print(f"[*] Installing Python dependencies...")
            # Check for requirements.txt or pyproject.toml
            if (config.project_root / "requirements.txt").exists():
                result = container.exec_run(
                    "pip install -r /app/requirements.txt",
                    workdir="/app"
                )
                if result.exit_code != 0:
                    print(f"[!] Warning: pip install failed: {result.output.decode()}")

            # Install project itself (for entry points)
            result = container.exec_run("pip install -e /app", workdir="/app")
            if result.exit_code == 0:
                print(f"[+] Python dependencies installed")

        elif config.language == "nodejs":
            print(f"[*] Installing Node.js dependencies...")
            # Run npm install
            result = container.exec_run("npm install", workdir="/app")
            if result.exit_code != 0:
                print(f"[!] Warning: npm install failed: {result.output.decode()}")
            else:
                print(f"[+] Node.js dependencies installed")

            # Run build if package.json has build script
            result = container.exec_run("npm run build || true", workdir="/app")

    async def _prompt_for_credentials(self, dependencies: List[str], server_name: str) -> Dict[str, str]:
        """
        Prompt user for API keys and environment variables.

        This runs BEFORE auto-provisioning mocks, giving users the option to provide
        real credentials instead of using mocked services.

        Args:
            dependencies: List of dependency names
            server_name: Name of the MCP server being assessed

        Returns:
            Dict of user-provided env vars
        """
        env_vars = {}

        print()
        print("=" * 70)
        print(f"  Environment Configuration for: {server_name}")
        print("=" * 70)
        print("  Detected dependencies. Please provide credentials if available.")
        print("  Leave blank to use auto-provisioned mocks.")
        print("-" * 70)

        # Common API keys
        api_keys_to_check = {
            "OPENAI_API_KEY": ["openai", "gpt"],
            "ANTHROPIC_API_KEY": ["anthropic", "claude"],
            "BRAVE_API_KEY": ["brave"],
            "GITHUB_TOKEN": ["github", "pygithub", "octokit"],
            "STRIPE_API_KEY": ["stripe"],
            "AWS_ACCESS_KEY_ID": ["boto3", "aws"],
            "GOOGLE_API_KEY": ["google", "googleapis"],
        }

        for env_var, dep_patterns in api_keys_to_check.items():
            if any(pattern in dep.lower() for dep in dependencies for pattern in dep_patterns):
                user_input = input(f"  {env_var} (leave blank for mock): ").strip()
                if user_input:
                    env_vars[env_var] = user_input
                    print(f"  [+] Using user-provided {env_var}")

        # Database URLs
        db_urls_to_check = {
            "DATABASE_URL": ["psycopg2", "postgresql", "postgres", "mysql", "sqlite"],
            "MONGODB_URL": ["pymongo", "mongodb", "mongo"],
            "REDIS_URL": ["redis"],
        }

        for env_var, dep_patterns in db_urls_to_check.items():
            if any(dep in dep_patterns for dep in dependencies):
                user_input = input(f"  {env_var} (leave blank for mock): ").strip()
                if user_input:
                    env_vars[env_var] = user_input
                    print(f"  [+] Using user-provided {env_var}")

        # Generic env vars (for any other common patterns)
        if not env_vars:
            print("  [*] No credentials provided. Will use auto-provisioned mocks.")

        print("=" * 70)
        print()

        return env_vars

    def _detect_cli_before_start(
        self,
        container: docker.models.containers.Container,
        config: ServerConfig
    ) -> tuple:
        """
        Detect CLI command and port BEFORE starting server.
        This allows us to recreate container with correct port if needed.

        Returns:
            (entry_point, port) tuple
        """
        entry_point = config.entry_point
        detected_port = None

        # Try CLI auto-detection for Python/Node MCP servers
        should_detect = False
        module_name = None
        base_command = entry_point

        # Case 1: python -m module
        if len(entry_point) >= 3 and entry_point[0] == "python" and entry_point[1] == "-m":
            should_detect = True
            module_name = entry_point[2]
        # Case 2: Just module name (like 'markitdown-mcp')
        elif len(entry_point) == 1 and config.language == "python":
            should_detect = True
            module_name = entry_point[0].replace('-', '_')
            base_command = ["python", "-m", module_name]
        # Case 3: npx -y package
        elif len(entry_point) >= 3 and entry_point[0] == "npx" and entry_point[1] == "-y":
            should_detect = True
            module_name = entry_point[2]

        if should_detect:
            from src.core.cli_detector import detect_cli_command
            try:
                detected_cmd = detect_cli_command(
                    container=container,
                    module=module_name,
                    transport="sse",
                    base_command=base_command
                )
                if detected_cmd != entry_point:
                    print(f"[*] CLI auto-detection adjusted command:")
                    print(f"    Original: {' '.join(entry_point)}")
                    print(f"    Detected: {' '.join(detected_cmd)}")
                    entry_point = detected_cmd

                    # Extract port from detected command
                    if "--port" in detected_cmd:
                        try:
                            port_idx = detected_cmd.index("--port")
                            if port_idx + 1 < len(detected_cmd):
                                detected_port = int(detected_cmd[port_idx + 1])
                        except (ValueError, IndexError):
                            pass
            except Exception as e:
                print(f"[!] Warning: CLI auto-detection failed: {e}")

        return entry_point, detected_port

    async def _start_sse_server(self, container: docker.models.containers.Container, config: ServerConfig) -> None:
        """
        Start an SSE MCP server inside the sidecar and verify it is reachable before returning.

        This avoids the "sleep infinity" sidecar doing nothing: we explicitly launch the MCP
        server with nohup and poll its /sse endpoint to confirm it is live.
        """
        print(f"[*] Starting SSE server in background...")

        # Construct safe shell command (config.entry_point already updated by _detect_cli_before_start)
        cmd = " ".join(shlex.quote(part) for part in config.entry_point)
        log_path = "/tmp/mcp_server.log"
        shell_cmd = f"cd /app && nohup {cmd} > {log_path} 2>&1 & echo $!"

        result = container.exec_run(["sh", "-c", shell_cmd], workdir="/app")
        if result.exit_code not in (0, None):
            raise ProvisioningError(
                f"Failed to launch SSE server (exit {result.exit_code}): {result.output.decode(errors='ignore')}"
            )

        # Wait for the server to become reachable on the HOST (port is published)
        port = config.sse_port or 9001
        container.reload()
        ports_map = container.attrs['NetworkSettings']['Ports'] or {}
        port_key = f"{port}/tcp"
        if port_key not in ports_map or not ports_map[port_key]:
            raise ProvisioningError(f"Could not find mapped port for {port_key} in container settings")

        host_port = ports_map[port_key][0]['HostPort']
        url = f"http://127.0.0.1:{host_port}/sse"
        last_error = None
        for attempt in range(20):  # ~10 seconds total
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    async with client.stream("GET", url, headers={"accept": "text/event-stream"}) as resp:
                        if resp.status_code < 500:
                            print(f"[+] SSE server responding (HTTP {resp.status_code}) at {url}")
                            return
                        else:
                            print(f"[!] SSE readiness attempt {attempt+1} got HTTP {resp.status_code}")
            except Exception as e:
                last_error = e
                print(f"[*] SSE readiness attempt {attempt+1} failed: {e}")
            await asyncio.sleep(0.5)

        # Pull logs to aid debugging
        log_result = container.exec_run(["sh", "-c", f"tail -n 50 {log_path}"])
        log_tail = log_result.output.decode(errors="ignore") if log_result.exit_code == 0 else ""

        # Try to detect and install missing system dependencies
        if self._detect_and_install_system_deps(container, log_tail, config):
            print(f"[*] Retrying SSE server startup after installing dependencies...")
            # Retry server startup once
            result = container.exec_run(["sh", "-c", shell_cmd], workdir="/app")
            if result.exit_code in (0, None):
                # Wait for server again
                for attempt in range(10):  # Shorter retry
                    try:
                        async with httpx.AsyncClient(timeout=5.0) as client:
                            async with client.stream("GET", url, headers={"accept": "text/event-stream"}) as resp:
                                if resp.status_code < 500:
                                    print(f"[+] SSE server responding (HTTP {resp.status_code}) at {url} after retry")
                                    return
                    except Exception:
                        pass
                    await asyncio.sleep(0.5)

        raise ProvisioningError(
            f"SSE server did not become ready at {url}. "
            f"Last error: {last_error}. "
            f"Log tail:\\n{log_tail}"
        )

    def _detect_and_install_system_deps(
        self,
        container: docker.models.containers.Container,
        error_output: str,
        config: ServerConfig
    ) -> bool:
        """
        Detect and install missing system dependencies from error messages.

        Args:
            container: Docker container
            error_output: Error logs from server startup
            config: Server configuration

        Returns:
            True if any packages were installed
        """
        import re

        # Map error patterns to system packages
        dependency_patterns = {
            r"couldn'?t find ffmpeg|ffmpeg.*not found": ["ffmpeg"],
            r"pandoc.*not found": ["pandoc"],
            r"poppler.*not found|pdftotext.*not found": ["poppler-utils"],
            r"imagemagick.*not found": ["imagemagick"],
            r"tesseract.*not found": ["tesseract-ocr"],
        }

        # Detect missing packages
        packages_to_install = []
        for pattern, pkgs in dependency_patterns.items():
            if re.search(pattern, error_output, re.IGNORECASE):
                packages_to_install.extend(pkgs)
                print(f"[*] Detected missing system dependency: {', '.join(pkgs)}")

        # Also guess based on server name
        name_lower = config.name.lower()
        if "markdown" in name_lower or "pdf" in name_lower:
            if "ffmpeg" not in packages_to_install:
                packages_to_install.append("ffmpeg")
            if "pandoc" not in packages_to_install:
                packages_to_install.append("pandoc")

        # Deduplicate
        packages_to_install = list(set(packages_to_install))

        if not packages_to_install:
            return False

        print(f"[*] Installing system dependencies: {', '.join(packages_to_install)}")

        # Update package list
        result = container.exec_run(["apt-get", "update", "-qq"], workdir="/app")
        if result.exit_code != 0:
            print(f"[!] Warning: apt-get update failed")
            return False

        # Install packages
        installed_any = False
        for package in packages_to_install:
            print(f"    Installing {package}...")
            result = container.exec_run(
                ["apt-get", "install", "-y", "-qq", package],
                workdir="/app"
            )
            if result.exit_code == 0:
                print(f"[+] Installed {package}")
                installed_any = True
            else:
                print(f"[!] Failed to install {package}")

        return installed_any

    async def _provision_mocks(self, dependencies: List[str], user_env: Dict[str, str]) -> Dict[str, str]:
        """
        Auto-provision mock services based on dependencies.

        This is called AFTER prompting the user. Only provisions mocks for
        dependencies where the user didn't provide credentials.

        Strategy:
        1. Detect database dependencies (postgres, mongo, mysql)
        2. Check if user already provided credentials
        3. Launch mock containers only if needed (docker-compose style)
        4. Return connection strings as env vars

        Args:
            dependencies: List of dependency names
            user_env: Dict of user-provided env vars (skip mocking for these)

        Returns:
            Dict of env vars (e.g., {"DATABASE_URL": "postgres://..."})
        """
        env_vars = {}

        # PostgreSQL mock (only if user didn't provide DATABASE_URL)
        if "DATABASE_URL" not in user_env and any(dep in ["psycopg2", "postgresql", "postgres"] for dep in dependencies):
            print(f"[*] Provisioning PostgreSQL mock...")
            pg_container = self.docker_client.containers.run(
                "postgres:14-alpine",
                detach=True,
                environment={
                    "POSTGRES_USER": "mcpsf",
                    "POSTGRES_PASSWORD": "mcpsf",
                    "POSTGRES_DB": "mcpsf"
                },
                remove=True
            )
            self.mock_containers.append(pg_container)

            # Get container IP
            pg_container.reload()
            ip = pg_container.attrs['NetworkSettings']['IPAddress']
            env_vars['DATABASE_URL'] = f"postgresql://mcpsf:mcpsf@{ip}:5432/mcpsf"
            print(f"[+] PostgreSQL mock: {env_vars['DATABASE_URL']}")

        # MongoDB mock (only if user didn't provide MONGODB_URL)
        if "MONGODB_URL" not in user_env and any(dep in ["pymongo", "mongodb", "mongo"] for dep in dependencies):
            print(f"[*] Provisioning MongoDB mock...")
            mongo_container = self.docker_client.containers.run(
                "mongo:6-jammy",
                detach=True,
                remove=True
            )
            self.mock_containers.append(mongo_container)

            mongo_container.reload()
            ip = mongo_container.attrs['NetworkSettings']['IPAddress']
            env_vars['MONGODB_URL'] = f"mongodb://{ip}:27017"
            print(f"[+] MongoDB mock: {env_vars['MONGODB_URL']}")

        return env_vars

    async def cleanup(self):
        """
        Clean up all provisioned containers and mocks.

        This should be called in a finally block!
        """
        print(f"[*] Cleaning up provisioned containers...")

        # Stop and remove mock containers
        for mock in self.mock_containers:
            try:
                mock.stop(timeout=2)
                # Container is already set to remove=True
            except Exception as e:
                print(f"[!] Warning: Failed to stop mock {mock.short_id}: {e}")

        self.mock_containers.clear()
        print(f"[+] Cleanup complete")


class ProvisioningError(Exception):
    """Failed to provision container."""
    pass

`\n## src/core/bridge.py
`$lang"""
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
- TestRunner �?Bridge �?Container:9001/sse

Stdio Transport (Sidecar Pattern):
- Container launched with: `docker run -d <image> sleep infinity`
- Bridge executes: `docker exec -i <container> <mcp_command>`
- Bridge attaches to exec session's stdin/stdout streams
- FastAPI server wraps stdin (POST /message) and stdout (GET /sse)
- TestRunner �?Bridge �?docker exec �?MCP process

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
        ┌─────────────────────────────────────────────────────────�?
        �? TestRunner (HTTP client)                               �?
        �?      �?                                                 �?
        �? http://localhost:{self.local_port}/sse                 �?
        └─────────────────────────────────────────────────────────�?
                        �?
        ┌─────────────────────────────────────────────────────────�?
        �? Bridge Process (FastAPI)                               �?
        �? - POST /message �?exec session stdin                   �?
        �? - GET /sse �?exec session stdout (SSE stream)          �?
        └─────────────────────────────────────────────────────────�?
                        �?
        ┌─────────────────────────────────────────────────────────�?
        �? Docker Exec Session (inside sidecar container)         �?
        �? $ npx -y @modelcontextprotocol/server-time             �?
        �? - Reads from stdin (JSON-RPC)                          �?
        �? - Writes to stdout (JSON-RPC responses)                �?
        └─────────────────────────────────────────────────────────�?
                        �?
        ┌─────────────────────────────────────────────────────────�?
        �? Sidecar Container (long-running)                       �?
        �? $ sleep infinity  �?Keeps container alive!             �?
        └─────────────────────────────────────────────────────────�?

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

`\n## src/core/cli_detector.py
`$lang"""
CLI Command Detector for MCP Servers.

Automatically detects the correct command-line syntax for different MCP servers
by parsing help output and trying common patterns.

Strategy:
1. Parse --help output to detect supported flags
2. Try common CLI patterns in order of likelihood
3. Validate each attempt by checking exit code / output
4. Return the working command

This eliminates the need for manual command overrides!
"""

import re
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class CLIPattern:
    """A detected CLI pattern for running an MCP server."""
    command: List[str]
    transport: str  # "sse" or "stdio"
    port: Optional[int] = None
    confidence: float = 0.0  # 0.0 to 1.0


class CLIDetector:
    """
    Detects correct CLI syntax for MCP servers.

    Usage:
        detector = CLIDetector()
        pattern = detector.detect(container, module="markitdown_mcp", transport="sse")
        # Returns: ["python", "-m", "markitdown_mcp", "--sse", "--port", "3001"]
    """

    # Common SSE flag patterns (in order of likelihood)
    SSE_PATTERNS = [
        ["--sse"],           # Most common
        ["--http"],          # Also common
        ["sse"],             # Positional arg
        ["--transport", "sse"],
        ["--mode", "sse"],
    ]

    # Common stdio flag patterns
    STDIO_PATTERNS = [
        [],                  # No args (default stdio)
        ["--stdio"],
        ["stdio"],
        ["--transport", "stdio"],
    ]

    def detect(
        self,
        container,
        module: str,
        transport: str = "sse",
        base_command: List[str] = None
    ) -> CLIPattern:
        """
        Detect correct CLI command for MCP server.

        Args:
            container: Docker container object
            module: Python module name or entry point
            transport: Desired transport ("sse" or "stdio")
            base_command: Base command (e.g., ["python", "-m", "module"])

        Returns:
            CLIPattern with detected command

        Strategy:
            1. Parse --help to understand CLI interface
            2. Try common patterns for desired transport
            3. Validate by attempting to start server
            4. Return first working pattern
        """
        if base_command is None:
            base_command = ["python", "-m", module]

        print(f"[*] Auto-detecting CLI syntax for: {module}")

        # Step 1: Parse help output
        help_info = self._parse_help(container, base_command)

        # Step 2: Generate candidate commands based on help
        candidates = self._generate_candidates(
            base_command,
            transport,
            help_info
        )

        # Step 3: Test each candidate
        for candidate in candidates:
            if self._validate_command(container, candidate, transport):
                print(f"[+] Detected working command: {' '.join(candidate.command)}")
                return candidate

        # Fallback: return base command with best guess
        print(f"[!] Warning: Could not auto-detect CLI syntax, using best guess")
        return CLIPattern(
            command=base_command,
            transport=transport,
            confidence=0.3
        )

    def _parse_help(
        self,
        container,
        base_command: List[str]
    ) -> Dict[str, any]:
        """
        Parse --help output to understand CLI interface.

        Returns:
            Dict with detected flags, options, defaults
        """
        # Use timeout to prevent hanging on servers that don't support --help
        cmd = base_command + ["--help"]
        cmd_str = " ".join(cmd)
        test_cmd = f"timeout 2 {cmd_str} 2>&1 || true"
        result = container.exec_run(["sh", "-c", test_cmd], workdir="/app")

        if result.exit_code not in (0, 124):  # 0=success, 124=timeout
            # Try -h
            cmd = base_command + ["-h"]
            cmd_str = " ".join(cmd)
            test_cmd = f"timeout 2 {cmd_str} 2>&1 || true"
            result = container.exec_run(["sh", "-c", test_cmd], workdir="/app")

        if result.exit_code not in (0, 124):  # No help available
            return {}

        help_text = result.output.decode('utf-8', errors='ignore')

        info = {
            'has_sse_flag': False,
            'has_http_flag': False,
            'has_stdio_flag': False,
            'has_transport_arg': False,
            'default_port': None,
            'port_flag': None,
        }

        # Detect flags
        if re.search(r'--sse\b', help_text):
            info['has_sse_flag'] = True
        if re.search(r'--http\b', help_text):
            info['has_http_flag'] = True
        if re.search(r'--stdio\b', help_text):
            info['has_stdio_flag'] = True
        if re.search(r'--transport\b', help_text):
            info['has_transport_arg'] = True

        # Detect port flag and default
        port_match = re.search(r'(--port)\s+.*?default[:\s]+(\d+)', help_text, re.IGNORECASE)
        if port_match:
            info['port_flag'] = port_match.group(1)
            info['default_port'] = int(port_match.group(2))
        elif re.search(r'--port\b', help_text):
            info['port_flag'] = '--port'

        print(f"[*] Parsed help: SSE={info['has_sse_flag']}, HTTP={info['has_http_flag']}, "
              f"Port={info['default_port']}")

        return info

    def _generate_candidates(
        self,
        base_command: List[str],
        transport: str,
        help_info: Dict
    ) -> List[CLIPattern]:
        """
        Generate candidate commands based on help info.

        Returns:
            List of CLIPattern sorted by confidence
        """
        candidates = []

        if transport == "sse":
            # Pattern 1: Use detected SSE flag (highest confidence)
            if help_info.get('has_sse_flag'):
                cmd = base_command + ["--sse"]
                if help_info.get('port_flag') and help_info.get('default_port'):
                    cmd += [help_info['port_flag'], str(help_info['default_port'])]
                candidates.append(CLIPattern(cmd, "sse", help_info.get('default_port'), 0.95))

            # Pattern 2: Use --http flag
            if help_info.get('has_http_flag'):
                cmd = base_command + ["--http"]
                if help_info.get('port_flag') and help_info.get('default_port'):
                    cmd += [help_info['port_flag'], str(help_info['default_port'])]
                candidates.append(CLIPattern(cmd, "sse", help_info.get('default_port'), 0.90))

            # Pattern 3: Use --transport sse
            if help_info.get('has_transport_arg'):
                cmd = base_command + ["--transport", "sse"]
                candidates.append(CLIPattern(cmd, "sse", confidence=0.85))

            # Pattern 4: Positional "sse"
            candidates.append(CLIPattern(base_command + ["sse"], "sse", confidence=0.70))

            # Pattern 5: Try common port 9001
            candidates.append(CLIPattern(
                base_command + ["--sse", "--port", "9001"],
                "sse",
                port=9001,
                confidence=0.60
            ))

        elif transport == "stdio":
            # Pattern 1: No args (stdio is often default)
            candidates.append(CLIPattern(base_command, "stdio", confidence=0.95))

            # Pattern 2: --stdio flag
            if help_info.get('has_stdio_flag'):
                candidates.append(CLIPattern(base_command + ["--stdio"], "stdio", confidence=0.90))

            # Pattern 3: Positional "stdio"
            candidates.append(CLIPattern(base_command + ["stdio"], "stdio", confidence=0.70))

        # Sort by confidence
        candidates.sort(key=lambda x: x.confidence, reverse=True)
        return candidates

    def _validate_command(
        self,
        container,
        pattern: CLIPattern,
        expected_transport: str
    ) -> bool:
        """
        Validate that a command works by attempting to start the server.

        Strategy:
            - Run command in background
            - Check if it starts without errors
            - For SSE: verify port is listening
            - For stdio: verify it accepts input

        Returns:
            True if command works
        """
        # Quick syntax check - run with timeout
        cmd_str = " ".join(pattern.command)
        test_cmd = f"timeout 2 {cmd_str} 2>&1 || true"

        result = container.exec_run(["sh", "-c", test_cmd], workdir="/app")
        output = result.output.decode('utf-8', errors='ignore')

        # Check for error patterns
        error_patterns = [
            r'error: unrecognized arguments',
            r'invalid choice',
            r'Usage:',  # Only if followed by error
            r'no such option',
            r'Traceback \(most recent call last\)',
        ]

        for pattern_re in error_patterns:
            if re.search(pattern_re, output, re.IGNORECASE):
                print(f"[!] Command failed validation: {' '.join(pattern.command)}")
                print(f"    Error: {output[:200]}")
                return False

        # If no obvious errors, consider it valid
        # (We can't do full server startup validation here as it would be too slow)
        print(f"[+] Command passed validation: {' '.join(pattern.command)}")
        return True


def detect_cli_command(
    container,
    module: str,
    transport: str,
    base_command: List[str] = None
) -> List[str]:
    """
    Convenience function to detect CLI command.

    Returns:
        Command as list of strings
    """
    detector = CLIDetector()
    pattern = detector.detect(container, module, transport, base_command)
    return pattern.command

`\n## src/core/lifecycle.py
`$lang"""
Server Lifecycle Management - Launch and shutdown MCP servers.

This module solves the "hard targets" problem by automatically starting
and stopping MCP servers as needed for assessment.

Key features:
- Automatic server launch from LaunchConfig
- Healthcheck-based ready detection
- Port-based ready detection
- Log pattern-based ready detection
- Graceful shutdown with fallback to force kill
"""

import asyncio
import subprocess
import time
import re
import socket
from pathlib import Path
from typing import Optional, Tuple
import psutil

from src.core.models import LaunchConfig, HealthcheckConfig, TransportConfig


class LifecycleError(Exception):
    """Base exception for lifecycle errors."""
    pass


class ServerLaunchError(LifecycleError):
    """Raised when server launch fails."""
    pass


class ServerNotReadyError(LifecycleError):
    """Raised when server doesn't become ready in time."""
    pass


class ManagedServer:
    """
    Manages the lifecycle of an MCP server process.

    This class handles:
    - Launching the server process
    - Waiting for it to become ready
    - Graceful shutdown
    - Force kill if needed
    """

    def __init__(
        self,
        launch_config: LaunchConfig,
        transport_config: TransportConfig,
        healthcheck_config: Optional[HealthcheckConfig] = None,
        target_id: str = "unknown"
    ):
        """
        Initialize managed server.

        Args:
            launch_config: Launch configuration
            transport_config: Transport configuration (fallback for command)
            healthcheck_config: Healthcheck configuration
            target_id: Target ID (for logging)
        """
        self.launch_config = launch_config
        self.transport_config = transport_config
        self.healthcheck_config = healthcheck_config
        self.target_id = target_id

        self.process: Optional[subprocess.Popen] = None
        self.pid: Optional[int] = None
        self.container_id: Optional[str] = None  # Docker/Podman container ID if sandboxed

    async def start(self) -> None:
        """
        Launch server and wait for it to be ready.

        Raises:
            ServerLaunchError: If launch fails
            ServerNotReadyError: If server doesn't become ready
        """
        if not self.launch_config.enabled:
            raise ServerLaunchError("Launch not enabled in configuration")

        print(f"[*] Launching server: {self.target_id}")

        # Determine command
        command = self.launch_config.command or self.transport_config.command
        if not command and not (self.launch_config.sandbox and self.launch_config.sandbox.image):
            raise ServerLaunchError("No launch command specified")

        # Determine args
        args = self.launch_config.args or self.transport_config.args

        # Determine working directory
        cwd = self.launch_config.working_dir or self.transport_config.working_dir

        # Build environment
        env = dict(self.transport_config.env)
        env.update(self.launch_config.env)

        # Base command before sandbox wrapping
        full_cmd = [command] + args if command else []

        # Optional sandbox wrapping
        sandbox = self.launch_config.sandbox
        if sandbox:
            if sandbox.type not in ("docker", "podman"):
                raise ServerLaunchError(f"Unsupported sandbox type: {sandbox.type}")
            sandbox_cmd = [sandbox.type, "run", "--rm"]
            if sandbox.network:
                sandbox_cmd += ["--network", sandbox.network]
            for m in sandbox.mounts:
                sandbox_cmd += ["-v", m]
            for p in sandbox.ports:
                sandbox_cmd += ["-p", p]
            for k, v in sandbox.env.items():
                sandbox_cmd += ["-e", f"{k}={v}"]
            if sandbox.workdir:
                sandbox_cmd += ["-w", sandbox.workdir]

            if not sandbox.image:
                raise ServerLaunchError("Sandbox image is required when sandboxing is enabled")

            # Command inside container
            inner_cmd = []
            if sandbox.cmd:
                inner_cmd = [sandbox.cmd] + sandbox.args
            elif full_cmd:
                inner_cmd = full_cmd

            full_cmd = sandbox_cmd + [sandbox.image] + inner_cmd

        print(f"[*] Command: {' '.join(full_cmd)}")
        if cwd:
            print(f"[*] Working dir: {cwd}")

        try:
            # Optional setup commands (usually dependency installs)
            for setup_cmd in self.launch_config.setup_commands:
                print(f"[*] ({self.target_id}) Running setup command: {setup_cmd}")
                subprocess.run(
                    setup_cmd,
                    shell=True,
                    cwd=cwd,
                    env=env if env else None,
                    check=True,
                    text=True,
                )

            # Launch process
            self.process = subprocess.Popen(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env if env else None,
                cwd=cwd,
                text=True,
                bufsize=1  # Line buffered
            )

            self.pid = self.process.pid
            print(f"[*] Server launched (PID: {self.pid})")

            # If sandboxed, capture container ID for proper cleanup
            if sandbox and sandbox.image:
                await asyncio.sleep(0.5)  # Brief delay for container to start
                try:
                    result = subprocess.run(
                        [sandbox.type, "ps", "--filter", f"ancestor={sandbox.image}", "--latest", "-q"],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        self.container_id = result.stdout.strip()
                        print(f"[*] Container ID: {self.container_id[:12]}")
                except Exception as e:
                    print(f"[!] Warning: Could not capture container ID: {e}")

            # Wait for server to be ready
            if self.launch_config.wait_for_ready:
                await self._wait_for_ready()
                # Allow a brief settling delay to avoid early disconnects on stream endpoints
                await asyncio.sleep(1)

        except Exception as e:
            raise ServerLaunchError(f"Failed to launch server: {e}") from e

    async def _wait_for_ready(self) -> None:
        """
        Wait for server to become ready.

        Uses configured ready check method:
        - healthcheck: Run healthcheck endpoint
        - port: Check if port is listening
        - log_pattern: Check for pattern in stdout/stderr
        """
        timeout = self.launch_config.ready_timeout_s
        check_method = self.launch_config.ready_check

        print(f"[*] Waiting for server ready (method: {check_method}, timeout: {timeout}s)...")

        start_time = time.time()

        while time.time() - start_time < timeout:
            # Check if process crashed
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                raise ServerNotReadyError(
                    f"Server process exited prematurely (code: {self.process.returncode})\n"
                    f"stdout: {stdout}\nstderr: {stderr}"
                )

            # Try ready check
            try:
                if check_method == "healthcheck":
                    if await self._check_healthcheck():
                        print(f"[+] Server ready (healthcheck passed)")
                        return

                elif check_method == "port":
                    if self._check_port():
                        print(f"[+] Server ready (port listening)")
                        return

                elif check_method == "log_pattern":
                    if self._check_log_pattern():
                        print(f"[+] Server ready (log pattern found)")
                        return

                else:
                    raise ServerNotReadyError(f"Unknown ready check method: {check_method}")

            except Exception as e:
                # Check failed, will retry
                pass

            # Wait before retry
            await asyncio.sleep(1)

        raise ServerNotReadyError(f"Server not ready after {timeout}s")

    async def _check_healthcheck(self) -> bool:
        """Check healthcheck endpoint."""
        if not self.healthcheck_config or not self.healthcheck_config.enabled:
            return False

        if self.healthcheck_config.type != "endpoint":
            return False

        url = self.healthcheck_config.url
        if not url:
            return False

        try:
            # Use asyncio to run HTTP check
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=self.healthcheck_config.timeout_s)

            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    self.healthcheck_config.method,
                    url
                ) as response:
                    return response.status == self.healthcheck_config.expected_status

        except:
            return False

    def _check_port(self) -> bool:
        """Check if port is listening."""
        port = self.launch_config.port
        if not port:
            return False

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            return result == 0
        except:
            return False

    def _check_log_pattern(self) -> bool:
        """Check for pattern in stdout/stderr."""
        pattern = self.launch_config.log_pattern
        if not pattern or not self.process:
            return False

        try:
            # Non-blocking read from stdout/stderr
            # This is a simplified version - in production you'd use asyncio subprocess
            # For now, we'll skip this check if process is running
            return False  # TODO: Implement proper async log monitoring
        except:
            return False

    async def stop(self) -> None:
        """
        Stop server gracefully, with force kill fallback.

        For Docker/Podman containers, this will:
        1. Stop the container explicitly
        2. Kill the parent docker run process
        """
        if not self.process or not self.pid:
            print(f"[*] Server not running")
            return

        print(f"[*] Stopping server (PID: {self.pid})...")

        # If this is a containerized server, stop the container first
        if self.container_id:
            sandbox_type = self.launch_config.sandbox.type if self.launch_config.sandbox else "docker"
            try:
                print(f"[*] Stopping container: {self.container_id[:12]}...")
                subprocess.run(
                    [sandbox_type, "stop", self.container_id],
                    capture_output=True,
                    timeout=10,
                    check=True
                )
                print(f"[+] Container stopped")
            except subprocess.TimeoutExpired:
                print(f"[!] Container stop timed out, force killing...")
                try:
                    subprocess.run(
                        [sandbox_type, "kill", self.container_id],
                        capture_output=True,
                        timeout=5,
                        check=True
                    )
                    print(f"[+] Container killed")
                except Exception as e:
                    print(f"[!] Failed to kill container: {e}")
            except Exception as e:
                print(f"[!] Failed to stop container: {e}")

        try:
            # Try graceful shutdown of parent process
            proc = psutil.Process(self.pid)

            # Send TERM signal
            proc.terminate()

            # Wait for graceful shutdown
            timeout = self.launch_config.shutdown_timeout_s
            try:
                proc.wait(timeout=timeout)
                print(f"[+] Server stopped gracefully")
                return
            except psutil.TimeoutExpired:
                # Graceful shutdown timed out
                if self.launch_config.kill_on_timeout:
                    print(f"[!] Graceful shutdown timed out, force killing...")
                    proc.kill()
                    proc.wait(timeout=5)
                    print(f"[+] Server force killed")
                else:
                    print(f"[!] Graceful shutdown timed out, leaving process running")

        except psutil.NoSuchProcess:
            print(f"[*] Server process already terminated")
        except Exception as e:
            print(f"[!] Error stopping server: {e}")

    async def __aenter__(self):
        """Context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.stop()


async def launch_server_if_needed(
    transport_config: TransportConfig,
    healthcheck_config: Optional[HealthcheckConfig],
    target_id: str
) -> Optional[ManagedServer]:
    """
    Launch server if launch configuration is present.

    Args:
        transport_config: Transport configuration
        healthcheck_config: Healthcheck configuration
        target_id: Target ID (for logging)

    Returns:
        ManagedServer instance if launched, None otherwise

    Raises:
        ServerLaunchError: If launch fails
        ServerNotReadyError: If server doesn't become ready
    """
    if not transport_config.launch or not transport_config.launch.enabled:
        return None

    server = ManagedServer(
        launch_config=transport_config.launch,
        transport_config=transport_config,
        healthcheck_config=healthcheck_config,
        target_id=target_id
    )

    await server.start()
    return server

`\n## src/core/auto_sandbox.py
`$lang"""
Automatic MCP Sandboxing - Zero-config transparent isolation.

This module provides the main entry point for automatic MCP assessment
with transparent Docker sandboxing. User never sees Docker - it just works.
"""

import asyncio
import os
import re
import socket
import tempfile
import subprocess
from pathlib import Path
from typing import Tuple, Dict, Optional, List
import tomllib

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

from src.core.lifecycle import ManagedServer
from src.core.runner import TestRunner
from src.core.models import (
    LaunchConfig,
    TransportConfig,
    AssessmentResult
)
from src.core.policy import ScopeConfig


class AutoSandbox:
    """
    Automatic MCP sandbox orchestrator.

    Provides zero-config assessment with transparent Docker isolation.
    User submits MCP source -> System handles everything automatically.
    """

    def __init__(self):
        """Initialize auto-sandbox."""
        if DOCKER_AVAILABLE:
            try:
                self.docker_client = docker.from_env()
            except Exception as e:
                raise DockerError(f"Docker not available: {e}")
        else:
            self.docker_client = None

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
        elif source_type in ["https", "http"]:
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
        if not DOCKER_AVAILABLE or not self.docker_client:
            raise DockerError("Docker is required for sandboxed assessment. Please install Docker.")

        # 1. Generate Dockerfile
        print(f"[*] Generating Dockerfile...")
        dockerfile, context_dir, detected_info = self._generate_dockerfile(source, source_type)

        # Track if we need to cleanup temp directory (npm/github create temp dirs)
        cleanup_temp_dir = source_type in ["npm", "github"]

        # 2. Build image (always rebuild to avoid stale entrypoints/config)
        image_tag_component = self._safe_image_name(detected_info["name"])
        image_tag = f"mcpsf-sandbox-{image_tag_component}:latest"

        # Collect or prompt for env if not provided
        env = env or self._derive_env_vars(context_dir, detected_info)

        print(f"[*] Building container (no cache)...")
        image_id = self._build_image(dockerfile, context_dir, image_tag, nocache=True)

        # 3. Detect transport type from detected_info
        transport_type = detected_info.get("transport", "stdio")  # Default to stdio

        print(f"[*] Detected transport: {transport_type}")

        # 4. Create appropriate config based on transport
        if transport_type == "sse":
            # SSE transport - allocate port and use HTTP
            port = self._find_free_port()
            print(f"[*] Allocated port: {port}")

            # Get container's internal port (default to 9001 if not detected)
            container_port = detected_info.get("sse_port", 9001)

            launch_env = env or self._default_env_for_target(detected_info)

            launch = LaunchConfig(
                enabled=True,
                sandbox=LaunchConfig.SandboxConfig(
                    type="docker",
                    image=image_tag,
                    network="bridge",  # Allow port mapping
                    ports=[f"{port}:{container_port}"],
                    env=launch_env
                ),
                ready_check="port",
                port=port,
                wait_for_ready=True,
                ready_timeout_s=60
            )

            transport = TransportConfig(type="sse", url=f"http://localhost:{port}/sse")
            server = ManagedServer(launch, transport, target_id=detected_info["name"])
            runner: Optional[TestRunner] = None
            try:
                print(f"[*] Starting SSE server...")
                await server.start()
                print(f"[+] Server ready")

                # Run assessment
                print(f"[*] Running assessment...")
                scope = ScopeConfig(
                    target=transport.url,
                    transport="sse",
                    mode=profile
                )
                runner = TestRunner(scope=scope)
                try:
                    result = await runner.assess(detector_ids=detectors)
                except Exception as e:
                    # Retry with root SSE path if default /sse fails
                    alt_url = f"http://localhost:{port}"
                    print(f"[!] SSE assess failed ({e}); retrying with {alt_url}")
                    scope = ScopeConfig(
                        target=alt_url,
                        transport="sse",
                        mode=profile
                    )
                    runner = TestRunner(scope=scope)
                    result = await runner.assess(detector_ids=detectors)

                print(f"[+] Assessment complete")

                return result

            finally:
                if runner:
                    try:
                        await runner.cleanup()
                    except Exception:
                        pass

                if not no_cleanup:
                    print(f"[*] Cleanup...")
                    await server.stop()

                    # Only remove temp directory (keep Docker image for caching)
                    if cleanup_temp_dir and context_dir.exists():
                        try:
                            import shutil
                            shutil.rmtree(context_dir)
                        except Exception:
                            pass  # Non-critical

                    print(f"[+] Cleanup complete (Docker image cached for reuse)")

        else:  # stdio transport (default)
            # stdio transport - run server and connect via stdin/stdout using image CMD
            import time
            container_name = f"mcpsf-stdio-{int(time.time())}"

            docker_args = [
                "run",
                "--rm",
                "-i",
                "--name", container_name,
                "--network", "bridge",
            ]

            # Propagate environment variables into the container if provided
            if env:
                for key, value in env.items():
                    docker_args += ["-e", f"{key}={value}"]

            docker_args.append(image_tag)

            transport = TransportConfig(
                type="stdio",
                command="docker",
                args=docker_args,
                env=env or {}
            )

            print(f"[*] Starting server via stdio transport...")
            print(f"[*] Container name: {container_name}")
            print(f"[*] Command: {transport.command} {' '.join(transport.args)}")

            runner: Optional[TestRunner] = None
            try:
                # Run assessment directly (TestRunner handles stdio communication)
                scope = ScopeConfig(
                    target=f"stdio://{transport.command}/{'/'.join(transport.args)}",
                    transport="stdio",
                    mode=profile
                )
                runner = TestRunner(scope=scope)

                print(f"[*] Running assessment...")
                result = await runner.assess(detector_ids=detectors)
                print(f"[+] Assessment complete")

                return result

            except Exception as e:
                # Print container logs to help diagnose command/entrypoint failures
                self._print_container_logs(container_name)
                raise

            finally:
                if runner:
                    try:
                        await runner.cleanup()
                    except Exception:
                        pass

                if not no_cleanup:
                    print(f"[*] Cleanup...")

                    # Stop and remove the stdio container if it's still running
                    try:
                        import subprocess
                        subprocess.run(
                            ["docker", "rm", "-f", container_name],
                            capture_output=True,
                            timeout=10
                        )
                        print(f"[+] Container removed (or already exited)")
                    except Exception as e:
                        print(f"[!] Warning: Failed to cleanup container {container_name}: {e}")

                    # Only remove temp directory (keep Docker image for caching)
                    if cleanup_temp_dir and context_dir.exists():
                        try:
                            import shutil
                            shutil.rmtree(context_dir)
                        except Exception:
                            pass  # Non-critical

                    print(f"[+] Cleanup complete (Docker image cached for reuse)")

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
            mode=profile
        )
        runner: Optional[TestRunner] = None
        try:
            runner = TestRunner(scope=scope)
            result = await runner.assess(detector_ids=detectors)
            return result
        finally:
            if runner:
                try:
                    await runner.cleanup()
                except Exception:
                    pass

    def _detect_source(self, source: str) -> str:
        """
        Detect source type from input string.

        Returns:
            "npm" | "github" | "local" | "https" | "localhost"

        Examples:
            "@modelcontextprotocol/server-time" �?"npm"
            "https://github.com/org/repo" �?"github"
            "./my-server" �?"local"
            "https://api.com:9001/sse" �?"https"
            "http://localhost:9001/sse" �?"localhost"
        """
        # npm package (scoped or unscoped)
        if source.startswith("@") or re.match(r'^[a-z0-9-]+$', source):
            return "npm"

        # GitHub URL
        if "github.com" in source:
            return "github"

        # HTTP/S URL
        if source.startswith("http://") or source.startswith("https://"):
            from urllib.parse import urlparse

            parsed = urlparse(source)
            host = parsed.hostname or ""
            if host in {"localhost", "127.0.0.1"}:
                return "localhost"
            return "https" if source.startswith("https://") else "http"

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

        Strategy: Use npx to run package in container (installed at runtime).
        """
        # Extract package name (remove scope if present)
        name = package.split("/")[-1]

        dockerfile = f"""FROM node:20-alpine

# Expose default MCP SSE port (if server uses SSE)
EXPOSE 9001

# Run server using npx (installs on-demand)
CMD ["npx", "-y", "{package}"]
"""

        # Use temp directory as build context
        context_dir = Path(tempfile.mkdtemp(prefix=f"mcpsf-{name}-"))

        detected_info = {
            "name": name,
            "language": "nodejs",
            "package": package,
            "transport": "stdio"  # Default to stdio for npm packages
        }

        return (dockerfile, context_dir, detected_info)

    def _generate_github_dockerfile(self, url: str) -> Tuple[str, Path, Dict]:
        """
        Generate Dockerfile for GitHub repository.

        Strategy:
        1. Clone repo to temp directory
        2. Detect language (package.json �?Node.js, requirements.txt �?Python)
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

        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(context_dir)],
            check=True,
            capture_output=True
        )

        # Detect language (prioritize Python for MCP servers)
        transport_type = "stdio"
        sse_port = None  # Will be set if SSE transport is detected
        has_requirements = (context_dir / "requirements.txt").exists()
        has_pyproject = (context_dir / "pyproject.toml").exists()

        if has_requirements or has_pyproject:
            # Python project - try to detect entry point
            entry_module = repo.replace("-", "_")  # Common pattern
            script_name = None

            # Check if pyproject.toml has entry point info
            try:
                if (context_dir / "pyproject.toml").exists():
                    with open(context_dir / "pyproject.toml", "rb") as f:
                        pyproject = tomllib.load(f)
                        project_section = pyproject.get("project", {})
                        scripts = project_section.get("scripts", {})
                        if scripts:
                            # Use first script as entry point; prefer CLI names that look like MCP servers
                            first_script = list(scripts.keys())[0]
                            if "mcp" in first_script or "server" in first_script:
                                script_name = first_script
                            entry_module = list(scripts.keys())[0]
            except Exception:
                pass

            # Choose install strategy: always install project itself so entrypoints exist
            if has_requirements:
                install_cmd = "RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir ."
            else:
                install_cmd = "RUN pip install --no-cache-dir ."

            python_image = self._select_python_image(context_dir)

            # Try to detect an SSE entrypoint (e.g., sse_server.py)
            sse_entry = self._detect_python_sse_entry(context_dir)
            if sse_entry:
                # Detect the port used by the SSE server
                sse_port = self._detect_python_sse_port(context_dir, sse_entry)
                module_name = sse_entry.rstrip(".py").replace("/", ".").replace("\\", ".")
                if module_name.startswith("src."):
                    module_name = module_name[len("src."):]
                dockerfile = f"""FROM {python_image}

WORKDIR /app
COPY . .

{install_cmd}

EXPOSE {sse_port}
CMD ["python", "-m", "{module_name}"]
"""
                transport_type = "sse"
            else:
                # Default to stdio entrypoint; prefer project CLI script if it looks like a server
                if script_name:
                    # Most fastmcp servers expect a mode argument; default to stdio when transport is stdio
                    default_arg = "stdio" if transport_type == "stdio" else "sse"
                    cmd_line = f'CMD ["{script_name}", "{default_arg}"]'
                else:
                    cmd_line = f'CMD ["python", "-m", "{entry_module}"]'

                dockerfile = f"""FROM {python_image}

WORKDIR /app
COPY . .

{install_cmd}

EXPOSE 9001
{cmd_line}
"""
                transport_type = "stdio"

            language = "python"

            detected_info = {
                "name": repo,
                "language": language,
                "url": url,
                "transport": transport_type,
                "sse_port": sse_port if transport_type == "sse" else None
            }

            return (dockerfile, context_dir, detected_info)

        elif (context_dir / "package.json").exists():
            # Node.js project
            # Ensure it looks like an MCP server; otherwise skip (e.g., pure UI apps)
            self._ensure_node_is_mcp(context_dir, detected_info)
            # Try to find the entry point from package.json
            import json
            try:
                with open(context_dir / "package.json") as f:
                    pkg = json.load(f)

                    # Priority: bin > start script > main field
                    entry_point = None

                    # 1. Check for bin entry
                    if "bin" in pkg:
                        bin_val = pkg["bin"]
                        if isinstance(bin_val, dict):
                            entry_point = list(bin_val.values())[0] if bin_val else None
                        else:
                            entry_point = bin_val

                    # 2. Try to extract from start script (e.g., "node dist/index.js")
                    if not entry_point:
                        start_script = pkg.get("scripts", {}).get("start", "")
                        if start_script:
                            # Extract file path from "node <path>" or "tsx <path>"
                            match = re.search(r'(?:node|tsx)\s+([^\s]+)', start_script)
                            if match:
                                entry_point = match.group(1)

                    # 3. Fall back to main field or default
                    if not entry_point:
                        entry_point = pkg.get("main", "dist/index.js")

            except:
                entry_point = "dist/index.js"

            sse_port = self._detect_node_sse_port(context_dir)

            dockerfile = f"""FROM node:20-alpine

WORKDIR /app
COPY . .

RUN npm install
RUN npm run build || true

EXPOSE {sse_port}
CMD ["node", "{entry_point}"]
"""
            language = "nodejs"
            transport_type = self._detect_transport_from_package_json(context_dir)
            detected_info = {
                "name": repo,
                "language": language,
                "url": url,
                "transport": transport_type,
                "sse_port": sse_port if transport_type == "sse" else None
            }

            return (dockerfile, context_dir, detected_info)

        else:
            raise SourceDetectionError(f"Cannot detect language in {url}")

    def _generate_local_dockerfile(self, path: str) -> Tuple[str, Path, Dict]:
        """
        Generate Dockerfile for local directory.

        Similar to GitHub, but context is already local.
        """
        orig_dir = Path(path).absolute()

        # Heuristic: prefer treating the provided directory itself as the
        # project root when it clearly looks like a standalone MCP project.
        # Only walk upwards as a fallback for unusual layouts.
        if (orig_dir / "package.json").exists():
            # Node.js MCP in the given directory
            context_dir = orig_dir
        elif (orig_dir / "requirements.txt").exists() or (orig_dir / "pyproject.toml").exists():
            # Python MCP in the given directory
            context_dir = orig_dir
        else:
            # Fallback: walk up to find a Python project root
            project_root = orig_dir
            while True:
                if (project_root / "requirements.txt").exists() or (project_root / "pyproject.toml").exists():
                    break
                if project_root.parent == project_root:
                    # Reached filesystem root, fall back to original directory
                    project_root = orig_dir
                    break
                project_root = project_root.parent
            context_dir = project_root

        # Detect language (prioritize Python for MCP servers)
        transport_type = "stdio"
        sse_port = None  # Will be set if SSE transport is detected
        has_requirements = (context_dir / "requirements.txt").exists()
        has_pyproject = (context_dir / "pyproject.toml").exists()

        if has_requirements or has_pyproject:
            # Python project - try to detect entry point
            entry_module = context_dir.name.replace("-", "_")  # Common pattern
            script_name = None

            # Check if pyproject.toml has entry point info
            try:
                if (context_dir / "pyproject.toml").exists():
                    with open(context_dir / "pyproject.toml", "rb") as f:
                        pyproject = tomllib.load(f)
                        project_section = pyproject.get("project", {})
                        scripts = project_section.get("scripts", {})
                        if scripts:
                            first_script = list(scripts.keys())[0]
                            if "mcp" in first_script or "server" in first_script:
                                script_name = first_script
                            entry_module = list(scripts.keys())[0]
            except Exception:
                pass

            # Always install project itself so entrypoints are available
            if has_requirements:
                install_cmd = "RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir ."
            else:
                install_cmd = "RUN pip install --no-cache-dir ."

            python_image = self._select_python_image(context_dir)

            # Try to detect an SSE entrypoint (e.g., sse_server.py or server_sse.py)
            # Prefer an entry under the originally requested path, then fall back to project root.
            sse_entry_rel = None

            # 1) Look for SSE entry within the requested subdirectory
            sse_sub = self._detect_python_sse_entry(orig_dir)
            if sse_sub:
                sse_entry_rel = (orig_dir / sse_sub).relative_to(context_dir)
            else:
                # 2) Fallback: look anywhere under context_dir
                sse_root = self._detect_python_sse_entry(context_dir)
                if sse_root:
                    sse_entry_rel = Path(sse_root)

            if sse_entry_rel:
                sse_entry_str = str(sse_entry_rel).replace("\\", "/")
                # Detect the port used by the SSE server
                sse_port = self._detect_python_sse_port(context_dir, sse_entry_str)
                module_name = sse_entry_str.rstrip(".py").replace("/", ".").replace("\\", ".")
                if module_name.startswith("src."):
                    module_name = module_name[len("src."):]
                dockerfile = f"""FROM {python_image}

WORKDIR /app
COPY . .

{install_cmd}

EXPOSE {sse_port}
CMD ["python", "-m", "{module_name}"]
"""
                transport_type = "sse"
            else:
                # Default to stdio entrypoint; prefer project CLI script if it looks like a server
                if script_name:
                    default_arg = "stdio" if transport_type == "stdio" else "sse"
                    cmd_line = f'CMD ["{script_name}", "{default_arg}"]'
                else:
                    cmd_line = f'CMD ["python", "-m", "{entry_module}"]'

                dockerfile = f"""FROM {python_image}

WORKDIR /app
COPY . .

{install_cmd}

EXPOSE 9001
{cmd_line}
"""
                transport_type = "stdio"

            language = "python"

        elif (context_dir / "package.json").exists():
            # Node.js project
            # Try to find the entry point from package.json
            import json
            try:
                with open(context_dir / "package.json") as f:
                    pkg = json.load(f)

                    # Priority: bin > start script > main field
                    entry_point = None

                    # 1. Check for bin entry
                    if "bin" in pkg:
                        bin_val = pkg["bin"]
                        if isinstance(bin_val, dict):
                            entry_point = list(bin_val.values())[0] if bin_val else None
                        else:
                            entry_point = bin_val

                    # 2. Try to extract from start script (e.g., "node dist/index.js")
                    if not entry_point:
                        start_script = pkg.get("scripts", {}).get("start", "")
                        if start_script:
                            # Extract file path from "node <path>" or "tsx <path>"
                            match = re.search(r'(?:node|tsx)\s+([^\s]+)', start_script)
                            if match:
                                entry_point = match.group(1)

                    # 3. Fall back to main field or default
                    if not entry_point:
                        entry_point = pkg.get("main", "dist/index.js")

            except:
                entry_point = "dist/index.js"

            sse_port = self._detect_node_sse_port(context_dir)

            dockerfile = f"""FROM node:20-alpine

WORKDIR /app
COPY . .

RUN npm install
RUN npm run build || true

EXPOSE {sse_port}
CMD ["node", "{entry_point}"]
"""
            language = "nodejs"
            transport_type = self._detect_transport_from_package_json(context_dir)

        else:
            raise SourceDetectionError(f"Cannot detect language in {path}")

        # Generate unique name: if orig_dir is a subdirectory of context_dir,
        # include both to ensure unique Docker images for monorepo challenges
        if orig_dir != context_dir and orig_dir.is_relative_to(context_dir):
            # Monorepo case: include subdirectory in name (e.g., "dv-mcp-challenge1")
            rel_path = orig_dir.relative_to(context_dir)
            # Convert path separators to hyphens for Docker-safe name
            sub_name = str(rel_path).replace("\\", "-").replace("/", "-")
            image_name = f"{context_dir.name}-{sub_name}"
        else:
            # Standard case: just use context directory name
            image_name = context_dir.name

        detected_info = {
            "name": image_name,
            "language": language,
            "path": str(context_dir),
            "orig_path": str(orig_dir),
            "transport": transport_type,
            "sse_port": sse_port if transport_type == "sse" else None
        }

        return (dockerfile, context_dir, detected_info)

    def _detect_transport_from_package_json(self, project_dir: Path) -> str:
        """
        Detect MCP transport type from package.json.

        Looks for:
        - SSE servers: dependencies on express/fastify, scripts that mention "server" or "http"
        - stdio servers: default for MCP (most common)

        Returns:
            "sse" or "stdio"
        """
        package_json_path = project_dir / "package.json"
        if not package_json_path.exists():
            return "stdio"

        try:
            import json
            with open(package_json_path) as f:
                package_data = json.load(f)

            # Check dependencies for web frameworks
            deps = package_data.get("dependencies", {})
            dev_deps = package_data.get("devDependencies", {})
            all_deps = {**deps, **dev_deps}

            # If it has express/fastify/koa, likely SSE
            web_frameworks = ["express", "fastify", "koa", "@hapi/hapi"]
            if any(fw in all_deps for fw in web_frameworks):
                # Check start script to confirm
                scripts = package_data.get("scripts", {})
                start_script = scripts.get("start", "")
                if "http" in start_script.lower() or "server" in start_script.lower():
                    return "sse"

            # Default to stdio (most MCP servers use stdio)
            return "stdio"

        except Exception:
            # If we can't parse package.json, assume stdio
            return "stdio"

    def _detect_python_sse_entry(self, project_dir: Path) -> Optional[str]:
        """
        Best-effort detection of a Python SSE MCP entrypoint.

        Heuristics (in order):
        - Root-level sse_server.py
        - Any file named server_sse.py
        - First .py file that references mcp.server.sse or SseServerTransport

        Returns:
            Relative path (POSIX-style) to entrypoint, or None.
        """
        # 1. Root-level sse_server.py
        candidate = project_dir / "sse_server.py"
        if candidate.exists():
            return candidate.name

        # 2. Any server_sse.py under the project tree (excluding virtualenv / cache dirs)
        matches: List[Path] = []
        exclude_dirs = {".venv", "venv", ".git", "__pycache__", "site-packages", "dist-packages"}
        for path in project_dir.rglob("server_sse.py"):
            if any(part in exclude_dirs for part in path.parts):
                continue
            matches.append(path)

        # 3. Fallback: scan for SseServerTransport imports/usages
        if not matches:
            for path in project_dir.rglob("*.py"):
                if any(part in exclude_dirs for part in path.parts):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                if "SseServerTransport" in text or "mcp.server.sse" in text:
                    matches.append(path)
                    break

        if matches:
            rel = matches[0].relative_to(project_dir)
            # Use POSIX-style path inside container
            return str(rel).replace("\\", "/")

        return None

    def _detect_python_sse_port(self, project_dir: Path, sse_entry: str) -> int:
        """
        Detect the port used by the Python SSE server.

        Args:
            project_dir: Project directory
            sse_entry: Relative path to SSE entry file (e.g., "server_sse.py")

        Returns:
            Port number (default: 9001)
        """
        try:
            entry_path = project_dir / sse_entry
            if not entry_path.exists():
                return 9001

            text = entry_path.read_text(encoding="utf-8", errors="ignore")

            # Look for common patterns:
            # self.port = 9001
            # port = 9002
            # uvicorn.run(..., port=9003)
            import re
            patterns = [
                r'self\.port\s*=\s*(\d+)',
                r'port\s*=\s*(\d+)',
                r'uvicorn\.run\([^)]*port\s*=\s*(\d+)',
            ]

            for pattern in patterns:
                match = re.search(pattern, text)
                if match:
                    return int(match.group(1))

            # Default to 9001
            return 9001

        except Exception:
            return 9001

    def _detect_node_sse_port(self, project_dir: Path) -> int:
        """
        Best-effort detection of a Node SSE server port.

        Looks for common patterns in .js/.ts files:
        - process.env.PORT || <number>
        - const PORT = <number>
        - const port = <number>
        """
        default_port = 9001
        patterns = [
            r'process\.env\.PORT\s*\|\|\s*(\d+)',
            r"process\.env\[['\"]PORT['\"]\]\s*\|\|\s*(\d+)",
            r"Number\(process\.env\[['\"]PORT['\"]\]\)\s*\|\|\s*(\d+)",
            r'const\s+PORT\s*=\s*(\d+)',
            r'const\s+port\s*=\s*(\d+)',
            r'let\s+port\s*=\s*(\d+)',
        ]

        exclude_dirs = {"node_modules", "dist", "build", ".git"}
        scanned = 0
        max_files = 300

        for path in project_dir.rglob("*"):
            if scanned >= max_files:
                break
            if not path.suffix.lower() in {".js", ".ts"}:
                continue
            if any(part in exclude_dirs for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            scanned += 1
            for pat in patterns:
                match = re.search(pat, text)
                if match:
                    try:
                        return int(match.group(1))
                    except Exception:
                        pass

        return default_port

    def _build_image(self, dockerfile: str, context_dir: Path, tag: str, nocache: bool = False) -> str:
        """
        Build Docker image from Dockerfile.

        Uses Docker SDK for Python.

        Returns:
            Image ID for cleanup purposes
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
                quiet=False,
                forcerm=True,  # Always remove intermediate containers
                nocache=nocache
            )

            # Print build logs (optional: can be suppressed)
            for line in logs:
                if 'stream' in line:
                    msg = line['stream'].strip()
                    if msg:
                        print(f"    {msg}")

            return image.id

        except Exception as e:
            raise DockerBuildError(f"Failed to build image: {e}")

    def _find_free_port(self) -> int:
        """Find an available port on localhost."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def _safe_image_name(self, name: str) -> str:
        """
        Sanitize a string so it can be safely used as part of a Docker image tag.

        Docker name components must match [a-z0-9]+(?:[._-][a-z0-9]+)*.
        """
        safe = re.sub(r'[^a-zA-Z0-9._-]+', '-', name)
        safe = safe.strip('-').lower()
        if not safe:
            safe = "mcp-target"
        return safe

    def _default_env_for_target(self, detected_info: Dict[str, str]) -> Dict[str, str]:
        """
        Provide default environment variables or prompt the user for required secrets.

        - API-based servers: prompt for known keys (skips if not provided)
        - DB-backed servers (e.g., MySQL/Postgres): skip for now to avoid requiring external services
        """
        name = detected_info.get("name", "").lower()

        # Skip heavy DB targets for now (requires external database)
        db_keywords = ["mysql", "postgres", "pgsql", "mariadb", "sqlserver", "oracle"]
        if any(k in name for k in db_keywords):
            raise AssessmentCancelled(
                f"{detected_info.get('name', 'target')} requires external database credentials; skipping for now."
            )

        # Known API key prompts
        api_key_map = {
            "brave": ["BRAVE_API_KEY"],
            "openai": ["OPENAI_API_KEY"],
            "anthropic": ["ANTHROPIC_API_KEY"],
        }

        env: Dict[str, str] = {}
        for key, vars_list in api_key_map.items():
            if key in name:
                for var in vars_list:
                    val = input(f"Enter {var} for {detected_info.get('name', key)} (leave blank to skip): ").strip()
                    if val:
                        env[var] = val
                    else:
                        raise AssessmentCancelled(f"Missing required secret {var}; skipping {detected_info.get('name', key)}")

        return env

    def _derive_env_vars(self, context_dir: Path, detected_info: Dict[str, str]) -> Dict[str, str]:
        """
        Aggregate environment requirements:
        - If known heavy/multi-service (docker-compose with multiple services) -> skip
        - Load .env.example/.env.sample style hints and prompt user once
        """
        # Multi-service detection: if compose present anywhere relevant, skip
        candidate_dirs = [context_dir]
        orig_path = detected_info.get("orig_path")
        if orig_path:
            try:
                cand = Path(orig_path)
                if cand not in candidate_dirs:
                    candidate_dirs.append(cand)
            except Exception:
                pass

        compose_names = ["docker-compose.yml", "docker-compose.yaml", "docker-compose.secure.yml"]
        for base in candidate_dirs:
            for name in compose_names:
                cf = base / name
                if cf.exists():
                    raise AssessmentCancelled(f"{detected_info.get('name','target')} ships docker-compose ({name}); skipping (multi-service stack).")

        # Parse env examples
        env_files = []
        for base in candidate_dirs:
            for name in [".env.example", ".env.sample", ".env.template", ".env"]:
                candidate = base / name
                if candidate.exists():
                    env_files.append(candidate)

        env_vars: Dict[str, str] = {}

        required_keys = []
        for ef in env_files:
            try:
                for line in ef.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key = line.split("=", 1)[0].strip()
                    if key and key not in required_keys:
                        required_keys.append(key)
            except Exception:
                continue

        if required_keys:
            # For automation, skip when env is not pre-supplied; avoids hanging on prompts.
            raise AssessmentCancelled(
                f"{detected_info.get('name','target')} requires environment config ({', '.join(required_keys)}); skipping until provided."
            )

        return env_vars

    def _select_python_image(self, project_dir: Path) -> str:
        """
        Choose an appropriate python base image based on requires-python.

        Defaults to 3.11 to satisfy most modern MCP servers.
        """
        default_image = "python:3.11-alpine"
        pyproject = project_dir / "pyproject.toml"
        if not pyproject.exists():
            return default_image

        try:
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
            requires = data.get("project", {}).get("requires-python")
            if requires:
                match = re.search(r"(\d+\.\d+)", requires)
                if match:
                    version = match.group(1)
                    return f"python:{version}-alpine"
        except Exception:
            pass

        return default_image

    def _ensure_node_is_mcp(self, project_dir: Path, detected_info: Dict[str, str]) -> None:
        """
        Basic heuristic: verify package.json references MCP before investing in build.
        Skips UI-only or unrelated Node apps that would time out.
        """
        pkg_path = project_dir / "package.json"
        if not pkg_path.exists():
            return
        try:
            import json
            data = json.loads(pkg_path.read_text())
            text_fields = json.dumps(data).lower()
            if "mcp" in text_fields or "modelcontextprotocol" in text_fields:
                return
        except Exception:
            return

        raise AssessmentCancelled(f"{detected_info.get('name','target')} does not appear to be an MCP server (no MCP deps); skipping.")

    def _print_container_logs(self, name: str) -> None:
        """
        Best-effort dump of container logs to aid debugging.
        """
        try:
            result = subprocess.run(
                ["docker", "logs", name],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.stdout:
                print("[*] Container stdout:")
                print(result.stdout.strip())
            if result.stderr:
                print("[*] Container stderr:")
                print(result.stderr.strip())
        except Exception as e:
            print(f"[!] Could not fetch container logs for {name}: {e}")

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


class DockerError(Exception):
    """Docker not available or failed."""
    pass


class DockerBuildError(Exception):
    """Docker image build failed."""
    pass


class AssessmentCancelled(Exception):
    """User cancelled assessment."""
    pass

`\n## tests/integration/test_discovery_sse.py
`$lang"""Quick test to verify Discovery picks SSE server."""

from src.core.discovery import SourceDiscovery

discovery = SourceDiscovery()
configs = discovery.discover("./targets/vulnerable/dv-mcp/challenges/easy/challenge1")

print("=" * 70)
print("  Discovery Test - Challenge 1")
print("=" * 70)
print(f"Found {len(configs)} config(s)")
for i, config in enumerate(configs):
    print(f"\nConfig {i+1}:")
    print(f"  Name: {config.name}")
    print(f"  Transport: {config.transport}")
    print(f"  Entry Point: {' '.join(config.entry_point)}")
    print(f"  Language: {config.language}")

`\n## tests/test_challenge1.py
`$lang"""
Test AMSAW v2 with DV-MCP Challenge 1 (Local).

This tests the full pipeline with a local vulnerable MCP server.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_challenge1():
    """Test full pipeline with DV-MCP Challenge 1."""
    print("=" * 70)
    print("  AMSAW v2 Test: DV-MCP Challenge 1 (Local)")
    print("=" * 70)
    print()

    # Use non-interactive mode for automated testing
    pipeline = AssessmentPipeline(interactive=False)

    try:
        # Run full assessment on local challenge
        result = await pipeline.run(
            source="./targets/vulnerable/dv-mcp/challenges/easy/challenge1",
            profile="aggressive"
        )

        # Verify result
        print()
        print("=" * 70)
        print("  Test Result")
        print("=" * 70)
        print(f"  Server Name: {result.profile.server_name}")
        summary = result.summary
        total = sum(summary.values())
        print(f"  Total Detectors: {total}")
        print(f"  Vulnerabilities: {summary.get('present', 0)}")
        print(f"  Expected: 2+ vulnerabilities (prompt injection)")
        print()

        if result.summary['present'] >= 1:
            print("[SUCCESS] Challenge 1 test PASSED!")
            print("  - Discovery worked")
            print("  - Provisioner worked")
            print("  - Bridge worked")
            print("  - TestRunner worked")
            print("  - Detectors found vulnerabilities")
        else:
            print("[WARNING] No vulnerabilities found (expected at least 1)")

    except Exception as e:
        print(f"[ERROR] Challenge 1 test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_challenge1())

`\n## tests/test_server_time_npm.py
`$lang"""
Test AMSAW v2 with npm MCP @modelcontextprotocol/server-time (stdio). Uses aggressive profile.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_server_time_npm():
    print("=" * 70)
    print("  AMSAW v2 Test: npm @modelcontextprotocol/server-time")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        result = await pipeline.run(
            source="@szemeng76/mcp-time-server",
            profile="aggressive"
        )

        summary = result.summary
        total = sum(summary.values())

        print()
        print("=" * 70)
        print("  Test Result")
        print("=" * 70)
        print(f"  Server Name: {result.profile.server_name}")
        print(f"  Total Detectors: {total}")
        print(f"  Vulnerabilities: {summary.get('present', 0)}")
        print()

        if summary.get('present', 0) >= 1:
            print("[SUCCESS] npm server-time test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found")

    except Exception as e:
        print(f"[ERROR] npm server-time test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_server_time_npm())

`\n## tests/test_markitdown_mcp.py
`$lang"""
Test AMSAW v2 with Microsoft MarkItDown MCP (GitHub).

Real-world test: https://github.com/microsoft/markitdown/tree/main/packages/markitdown-mcp
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_markitdown_mcp():
    print("=" * 70)
    print("  AMSAW v2 Test: Microsoft MarkItDown MCP (GitHub)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        result = await pipeline.run(
            source="https://github.com/microsoft/markitdown/tree/main/packages/markitdown-mcp",
            profile="aggressive"
        )

        summary = result.summary
        total = sum(summary.values())

        print()
        print("=" * 70)
        print("  Test Result")
        print("=" * 70)
        print(f"  Server Name: {result.profile.server_name}")
        print(f"  Total Detectors: {total}")
        print(f"  Vulnerabilities: {summary.get('present', 0)}")
        print()

        if summary.get('present', 0) >= 1:
            print("[SUCCESS] MarkItDown MCP test PASSED - Vulnerabilities found!")
        else:
            print("[SUCCESS] MarkItDown MCP test PASSED - No vulnerabilities found (clean server)")

    except Exception as e:
        print(f"[ERROR] MarkItDown MCP test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_markitdown_mcp())

`\n## tests/test_github_mcp.py
`$lang"""
Test AMSAW v2 with a GitHub-hosted MCP (server-time repo path). Uses aggressive profile.
Discovery clones and analyzes without hardcoding subpaths beyond the GitHub URL itself.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_github_mcp():
    print("=" * 70)
    print("  AMSAW v2 Test: GitHub MCP (server-time)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        result = await pipeline.run(
            source="https://github.com/modelcontextprotocol/servers/tree/main/src/time",
            profile="aggressive"
        )

        summary = result.summary
        total = sum(summary.values())

        print()
        print("=" * 70)
        print("  Test Result")
        print("=" * 70)
        print(f"  Server Name: {result.profile.server_name}")
        print(f"  Total Detectors: {total}")
        print(f"  Vulnerabilities: {summary.get('present', 0)}")
        print()

        if summary.get('present', 0) >= 1:
            print("[SUCCESS] GitHub MCP test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found")

    except Exception as e:
        print(f"[ERROR] GitHub MCP test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_github_mcp())

`\n## tests/test_excel_mcp.py
`$lang"""
Test AMSAW v2 with Excel MCP (local project). Uses aggressive profile.

Runs the full pipeline against ./targets/excel-mcp-server.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_excel_mcp():
    print("=" * 70)
    print("  AMSAW v2 Test: Excel MCP (Local)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)
    source = "./targets/excel-mcp-server"

    try:
        # Excel MCP's Typer CLI needs a subcommand (stdio/sse/streamable-http).
        # Force stdio so the bridge receives a running server.
        configs = pipeline.discovery.discover(source)
        if not configs:
            raise RuntimeError("Discovery returned no configs for Excel MCP")
        config = configs[0]
        if "stdio" not in config.entry_point:
            config.entry_point.append("stdio")
        pipeline.discovery.discover = lambda _: configs

        result = await pipeline.run(
            source=source,
            profile="aggressive"
        )

        summary = result.summary
        total = sum(summary.values())

        print()
        print("=" * 70)
        print("  Test Result")
        print("=" * 70)
        print(f"  Server Name: {result.profile.server_name}")
        print(f"  Total Detectors: {total}")
        print(f"  Vulnerabilities: {summary.get('present', 0)}")
        print()

        if summary.get('present', 0) >= 1:
            print("[SUCCESS] Excel MCP test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found")

    except Exception as e:
        print(f"[ERROR] Excel MCP test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_excel_mcp())

`\n## tests/test_wikipedia_mcp.py
`$lang"""
Test AMSAW v2 with Wikipedia MCP (local project). Uses aggressive profile.

Discovery intentionally points only at the project root (no subpath hints) so
we exercise the generic detection flow. This may fail if dependencies/SDK are
missing; failures are printed for visibility.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_wikipedia_mcp():
    print("=" * 70)
    print("  AMSAW v2 Test: Wikipedia MCP (Local)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        result = await pipeline.run(
            source="./targets/wikipedia-mcp",
            profile="aggressive"
        )

        summary = result.summary
        total = sum(summary.values())

        print()
        print("=" * 70)
        print("  Test Result")
        print("=" * 70)
        print(f"  Server Name: {result.profile.server_name}")
        print(f"  Total Detectors: {total}")
        print(f"  Vulnerabilities: {summary.get('present', 0)}")
        print()

        if summary.get('present', 0) >= 1:
            print("[SUCCESS] Wikipedia MCP test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found")

    except Exception as e:
        print(f"[ERROR] Wikipedia MCP test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_wikipedia_mcp())

`\n## tests/test_remote_sse.py
`$lang"""
Test AMSAW v2 with a remote HTTPS/HTTP SSE endpoint.

This tests the wrapper system's ability to handle remote servers
without containerization (direct connection mode).
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_remote_sse():
    print("=" * 70)
    print("  AMSAW v2 Test: Remote SSE Endpoint (localhost:9001)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        # Test with HTTP localhost URL (simulating remote server)
        result = await pipeline.run(
            source="http://localhost:9001/sse",
            profile="aggressive"
        )

        summary = result.summary
        total = sum(summary.values())

        print()
        print("=" * 70)
        print("  Test Result")
        print("=" * 70)
        print(f"  Server Name: {result.profile.server_name}")
        print(f"  Total Detectors: {total}")
        print(f"  Vulnerabilities: {summary.get('present', 0)}")
        print()

        if summary.get('present', 0) >= 1:
            print("[SUCCESS] Remote SSE test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found")

    except Exception as e:
        print(f"[ERROR] Remote SSE test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_remote_sse())

`\n## tests/test_remote_sse_pipedream.py
`$lang"""
Test AMSAW v2 with a remote SSE MCP endpoint (pipedream). Uses aggressive profile.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_remote_sse_pipedream():
    print("=" * 70)
    print("  AMSAW v2 Test: Remote SSE MCP (pipedream)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        result = await pipeline.run(
            source="https://mcp.pipedream.net/v2",
            profile="aggressive"
        )

        summary = result.summary
        total = sum(summary.values())

        print("\n" + "=" * 70)
        print("  Test Result")
        print("=" * 70)
        print(f"  Server Name: {result.profile.server_name}")
        print(f"  Total Detectors: {total}")
        print(f"  Vulnerabilities: {summary.get('present', 0)}")
        print()

        if summary.get('present', 0) >= 1:
            print("[SUCCESS] Remote SSE pipedream test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found")

    except Exception as e:
        print(f"[ERROR] Remote SSE pipedream test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_remote_sse_pipedream())

`\n