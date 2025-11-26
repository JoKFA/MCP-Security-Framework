"""
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
   - If can't detect language → raise error
   - If no MCP SDK found → raise error
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
    sse_host: Optional[str] = None  # Detected host binding (e.g., "127.0.0.1", "0.0.0.0")
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

        # Local directory (resolve to handle relative paths)
        path = Path(source).resolve()
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
                    transport, detected_host, detected_port = self._detect_python_transport(tree)
                    mcp_files.append((entry_script, transport, detected_host, detected_port))
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
                        transport, detected_host, detected_port = self._detect_python_transport(tree)
                        mcp_files.append((py_file, transport, detected_host, detected_port))
                except Exception:
                    continue

        if not mcp_files:
            raise MCPNotFoundError(f"No MCP SDK found in {entry_script or project_root}")

        # Create configs from detected files
        for py_file, transport, ast_detected_host, ast_detected_port in mcp_files:
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

            # Detect SSE port and host if using SSE transport
            sse_port = None
            sse_host = None
            if transport == "sse":
                # Use AST-detected port if available, otherwise fallback to regex detection
                sse_port = ast_detected_port or self._detect_python_sse_port(py_file)
                sse_host = ast_detected_host  # Can be None, will default to 0.0.0.0 in provisioner

            configs.append(ServerConfig(
                name=project_root.name,
                source_type="local",
                language="python",
                entry_point=entry_point,
                transport=transport,
                dependencies=[],  # TODO: Parse from requirements.txt
                env_vars={},
                sse_port=sse_port,
                sse_host=sse_host,
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

    def _detect_python_transport(self, tree: ast.AST) -> tuple[str, str | None, int | None]:
        """
        Detect transport type, host, and port from Python AST using structural signals.

        We score evidence for stdio vs SSE and pick the higher score.
        Default is stdio (safer fallback).

        Returns:
            Tuple of (transport, detected_host, detected_port)
            - transport: "sse" or "stdio"
            - detected_host: Host string (e.g., "127.0.0.1", "0.0.0.0") or None if not found
            - detected_port: Port number or None if not found
        """
        analyzer = TransportAnalyzer()
        analyzer.visit(tree)
        print(f"[*] Transport Analysis - Stdio Score: {analyzer.stdio_score}, SSE Score: {analyzer.sse_score}")

        transport = "sse" if analyzer.sse_score > analyzer.stdio_score else "stdio"

        # Report detected host/port
        if analyzer.detected_host:
            print(f"[+] Detected host from AST: {analyzer.detected_host}")
        if analyzer.detected_port:
            print(f"[+] Detected port from AST: {analyzer.detected_port}")

        return transport, analyzer.detected_host, analyzer.detected_port

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
        self.detected_host = None  # Detected host binding (e.g., "127.0.0.1", "0.0.0.0")
        self.detected_port = None  # Detected port number

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
                # Detect host and port from uvicorn.run() calls
                self._extract_host_port_from_call(node)

            # app.run() or similar (Flask, FastAPI)
            if name in ["run", "serve"]:
                self._extract_host_port_from_call(node)

            # Transport arg hints
            for kw in node.keywords:
                if kw.arg == "transport" and isinstance(kw.value, ast.Constant):
                    if kw.value.value == "sse":
                        self.sse_score += 20
                    elif kw.value.value == "stdio":
                        self.stdio_score += 20

        self.generic_visit(node)

    def _extract_host_port_from_call(self, node):
        """Extract host and port from function call keywords."""
        for kw in node.keywords:
            if kw.arg == "host" and isinstance(kw.value, ast.Constant):
                if isinstance(kw.value.value, str):
                    self.detected_host = kw.value.value
            elif kw.arg == "port" and isinstance(kw.value, ast.Constant):
                if isinstance(kw.value.value, int):
                    self.detected_port = kw.value.value

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
