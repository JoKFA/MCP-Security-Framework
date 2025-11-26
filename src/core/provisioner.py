"""
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
    mocks: Dict[str, str] = None  # Mock service name → connection string

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

        Raises:
            ProvisioningError: If Docker is not available
        """
        try:
            self.docker_client = docker.from_env()
            # Test Docker connectivity
            self.docker_client.ping()
        except Exception as e:
            raise ProvisioningError(
                "Cannot connect to Docker daemon",
                suggestion="Make sure Docker is installed and running:\n"
                          "  • Windows/macOS: Start Docker Desktop\n"
                          "  • Linux: Run 'sudo systemctl start docker'\n"
                          f"  • Original error: {str(e)}"
            )

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

        # Check if Docker image exists
        try:
            self.docker_client.images.get(image)
        except docker.errors.ImageNotFound:
            raise ProvisioningError(
                f"Docker image not found: {image}",
                suggestion=f"Build the required Docker image:\n"
                          f"  docker build -t {image.split(':')[0]} -f docker/{image.split(':')[0]}.Dockerfile .\n\n"
                          f"Or build all MCPSF images:\n"
                          f"  docker build -t mcp-runner-python -f docker/mcp-runner-python.Dockerfile .\n"
                          f"  docker build -t mcp-runner-node -f docker/mcp-runner-node.Dockerfile ."
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

        # OPTIMIZATION: Pre-detect port and command using CLI detection BEFORE creating container
        # This avoids wasteful container recreation
        if config.transport == "sse" and config.project_root and config.entry_point:
            print(f"[*] Pre-detecting CLI parameters before container creation...")
            temp_container = None
            try:
                # Create temporary container just for CLI detection
                temp_volumes = {str(config.project_root.absolute()): {'bind': '/app', 'mode': 'rw'}}
                temp_labels = {"mcpsf.managed": "true", "mcpsf.temporary": "true"}
                temp_container = self.docker_client.containers.run(
                    image,
                    command=["sleep", "infinity"],  # Keep alive during detection
                    detach=True,
                    stdin_open=True,
                    volumes=temp_volumes,
                    network_mode="bridge",
                    labels=temp_labels
                )

                # Install dependencies temporarily
                await self._install_dependencies(temp_container, config)

                # Detect CLI parameters
                detected_entry, detected_port = self._detect_cli_before_start(temp_container, config)

                if detected_entry:
                    print(f"[+] Pre-detected command: {' '.join(detected_entry)}")
                    config.entry_point = detected_entry

                if detected_port and detected_port != (config.sse_port or 9001):
                    print(f"[+] Pre-detected SSE port: {detected_port}")
                    config.sse_port = detected_port

            finally:
                # Clean up temporary container
                if temp_container:
                    try:
                        temp_container.stop(timeout=1)
                        temp_container.remove()
                    except Exception as e:
                        print(f"[!] Warning: Failed to cleanup temp container: {e}")

        # Launch sidecar container
        print(f"[*] Launching sidecar container: {image}")

        # If using SSE transport, publish the SSE port to host
        ports = None
        if config.transport == "sse":
            target_port = config.sse_port or 9001
            ports = {f"{target_port}/tcp": None}  # None -> random host port

        # Add labels for container tracking and cleanup
        import time as time_module
        labels = {
            "mcpsf.managed": "true",
            "mcpsf.mcp_name": config.name,
            "mcpsf.language": config.language,
            "mcpsf.transport": config.transport,
            "mcpsf.created_at": str(int(time_module.time()))
        }

        container = self.docker_client.containers.run(
            image,
            command=["sleep", "infinity"],  # Keep alive!
            detach=True,
            stdin_open=True,
            volumes=volumes if volumes else None,
            environment=environment if environment else None,
            ports=ports,
            network_mode="bridge",
            labels=labels
        )

        print(f"[+] Sidecar container launched: {container.short_id}")

        # Install dependencies at runtime (Runner Pattern)
        if config.project_root:
            await self._install_dependencies(container, config)

        # Start SSE server (CLI already detected before container creation)
        if config.transport == "sse":
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

            # CRITICAL: Remove host's node_modules to avoid native module conflicts
            # Native modules (.node files) are compiled binaries specific to the platform
            # Host (Windows/macOS) binaries won't work in Linux container
            print(f"[*] Removing host node_modules (if exists)...")
            container.exec_run("rm -rf /app/node_modules", workdir="/app")

            # Install dependencies in container (compiles native modules for Linux)
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

    def _detect_port_from_source(self, config: ServerConfig) -> Optional[int]:
        """
        Pre-detect SSE port by analyzing source code BEFORE creating container.
        This avoids wasteful container recreation.

        Strategy:
        - Parse Python files for port assignments
        - Look for common patterns: PORT = 3001, uvicorn.run(..., port=3001)
        - Fallback to discovery.py's _detect_python_sse_port logic

        Args:
            config: Server configuration with project_root

        Returns:
            Detected port, or None if not found
        """
        if not config.project_root or config.language != "python":
            return None

        import re

        # Find Python files that likely contain the server
        search_patterns = [
            config.project_root / "server.py",
            config.project_root / "server_sse.py",
            config.project_root / "__main__.py",
            config.project_root / "src" / "server.py",
        ]

        # Also search based on entry point
        if config.entry_point and "python" in config.entry_point[0]:
            # Extract module name from entry point
            for part in config.entry_point:
                if part.endswith(".py"):
                    search_patterns.insert(0, config.project_root / part)
                elif not part.startswith("-"):
                    # Might be module name like "markitdown_mcp"
                    module_file = part.replace(".", "/") + ".py"
                    search_patterns.insert(0, config.project_root / module_file)

        for py_file in search_patterns:
            if not py_file.exists():
                continue

            try:
                text = py_file.read_text(encoding="utf-8", errors="ignore")

                # Look for port assignment patterns
                patterns = [
                    r'self\.port\s*=\s*(\d+)',      # self.port = 3001
                    r'\bport\s*=\s*(\d+)',          # port = 3001
                    r'uvicorn\.run\([^)]*port\s*=\s*(\d+)',  # uvicorn.run(..., port=3001)
                    r'PORT\s*=\s*(\d+)',            # PORT = 3001
                    r'default:\s*(\d{4,5})\)',      # default: 3001) (argparse)
                    r'port.*else\s+(\d{4,5})',      # port=args.port if args.port else 3001
                    r'"--port"[^}]*default[=:]\s*(\d{4,5})',  # "--port", default=3001
                ]

                for pattern in patterns:
                    match = re.search(pattern, text)
                    if match:
                        detected_port = int(match.group(1))
                        print(f"[+] Pre-detected port {detected_port} from {py_file.name}")
                        return detected_port

            except Exception as e:
                continue

        return None

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

        Implements Crash Analysis Loop with up to 3 retries for common failure modes:
        1. Missing system dependencies (ffmpeg, pandoc, etc.)
        2. Host binding issues (127.0.0.1 vs 0.0.0.0)
        3. Port conflicts
        """
        print(f"[*] Starting SSE server in background...")

        # Crash analysis loop - retry up to 3 times
        max_retries = 3
        for retry_attempt in range(max_retries):
            if retry_attempt > 0:
                print(f"[*] Crash analysis retry {retry_attempt}/{max_retries-1}...")

            # Construct safe shell command (config.entry_point already updated by _detect_cli_before_start)
            cmd = " ".join(shlex.quote(part) for part in config.entry_point)
            log_path = "/tmp/mcp_server.log"

            # Kill any existing server process before (re)starting
            # Always do this to ensure clean state, even on first attempt
            container.exec_run(["sh", "-c", "pkill -9 -f python || true"])
            await asyncio.sleep(2)  # Give port time to be released

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

            # Wait for server to be ready
            wait_attempts = 20 if retry_attempt == 0 else 10  # Shorter waits on retries
            for attempt in range(wait_attempts):
                try:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        async with client.stream("GET", url, headers={"accept": "text/event-stream"}) as resp:
                            if resp.status_code < 500:
                                print(f"[+] SSE server responding (HTTP {resp.status_code}) at {url}")
                                return  # Success!
                            else:
                                print(f"[!] SSE readiness attempt {attempt+1} got HTTP {resp.status_code}")
                except Exception as e:
                    last_error = e
                    if attempt == 0 or attempt % 5 == 0:  # Log every 5th attempt to reduce noise
                        print(f"[*] SSE readiness attempt {attempt+1} failed: {e}")
                await asyncio.sleep(0.5)

            # Server not responding - analyze logs to determine fix
            log_result = container.exec_run(["sh", "-c", f"tail -n 100 {log_path}"])
            log_tail = log_result.output.decode(errors="ignore") if log_result.exit_code == 0 else ""

            # Crash Analysis: Detect failure mode and apply fix
            fixed = False

            # Fix 1: Missing system dependencies (ffmpeg, pandoc, etc.)
            if self._detect_and_install_system_deps(container, log_tail, config):
                print(f"[*] Installed missing system dependencies, will retry...")
                fixed = True
                continue

            # Fix 2: Host binding issue (127.0.0.1 vs 0.0.0.0)
            if self._detect_host_binding_issue(log_tail):
                print(f"[!] Detected host binding issue (server on 127.0.0.1 not reachable from host)")
                if self._fix_host_binding(container, config, log_tail):
                    print(f"[*] Applied host binding fix, will retry...")
                    fixed = True
                    continue

            # Fix 3: Port conflict or other startup issues
            if "Address already in use" in log_tail or "EADDRINUSE" in log_tail:
                print(f"[!] Detected port conflict, incrementing port...")
                config.sse_port = (config.sse_port or 9001) + 1
                # Need to recreate container with new port - this is expensive but necessary
                raise ProvisioningError(
                    f"Port conflict detected. Please recreate container with port {config.sse_port}"
                )

            # No fix applied and out of retries
            if not fixed:
                break

        # All retries exhausted
        raise ProvisioningError(
            f"SSE server did not become ready at {url} after {max_retries} retries. "
            f"Last error: {last_error}. "
            f"Log tail:\\n{log_tail}"
        )

    def _detect_host_binding_issue(self, log_output: str) -> bool:
        """
        Detect if server started but is only listening on 127.0.0.1 (localhost).

        This is a common issue where the server runs successfully inside the container
        but doesn't bind to 0.0.0.0, making it unreachable from the host.

        Args:
            log_output: Server logs

        Returns:
            True if host binding issue detected
        """
        import re

        # Positive indicators: server started successfully
        server_started = any(pattern in log_output for pattern in [
            "Uvicorn running on",
            "Application startup complete",
            "Started server process",
            "Server started",
            "Listening on"
        ])

        if not server_started:
            return False

        # Negative indicator: bound to localhost only
        localhost_binding = bool(re.search(r'(127\.0\.0\.1|localhost):\d+', log_output))

        # Double-check: NOT bound to 0.0.0.0
        all_interfaces_binding = bool(re.search(r'0\.0\.0\.0:\d+', log_output))

        return server_started and localhost_binding and not all_interfaces_binding

    def _fix_host_binding(
        self,
        container: docker.models.containers.Container,
        config: ServerConfig,
        log_output: str
    ) -> bool:
        """
        Fix host binding issue by modifying server command to bind to 0.0.0.0.

        Strategy:
        1. Add --host 0.0.0.0 to uvicorn-based servers
        2. Inject HOST=0.0.0.0 environment variable
        3. Modify config.entry_point with new flags

        Args:
            container: Docker container
            config: Server configuration (will be modified in-place)
            log_output: Server logs

        Returns:
            True if fix was applied
        """
        # Detect server type from logs
        is_uvicorn = "uvicorn" in log_output.lower()
        is_fastapi = "fastapi" in log_output.lower() or "starlette" in log_output.lower()

        if not (is_uvicorn or is_fastapi):
            print(f"[!] Unknown server type, cannot apply host binding fix")
            return False

        # Check if --host flag already present
        if "--host" in config.entry_point:
            # Already has host flag, modify it
            try:
                host_idx = config.entry_point.index("--host")
                if host_idx + 1 < len(config.entry_point):
                    config.entry_point[host_idx + 1] = "0.0.0.0"
                    print(f"[*] Modified existing --host flag to 0.0.0.0")
                    return True
            except ValueError:
                pass

        # Add --host 0.0.0.0 flag
        # Insert before any positional arguments (typically at the end for uvicorn)
        config.entry_point.extend(["--host", "0.0.0.0"])
        print(f"[*] Added --host 0.0.0.0 to command: {' '.join(config.entry_point)}")
        return True

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
                labels={"mcpsf.managed": "true", "mcpsf.mock": "postgres"},
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
                labels={"mcpsf.managed": "true", "mcpsf.mock": "mongodb"},
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

    def __init__(self, message: str, suggestion: str = None):
        full_message = message
        if suggestion:
            full_message += f"\n\n💡 Suggestion: {suggestion}"
        elif "port" in message.lower() or "address already in use" in message.lower():
            full_message += "\n\n💡 Suggestion: Port conflict detected"
            full_message += "\n  • Another service is using this port"
            full_message += "\n  • Run 'docker ps' to see active containers"
            full_message += "\n  • Or run 'mcpsf cleanup' to remove orphaned containers"
        elif "connection" in message.lower() or "not become ready" in message.lower():
            full_message += "\n\n💡 Suggestion: Server failed to start"
            full_message += "\n  • Check container logs above for errors"
            full_message += "\n  • Verify server code has no syntax errors"
            full_message += "\n  • Missing dependencies will be auto-installed (check retry logs)"
        super().__init__(full_message)
