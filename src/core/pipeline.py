"""
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
          ↓
    Discovery Engine → ServerConfig
          ↓
    Provisioner → ProvisionedContainer
          ↓
    Universal Bridge → Normalized HTTP URL
          ↓
    TestRunner → AssessmentResult
          ↓
    Reports (JSON, SARIF, CLI)

Design Principles:
==================

1. **Error Handling at Each Phase**
   - Discovery fails → Clear error message
   - Provisioning fails → Cleanup and report
   - Bridge fails → Cleanup and report
   - Assessment fails → Still generate partial report

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
import signal
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
        self._shutdown_requested = False
        self._active_resources = {
            "bridge": None,
            "runner": None,
            "provisioned": None
        }

    def _setup_signal_handlers(self):
        """
        Setup signal handlers for graceful shutdown.

        Catches Ctrl+C (SIGINT) and SIGTERM to ensure containers are cleaned up.
        """
        def signal_handler(signum, frame):
            if not self._shutdown_requested:
                self._shutdown_requested = True
                print("\n[!] Interrupt received, cleaning up containers...")
                # The cleanup will happen in the finally block

        # Register handlers (Windows supports SIGINT, Unix supports both)
        signal.signal(signal.SIGINT, signal_handler)
        try:
            signal.signal(signal.SIGTERM, signal_handler)
        except (AttributeError, ValueError):
            # SIGTERM not available on Windows
            pass

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

        # Setup signal handlers for graceful shutdown
        self._setup_signal_handlers()

        print("=" * 70)
        print("  AMSAW v2 - Automatic MCP Security Assessment")
        print("=" * 70)
        print()

        container = None
        bridge = None
        runner = None
        provisioned = None

        try:
            # Check for shutdown request
            if self._shutdown_requested:
                raise KeyboardInterrupt("Assessment cancelled by user")
            # Phase 1: Discovery
            print("[Phase 1] Discovery Engine")
            print("-" * 70)
            configs = self.discovery.discover(source)
            if not configs:
                raise MCPNotFoundError(f"No MCP servers found in: {source}")

            # Handle monorepo: if multiple configs found, use first or let user choose
            if len(configs) > 1:
                print(f"[*] Found {len(configs)} MCP servers in repository:")
                for i, cfg in enumerate(configs, 1):
                    print(f"    {i}. {cfg.name} ({cfg.language}, {cfg.transport})")
                print(f"[*] Assessing first server: {configs[0].name}")
                print(f"    (Use mcpsf assess <source> --server-index=N to select a different server)")

            config = configs[0]  # Use first config (TODO: add CLI flag for selection)
            print(f"[+] Found: {config.name}")
            print(f"[+] Language: {config.language}")
            print(f"[+] Transport: {config.transport}")
            print()

            # Check for shutdown before provisioning
            if self._shutdown_requested:
                raise KeyboardInterrupt("Assessment cancelled by user")

            # Phase 2: Provisioner
            print("[Phase 2] Container Provisioner")
            print("-" * 70)
            provisioned = await self.provisioner.provision(config)
            self._active_resources["provisioned"] = provisioned  # Track for cleanup

            if provisioned.container_id:
                print(f"[+] Container: {provisioned.container_id[:12]}")
                print(f"[+] Image: {provisioned.image}")
                if provisioned.mocks:
                    print(f"[+] Mocks: {', '.join(provisioned.mocks.keys())}")
                print()

                # Check for shutdown before bridging
                if self._shutdown_requested:
                    raise KeyboardInterrupt("Assessment cancelled by user")

                # Phase 3: Universal Bridge
                print("[Phase 3] Universal Bridge")
                print("-" * 70)
                bridge = UniversalBridge(
                    provisioned.container_id,
                    mcp_command=provisioned.mcp_command,
                    container_port=config.sse_port or 9001,
                    transport_hint=config.transport
                )
                self._active_resources["bridge"] = bridge  # Track for cleanup
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

            # Check for shutdown before assessment
            if self._shutdown_requested:
                raise KeyboardInterrupt("Assessment cancelled by user")

            # Phase 4: TestRunner (existing code!)
            print("[Phase 4] Security Assessment")
            print("-" * 70)
            scope = ScopeConfig(
                target=url,
                transport=config.transport,
                mode=profile
            )
            runner = TestRunner(scope=scope)
            self._active_resources["runner"] = runner  # Track for cleanup
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
            # Cleanup (ALWAYS runs - even on Ctrl+C!)
            print()
            if self._shutdown_requested:
                print("[Cleanup] Interrupted assessment - cleaning up resources...")
            else:
                print("[Cleanup] Stopping services...")

            # Use tracked resources for cleanup
            runner = self._active_resources.get("runner") or runner
            bridge = self._active_resources.get("bridge") or bridge
            provisioned = self._active_resources.get("provisioned") or provisioned

            cleanup_errors = []

            # Cleanup runner
            if runner:
                try:
                    await runner.cleanup()
                    print("[+] TestRunner cleaned up")
                except Exception as e:
                    cleanup_errors.append(f"Runner: {e}")
                    print(f"[!] Warning: Runner cleanup failed: {e}")

            # Cleanup bridge
            if bridge:
                try:
                    await bridge.stop()
                    print("[+] Bridge stopped")
                except Exception as e:
                    cleanup_errors.append(f"Bridge: {e}")
                    print(f"[!] Warning: Bridge cleanup failed: {e}")

            # Cleanup main container
            if provisioned and provisioned.container_id:
                try:
                    container = self.provisioner.docker_client.containers.get(
                        provisioned.container_id
                    )
                    container.stop(timeout=2)
                    container.remove()
                    print(f"[+] Container {provisioned.container_id[:12]} stopped and removed")
                except Exception as e:
                    cleanup_errors.append(f"Container {provisioned.container_id[:12]}: {e}")
                    print(f"[!] Warning: Container cleanup failed: {e}")

            # Cleanup provisioner (mock containers)
            try:
                await self.provisioner.cleanup()
                if self.provisioner.mock_containers:
                    print(f"[+] Mock containers cleaned up")
            except Exception as e:
                cleanup_errors.append(f"Provisioner: {e}")
                print(f"[!] Warning: Provisioner cleanup failed: {e}")

            if cleanup_errors:
                print(f"[!] Cleanup completed with {len(cleanup_errors)} warning(s)")
            else:
                print("[+] Cleanup complete - all resources released")
            print()
