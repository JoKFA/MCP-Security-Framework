#!/usr/bin/env python3
"""
MCP Security Framework (mcpsf) - Command Line Interface

Usage:
    mcpsf assess <target> [options]
    mcpsf list-detectors
    mcpsf version

Examples:
    # Assess an SSE server
    mcpsf assess http://localhost:9001/sse

    # Assess with scope file
    mcpsf assess http://localhost:9001/sse --scope scope.yaml

    # Run specific detectors only
    mcpsf assess http://localhost:9001/sse --detectors MCP-2024-PI-001,MCP-2024-CE-001

    # Save reports to custom directory
    mcpsf assess http://localhost:9001/sse --output ./my-reports

    # Stdio transport
    mcpsf assess stdio://npx/-s/@modelcontextprotocol/server-filesystem/tmp/testdir
"""

import sys
import asyncio
import argparse
import re
from pathlib import Path
from datetime import datetime

from src.core.runner import TestRunner
from src.core.policy import ScopeConfig, RateLimitConfig, PolicyConfig
from src.core.models import DetectionStatus
from src.modules.registry import DetectorRegistry

# Version
VERSION = "0.4.0"


def run_async(coro):
    """
    Run an async coroutine without using asyncio.run().

    This avoids asyncio.run() shutdown noise from third-party libraries.
    """
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def print_banner():
    """Print MCP Security Framework banner"""
    try:
        banner = f"""
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║           MCP Security Framework (mcpsf) v{VERSION}                    ║
║           Professional Security Testing for MCP Servers            ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
"""
        print(banner)
    except UnicodeEncodeError:
        # Fallback for Windows consoles that don't support Unicode box characters
        banner = f"""
======================================================================

           MCP Security Framework (mcpsf) v{VERSION}
           Professional Security Testing for MCP Servers

======================================================================
"""
        print(banner)


def list_detectors():
    """List all available detectors"""
    print_banner()
    print("\n[*] Available Detectors:\n")

    registry = DetectorRegistry()
    registry.load_detectors()
    detectors = registry.get_all_detectors()

    if not detectors:
        print("    No detectors found!")
        return

    print(f"{'ID':<25} {'Name':<45} {'Severity':<10}")
    print("-" * 85)

    for detector in detectors:
        meta = detector.metadata
        print(f"{meta.id:<25} {meta.name:<45} {meta.severity_default:<10}")

    print(f"\n[+] Total: {len(detectors)} detectors\n")


def cleanup_containers(args):
    """Clean up orphaned MCPSF containers"""
    import docker
    from datetime import datetime

    print_banner()
    print("\n[*] Scanning for orphaned MCPSF containers...\n")

    try:
        docker_client = docker.from_env()
    except Exception as e:
        print(f"[!] Error: Cannot connect to Docker: {e}")
        print("[*] Make sure Docker is running")
        return 1

    # Find all containers with mcpsf.managed label
    try:
        mcpsf_containers = docker_client.containers.list(
            all=True,
            filters={"label": "mcpsf.managed=true"}
        )
    except Exception as e:
        print(f"[!] Error listing containers: {e}")
        return 1

    if not mcpsf_containers:
        print("[+] No MCPSF containers found")
        return 0

    print(f"[*] Found {len(mcpsf_containers)} MCPSF container(s):\n")

    # Display containers with details
    for container in mcpsf_containers:
        labels = container.labels
        mcp_name = labels.get("mcpsf.mcp_name", "unknown")
        language = labels.get("mcpsf.language", "unknown")
        transport = labels.get("mcpsf.transport", "unknown")
        created_at = labels.get("mcpsf.created_at", "unknown")
        is_mock = labels.get("mcpsf.mock", None)
        is_temp = labels.get("mcpsf.temporary", None)

        # Calculate age
        age_str = "unknown"
        if created_at != "unknown":
            try:
                created_timestamp = int(created_at)
                age_seconds = int(datetime.now().timestamp()) - created_timestamp
                age_minutes = age_seconds // 60
                age_hours = age_minutes // 60
                if age_hours > 0:
                    age_str = f"{age_hours}h {age_minutes % 60}m"
                else:
                    age_str = f"{age_minutes}m"
            except:
                pass

        container_type = "Mock" if is_mock else ("Temporary" if is_temp else "MCP")
        status = container.status

        print(f"  [{container.short_id}] {container_type}")
        print(f"    Name:      {mcp_name}")
        print(f"    Language:  {language}")
        print(f"    Transport: {transport}")
        print(f"    Status:    {status}")
        print(f"    Age:       {age_str}")
        if is_mock:
            print(f"    Mock Type: {is_mock}")
        print()

    # Ask for confirmation unless --force flag is used
    if not args.force:
        response = input(f"Remove all {len(mcpsf_containers)} container(s)? [y/N]: ").strip().lower()
        if response not in ['y', 'yes']:
            print("[*] Cleanup cancelled")
            return 0

    # Remove containers
    print()
    removed_count = 0
    error_count = 0

    for container in mcpsf_containers:
        try:
            print(f"[*] Removing {container.short_id}...")
            if container.status == "running":
                container.stop(timeout=2)
            container.remove()
            removed_count += 1
            print(f"[+] Removed {container.short_id}")
        except Exception as e:
            error_count += 1
            print(f"[!] Failed to remove {container.short_id}: {e}")

    print()
    print("=" * 70)
    if error_count == 0:
        print(f"[+] Successfully removed {removed_count} container(s)")
    else:
        print(f"[+] Removed {removed_count} container(s), {error_count} failed")
    print("=" * 70)

    return 0 if error_count == 0 else 1


def parse_target(target_str: str) -> dict:
    """
    Parse target string into transport config.

    Formats:
    - http://localhost:9001/sse  -> SSE transport
    - stdio://command/arg1/arg2  -> stdio transport
    """
    if target_str.startswith("http://") or target_str.startswith("https://"):
        return {
            "transport": "sse",
            "url": target_str
        }
    elif target_str.startswith("stdio://"):
        # Format: stdio://command/arg1/arg2/...
        parts = target_str[8:].split("/")
        command = parts[0] if parts else "npx"
        args = parts[1:] if len(parts) > 1 else []
        return {
            "transport": "stdio",
            "command": command,
            "args": args
        }
    else:
        # Assume SSE if no protocol
        if not target_str.startswith("http"):
            target_str = f"http://{target_str}"
        return {
            "transport": "sse",
            "url": target_str
        }


async def assess_target(args):
    """Run assessment against target"""
    from src.core.pipeline import AssessmentPipeline
    from src.core.discovery import SourceDetectionError

    print_banner()

    try:
        # Mode 1: AMSAW v2 Auto-sandbox (npm/github/local/https sources)
        if args.target:
            # Try new pipeline first - it handles all source types
            try:
                pipeline = AssessmentPipeline(interactive=True)  # Allow credential prompts

                print(f"\n[*] AMSAW v2 - Automatic MCP Security Assessment")
                print(f"[*] Source: {args.target}\n")

                # Parse detector IDs
                detector_ids = None
                if args.detectors:
                    detector_ids = [d.strip() for d in args.detectors.split(",")]

                # Run assessment through new pipeline
                result = await pipeline.run(
                    source=args.target,
                    profile=args.profile or args.mode or "balanced",
                    detectors=detector_ids
                )

                # Generate reports
                from src.core.reporters.manager import ReportManager

                output_dir = Path(args.output) if args.output else Path("./reports")
                report_mgr = ReportManager(reports_dir=output_dir)

                # Generate bundle with all report formats
                bundle_path = report_mgr.generate_bundle(result, bundle_name=None)

                # Print summary
                print("\n" + "=" * 70)
                print("  ASSESSMENT COMPLETE")
                print("=" * 70)

                vulns = [r for r in result.results if r.status.value == "PRESENT"]
                if vulns:
                    print(f"\n[!] Vulnerabilities found: {len(vulns)}")
                    for vuln in vulns:
                        severity = vuln.standards.cvss.severity.upper() if vuln.standards and vuln.standards.cvss else "UNKNOWN"
                        name = vuln.detector_name or vuln.detector_id
                        print(f"    [{severity}] {vuln.detector_id}: {name}")
                    print(f"\nReports saved to: {output_dir}")
                    return 1  # Exit code 1 = vulnerabilities found
                else:
                    print(f"\n[+] No vulnerabilities found")
                    print(f"Reports saved to: {output_dir}")
                    return 0  # Exit code 0 = clean

            except SourceDetectionError as e:
                # Not a recognized source, fall through to legacy URL handling
                print(f"[!] Warning: {e}")
                print(f"[*] Falling back to direct URL mode...")
            except Exception as e:
                print(f"[!] Pipeline error: {e}")
                print(f"[*] Falling back to direct URL mode...")
                import traceback
                traceback.print_exc()

        # Mode 2: Direct URL/command (legacy mode)
        if args.target:
            target_config = parse_target(args.target)
            print(f"\n[*] Target: {args.target}")
            print(f"[*] Transport: {target_config['transport']}")

            # Create scope configuration
            if args.scope:
                # Load from YAML file
                print(f"[*] Loading scope from: {args.scope}")
                scope = ScopeConfig.load_from_yaml(args.scope)
                if args.mode or args.profile:
                    scope.mode = args.profile or args.mode
                if args.output:
                    scope.reporting.output_dir = args.output
            else:
                # Create default scope
                scope = ScopeConfig(
                    target=args.target,
                    mode=args.profile or args.mode or "balanced",
                    allowed_prefixes=["internal://", "file://", "/resources", "/tools/"],
                    blocked_paths=[],
                    rate_limit=RateLimitConfig(qps=3, burst=5),
                    policy=PolicyConfig(
                        dry_run=False,
                        redact_evidence=True,
                        max_payload_kb=256,
                        max_total_requests=1000,
                    )
                )
                if args.output:
                    scope.reporting.output_dir = args.output

        else:
            print("\n[!] Error: Must specify <target>")
            print("[*] Example:")
            print("    mcpsf assess http://localhost:9001/sse")
            return 1

        # Parse detector IDs
        detector_ids = None
        if args.detectors:
            detector_ids = [d.strip() for d in args.detectors.split(",")]
            print(f"[*] Running specific detectors: {', '.join(detector_ids)}")
        else:
            print("[*] Running all detectors")

    except Exception as e:
        print(f"\n[!] Failed to prepare assessment: {e}")
        return 1

    # Create test runner
    print("\n[*] Initializing assessment engine...")
    runner = TestRunner(scope)

    try:
        # Run assessment
        print("[*] Starting assessment (this may take 1-3 minutes)...\n")

        result = await runner.assess(detector_ids=detector_ids)

        # Generate report bundle using ReportManager
        print("\n[*] Generating assessment reports...")
        from src.core.reporters.manager import ReportManager
        report_manager = ReportManager()

        # Create bundle name from server or output arg
        if args.output:
            bundle_name = Path(args.output).name  # Use last component if path given
        else:
            # Auto-name from server
            server_name = result.profile.server_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
            bundle_name = server_name

        # Generate complete bundle (JSON, SARIF, CLI reports + audit log + metadata)
        bundle_dir = report_manager.generate_bundle(
            result,
            bundle_name=bundle_name
        )

        print(f"[*] Output directory: {bundle_dir}")

        # Print summary
        print("\n" + "="*70)
        print("  ASSESSMENT COMPLETE")
        print("="*70)

        print(f"\n[+] Server: {result.profile.server_name}")
        print(f"[+] Version: {result.profile.server_version}")
        print(f"[+] Protocol: {result.profile.protocol_version}")
        print(f"[+] Transport: {result.profile.transport}")

        # Count results
        present = sum(1 for r in result.results if r.status == DetectionStatus.PRESENT)
        absent = sum(1 for r in result.results if r.status == DetectionStatus.ABSENT)
        unknown = sum(1 for r in result.results if r.status == DetectionStatus.UNKNOWN)
        na = sum(1 for r in result.results if r.status == DetectionStatus.NOT_APPLICABLE)

        print(f"\n[RESULTS]")
        print(f"  Detectors run:        {len(result.results)}")
        print(f"  Vulnerabilities:      {present}")
        print(f"  Passed:               {absent}")
        print(f"  Unknown:              {unknown}")
        print(f"  Not Applicable:       {na}")

        # Show vulnerabilities
        if present > 0:
            print(f"\n[!] VULNERABILITIES DETECTED:")
            for r in result.results:
                if r.status == DetectionStatus.PRESENT:
                    severity = r.standards.cvss.severity if r.standards and r.standards.cvss else 'HIGH'
                    print(f"\n  [{severity}] {r.detector_name}")
                    print(f"      ID: {r.detector_id}")
                    print(f"      Confidence: {r.confidence:.0%}")
                    if r.affected_resources:
                        print(f"      Affected: {', '.join(r.affected_resources[:3])}")
                    if r.proof_of_concepts:
                        print(f"      PoCs: {len(r.proof_of_concepts)}")

        # Show report locations
        print(f"\n[+] Reports saved to: {bundle_dir}")
        for item in sorted(bundle_dir.iterdir()):
            print(f"    - {item.name}")

        # Print to console if verbose
        if args.verbose:
            print("\n" + "="*70)
            cli_output = report_manager.generate_cli_output(result, verbose=True, use_colors=False)
            print(cli_output)

        print(f"\n[+] Assessment ID: {result.assessment_id}")
        print(f"[+] Duration: {(result.completed_at - result.started_at).total_seconds():.2f}s")

        # Exit code based on findings
        if present > 0:
            print(f"\n[!] Exiting with code 1 (vulnerabilities found)")
            return 1
        else:
            print(f"\n[+] Exiting with code 0 (no vulnerabilities found)")
            return 0

    except Exception as e:
        print(f"\n[!] Assessment failed with error:")
        print(f"    {type(e).__name__}: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    finally:
        # Cleanup assessment
        if 'runner' in locals():
            await runner.cleanup()
            print("[+] Server stopped")






def targets_init(args):
    """Initialize new target (DEPRECATED - use auto-sandbox instead)"""
    print("\n[!] The 'targets' registry system has been deprecated in v0.4")
    print("[*] Use auto-sandbox instead:")
    print("")
    print("    # Assess local MCP directory")
    print("    mcpsf assess ./path/to/mcp-server")
    print("")
    print("    # Assess npm package")
    print("    mcpsf assess @modelcontextprotocol/server-time")
    print("")
    print("    # Assess GitHub repo")
    print("    mcpsf assess https://github.com/user/mcp-server")
    print("")
    return 1


def targets_show(args):
    """DEPRECATED - show target info"""
    print("\n[!] The 'targets' registry system has been deprecated in v0.4")
    print("[*] Use auto-sandbox assess directly instead")
    return 1


def targets_validate(args):
    """DEPRECATED - validate target profile"""
    print("\n[!] The 'targets' registry system has been deprecated in v0.4")
    print("[*] Use auto-sandbox assess directly instead")
    return 1


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="MCP Security Framework - Professional security testing for MCP servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Assess an SSE server
  mcpsf assess http://localhost:9001/sse

  # Assess with custom scope
  mcpsf assess http://localhost:9001/sse --scope scope.yaml

  # Run specific detectors
  mcpsf assess http://localhost:9001/sse --detectors MCP-2024-PI-001,MCP-2024-CE-001

  # Stdio transport
  mcpsf assess stdio://npx/-s/@modelcontextprotocol/server-filesystem/tmp/testdir

For more information, see: https://github.com/yourorg/mcp-security-framework
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # assess command
    assess_parser = subparsers.add_parser("assess", help="Assess an MCP server for vulnerabilities")
    assess_parser.add_argument("target", nargs="?", help="Target MCP server (URL or stdio://command) - optional if using --target flag")
    assess_parser.add_argument("-s", "--scope", help="Path to scope.yaml configuration file")
    assess_parser.add_argument("-d", "--detectors", help="Comma-separated list of detector IDs to run")
    assess_parser.add_argument("-o", "--output", help="Output directory for reports")
    assess_parser.add_argument(
        "--mode",
        choices=["safe", "balanced", "aggressive"],
        default=None,
        help="Assessment intensity: safe (minimal probing), balanced (default), aggressive (full active testing)",
    )
    assess_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    assess_parser.add_argument("--profile", help="Assessment profile mode (alias for --mode)")

    # targets command group
    targets_parser = subparsers.add_parser("targets", help="Manage target registry")
    targets_subparsers = targets_parser.add_subparsers(dest="targets_command", help="Target management commands")

    # targets list
    list_parser = targets_subparsers.add_parser("list", help="List all targets")
    list_parser.add_argument("--tag", help="Filter by tag")
    list_parser.add_argument("--status", choices=["active", "disabled", "maintenance"], help="Filter by status")

    # targets show
    show_parser = targets_subparsers.add_parser("show", help="Show target details")
    show_parser.add_argument("target_id", help="Target ID")

    # targets validate
    validate_parser = targets_subparsers.add_parser("validate", help="Validate target profile or registry")
    validate_parser.add_argument("profile", nargs="?", help="Profile YAML to validate (omit to validate entire registry)")

    # targets init
    init_parser = targets_subparsers.add_parser("init", help="Initialize new target")
    init_parser.add_argument("--id", help="Target ID")
    init_parser.add_argument("--type", choices=["sse", "stdio"], help="Transport type")
    init_parser.add_argument("--url", help="SSE URL or stdio command")
    init_parser.add_argument("--command", help="stdio command (for stdio type)")
    init_parser.add_argument("--args", help="Command arguments (comma-separated)")
    init_parser.add_argument("--tags", help="Tags (comma-separated)")
    init_parser.add_argument("--probe", help="Probe URL to auto-detect configuration")

    # list-detectors command
    subparsers.add_parser("list-detectors", help="List all available detectors")

    # batch command
    batch_parser = subparsers.add_parser("batch", help="Run batch assessments against multiple targets")
    batch_parser.add_argument("targets", help="Target selector (all | tag=X | id=a,b | group=G | status=active)")
    batch_parser.add_argument("--profile", choices=["safe", "balanced", "aggressive"], default="balanced", help="Assessment profile (default: balanced)")
    batch_parser.add_argument("--concurrency", type=int, default=3, help="Maximum concurrent targets (default: 3, max: 10)")
    batch_parser.add_argument("--timeout", type=int, default=300, help="Per-target timeout in seconds (default: 300)")
    batch_parser.add_argument("--resume", action="store_true", help="Resume from previous batch state")
    batch_parser.add_argument("--detectors", help="Comma-separated detector IDs to run")
    batch_parser.add_argument("--scope", help="Override scope.yaml for all targets")
    batch_parser.add_argument("--output", help="Batch output directory (default: reports/)")
    batch_parser.add_argument("--no-skip-completed", action="store_true", help="Do not skip targets already marked completed in batch state")

    # cleanup command
    cleanup_parser = subparsers.add_parser("cleanup", help="Clean up orphaned MCPSF containers")
    cleanup_parser.add_argument("--force", "-f", action="store_true", help="Skip confirmation prompt")

    # version command
    subparsers.add_parser("version", help="Show version information")

    # Parse args
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Execute command
    if args.command == "assess":
        exit_code = run_async(assess_target(args))
        sys.exit(exit_code)

    elif args.command == "list-detectors":
        list_detectors()
        sys.exit(0)

    elif args.command == "cleanup":
        exit_code = cleanup_containers(args)
        sys.exit(exit_code)

    elif args.command == "version":
        print_banner()
        registry = DetectorRegistry()
        registry.load_detectors()
        print(f"\n[+] Version: {VERSION}")
        print("[+] Python: " + sys.version.split()[0])
        print("[+] Detectors: " + str(len(registry.get_all_detectors())))
        sys.exit(0)

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
