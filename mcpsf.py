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
from pathlib import Path
from datetime import datetime

from src.core.runner import TestRunner
from src.core.policy import ScopeConfig, RateLimitConfig, PolicyConfig
from src.core.models import DetectionStatus
from src.modules.registry import DetectorRegistry


def print_banner():
    """Print MCP Security Framework banner"""
    banner = """
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║           MCP Security Framework (mcpsf) v0.2.0                    ║
║           Professional Security Testing for MCP Servers            ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
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
    print_banner()

    # Parse target
    target_config = parse_target(args.target)
    print(f"\n[*] Target: {args.target}")
    print(f"[*] Transport: {target_config['transport']}")

    # Create scope configuration
    if args.scope:
        # Load from YAML file
        print(f"[*] Loading scope from: {args.scope}")
        scope = ScopeConfig.load_from_yaml(args.scope)
        if args.mode:
            scope.mode = args.mode
        if args.output:
            scope.reporting.output_dir = args.output
    else:
        # Create default scope
        scope = ScopeConfig(
            target=args.target,
            mode=args.mode or "balanced",
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

    # Parse detector IDs
    detector_ids = None
    if args.detectors:
        detector_ids = [d.strip() for d in args.detectors.split(",")]
        print(f"[*] Running specific detectors: {', '.join(detector_ids)}")
    else:
        print("[*] Running all detectors")

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
        await runner.cleanup()


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
    assess_parser.add_argument("target", help="Target MCP server (URL or stdio://command)")
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

    # list-detectors command
    subparsers.add_parser("list-detectors", help="List all available detectors")

    # version command
    subparsers.add_parser("version", help="Show version information")

    # Parse args
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # Execute command
    if args.command == "assess":
        exit_code = asyncio.run(assess_target(args))
        sys.exit(exit_code)

    elif args.command == "list-detectors":
        list_detectors()
        sys.exit(0)

    elif args.command == "version":
        print_banner()
        registry = DetectorRegistry()
        registry.load_detectors()
        print("\n[+] Version: 0.2.0")
        print("[+] Python: " + sys.version.split()[0])
        print("[+] Detectors: " + str(len(registry.get_all_detectors())))
        sys.exit(0)

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
