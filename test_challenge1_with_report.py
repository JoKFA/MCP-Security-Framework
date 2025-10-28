#!/usr/bin/env python3
"""
Test MCP Security Framework against DV-MCP Challenge 1.

This script:
1. Runs all detectors against Challenge 1
2. Generates reports in all formats
3. Creates a complete bundle
4. Prints summary to console
"""

import asyncio
from pathlib import Path

from src.core.runner import TestRunner
from src.core.policy import ScopeConfig
from src.core.reporters.manager import ReportManager


async def main():
    """Run assessment against DV-MCP Challenge 1."""
    print("=" * 80)
    print("MCP Security Framework - DV-MCP Challenge 1 Assessment")
    print("=" * 80)
    print()

    # Configure target
    scope = ScopeConfig(
        target="http://localhost:9001/sse",
        transport="sse",
        allowed_prefixes=["internal://", "notes://", "/"],  # Allow access to internal and notes resources
        blocked_paths=[],  # Don't block anything for testing
    )

    print(f"Target: {scope.target}")
    print(f"Transport: {scope.transport}")
    print(f"Max requests: {scope.policy.max_total_requests}")
    print()

    # Run assessment
    print("Running detectors...")
    runner = TestRunner(scope)

    try:
        result = await runner.assess()

        print(f"[OK] Assessment complete: {result.assessment_id}")
        print(f"  Duration: {(result.completed_at - result.started_at).total_seconds():.2f}s")
        print(f"  Detectors run: {len(result.results)}")
        print()
    finally:
        await runner.cleanup()

    # Generate report bundle
    print("Generating assessment bundle...")
    report_manager = ReportManager()

    # Create complete bundle (all formats + audit log + metadata)
    bundle_dir = report_manager.generate_bundle(
        result,
        bundle_name="Challenge1_Basic_Prompt_Injection"
    )
    print(f"  [OK] Bundle created: {bundle_dir}")
    print()

    # List bundle contents
    print("Bundle contents:")
    for item in sorted(bundle_dir.iterdir()):
        size = item.stat().st_size
        print(f"  - {item.name:20s} ({size:,} bytes)")

    print()
    print("=" * 80)
    print("Assessment complete!")
    print()

    # Print quick summary
    present = result.summary.get('present', 0)
    absent = result.summary.get('absent', 0)

    if present > 0:
        print(f"[WARNING] Found {present} vulnerability/vulnerabilities")
        print()
        print("Detected issues:")
        for detector_result in result.results:
            if detector_result.status.value == "PRESENT":
                severity = detector_result.standards.cvss.severity if detector_result.standards.cvss else "UNKNOWN"
                print(f"  - [{severity}] {detector_result.detector_name}")
                print(f"    Signals: {len(detector_result.signals)}")
                print(f"    PoCs: {len(detector_result.proof_of_concepts)}")
    else:
        print("[OK] No vulnerabilities detected")

    print()
    print(f"Reports:  {report_manager.reports_dir}")
    print(f"Captures: {report_manager.captures_dir}")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
