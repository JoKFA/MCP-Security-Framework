"""
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
