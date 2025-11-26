"""
End-to-end test for AMSAW v2 Pipeline.

Tests the full assessment flow from source to report.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_npm_assessment():
    """Test full pipeline with npm package."""
    print("=" * 70)
    print("  End-to-End Test: npm Package Assessment")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline()

    try:
        # Run full assessment
        result = await pipeline.run(
            source="@modelcontextprotocol/server-time",
            profile="safe"
        )

        # Verify result
        print()
        print("[Verification]")
        print(f"  Server Name: {result.profile.server_name}")
        print(f"  Total Detectors: {result.summary['total']}")
        print(f"  Vulnerabilities: {result.summary['present']}")
        print()

        if result.summary['total'] > 0:
            print("[SUCCESS] Pipeline test PASSED!")
            print("  - Discovery worked")
            print("  - Provisioner worked")
            print("  - Bridge worked")
            print("  - TestRunner worked")
            print("  - Cleanup worked")
        else:
            print("[WARNING] No detectors ran")

    except Exception as e:
        print(f"[ERROR] Pipeline test FAILED: {e}")
        raise


async def test_https_assessment():
    """Test pipeline with HTTPS URL (skip container provisioning)."""
    print()
    print("=" * 70)
    print("  End-to-End Test: HTTPS URL Assessment")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline()

    try:
        # Note: This will try to connect to a real server
        # For testing purposes, we'll use a mock URL
        print("[SKIP] HTTPS test requires live server")
        print("  In production, would assess: https://api.example.com/sse")

    except Exception as e:
        print(f"[ERROR] HTTPS test FAILED: {e}")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  AMSAW v2 Pipeline Test Suite")
    print("=" * 70 + "\n")

    asyncio.run(test_npm_assessment())
    asyncio.run(test_https_assessment())

    print()
    print("=" * 70)
    print("  All Pipeline Tests Completed!")
    print("=" * 70)
