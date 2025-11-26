"""
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
