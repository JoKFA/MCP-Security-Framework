"""
Smoke test for DV-MCP Challenge 2 (local target).

Uses aggressive profile to exercise full pipeline end-to-end.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_challenge2():
    print("=" * 70)
    print("  AMSAW v2 Test: DV-MCP Challenge 2 (Local)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        result = await pipeline.run(
            source="./targets/vulnerable/dv-mcp/challenges/easy/challenge2",
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
            print("[SUCCESS] Challenge 2 test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found (expected at least 1)")

    except Exception as e:
        print(f"[ERROR] Challenge 2 test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_challenge2())

