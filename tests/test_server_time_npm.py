"""
Test AMSAW v2 with npm MCP @modelcontextprotocol/server-time (stdio). Uses aggressive profile.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_server_time_npm():
    print("=" * 70)
    print("  AMSAW v2 Test: npm @modelcontextprotocol/server-time")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        result = await pipeline.run(
            source="@szemeng76/mcp-time-server",
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
            print("[SUCCESS] npm server-time test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found")

    except Exception as e:
        print(f"[ERROR] npm server-time test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_server_time_npm())
