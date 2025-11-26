"""
Test AMSAW v2 with Wikipedia MCP (local project). Uses aggressive profile.

Discovery intentionally points only at the project root (no subpath hints) so
we exercise the generic detection flow. This may fail if dependencies/SDK are
missing; failures are printed for visibility.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_wikipedia_mcp():
    print("=" * 70)
    print("  AMSAW v2 Test: Wikipedia MCP (Local)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        result = await pipeline.run(
            source="./targets/wikipedia-mcp",
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
            print("[SUCCESS] Wikipedia MCP test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found")

    except Exception as e:
        print(f"[ERROR] Wikipedia MCP test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_wikipedia_mcp())
