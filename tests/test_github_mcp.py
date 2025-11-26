"""
Test AMSAW v2 with a GitHub-hosted MCP (server-time repo path). Uses aggressive profile.
Discovery clones and analyzes without hardcoding subpaths beyond the GitHub URL itself.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_github_mcp():
    print("=" * 70)
    print("  AMSAW v2 Test: GitHub MCP (server-time)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        result = await pipeline.run(
            source="https://github.com/modelcontextprotocol/servers/tree/main/src/time",
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
            print("[SUCCESS] GitHub MCP test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found")

    except Exception as e:
        print(f"[ERROR] GitHub MCP test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_github_mcp())
