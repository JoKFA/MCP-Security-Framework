"""
Test AMSAW v2 with Microsoft MarkItDown MCP (GitHub).

Real-world test: https://github.com/microsoft/markitdown/tree/main/packages/markitdown-mcp
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_markitdown_mcp():
    print("=" * 70)
    print("  AMSAW v2 Test: Microsoft MarkItDown MCP (GitHub)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)

    try:
        result = await pipeline.run(
            source="https://github.com/microsoft/markitdown/tree/main/packages/markitdown-mcp",
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
            print("[SUCCESS] MarkItDown MCP test PASSED - Vulnerabilities found!")
        else:
            print("[SUCCESS] MarkItDown MCP test PASSED - No vulnerabilities found (clean server)")

    except Exception as e:
        print(f"[ERROR] MarkItDown MCP test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_markitdown_mcp())
