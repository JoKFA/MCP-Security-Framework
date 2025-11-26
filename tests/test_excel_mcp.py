"""
Test AMSAW v2 with Excel MCP (local project). Uses aggressive profile.

Runs the full pipeline against ./targets/excel-mcp-server.
"""

import asyncio
from src.core.pipeline import AssessmentPipeline


async def test_excel_mcp():
    print("=" * 70)
    print("  AMSAW v2 Test: Excel MCP (Local)")
    print("=" * 70)
    print()

    pipeline = AssessmentPipeline(interactive=False)
    source = "./targets/excel-mcp-server"

    try:
        # Excel MCP's Typer CLI needs a subcommand (stdio/sse/streamable-http).
        # Force stdio so the bridge receives a running server.
        configs = pipeline.discovery.discover(source)
        if not configs:
            raise RuntimeError("Discovery returned no configs for Excel MCP")
        config = configs[0]
        if "stdio" not in config.entry_point:
            config.entry_point.append("stdio")
        pipeline.discovery.discover = lambda _: configs

        result = await pipeline.run(
            source=source,
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
            print("[SUCCESS] Excel MCP test PASSED!")
        else:
            print("[WARNING] No vulnerabilities found")

    except Exception as e:
        print(f"[ERROR] Excel MCP test FAILED: {e}")
        import traceback
        traceback.print_exc()
        raise


if __name__ == "__main__":
    asyncio.run(test_excel_mcp())
