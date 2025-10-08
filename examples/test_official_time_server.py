#!/usr/bin/env python3
"""Test adapter against official MCP Time server (stdio transport)"""

import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from adapters import McpClientAdapter


async def main():
    print("=== Testing McpClientAdapter with Official MCP Time Server (stdio) ===\n")

    # This is a REAL production MCP server using stdio transport!
    adapter = McpClientAdapter(
        transport="stdio",
        command="python",
        args=["-m", "mcp_server_time"]
    )

    try:
        # Connect
        print("[1] Connecting to official MCP Time server...")
        connection_info = await adapter.connect()
        print(f"[OK] Connected to: {connection_info['server_info']['name']}")
        print(f"     Version: {connection_info['server_info']['version']}")
        print(f"     Protocol: {connection_info['protocol_version']}")
        print(f"     Transport: {connection_info['transport']}\n")

        # List tools
        print("[2] Listing tools...")
        tools = await adapter.list_tools()
        print(f"[OK] Found {len(tools)} tools:")
        for tool in tools:
            print(f"     - {tool['name']}: {tool.get('description', 'No description')}")
        print()

        # Call get_current_time tool
        print("[3] Calling tool: get_current_time")
        result = await adapter.call_tool("get_current_time", {
            "timezone": "America/New_York"
        })
        print(f"[OK] Result:")
        for item in result['content']:
            if item.get('text'):
                print(f"     {item['text']}")
        print()

        # Save capture
        adapter.save_capture("captures/test_official_time.ndjson")
        print(f"[4] Saved capture to: captures/test_official_time.ndjson")
        print(f"    Events captured: {len(adapter.get_capture_log())}\n")

        print("=== Success! Adapter works with STDIO transport and official MCP server! ===")

    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        await adapter.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
