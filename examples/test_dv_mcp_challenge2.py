#!/usr/bin/env python3
"""Test adapter against DV-MCP Challenge 2 (different server)"""

import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from adapters import McpClientAdapter


async def main():
    print("=== Testing McpClientAdapter with DV-MCP Challenge 2 ===\n")

    # Different port, different server!
    adapter = McpClientAdapter(
        transport="sse",
        url="http://localhost:9002/sse"
    )

    try:
        # Connect
        print("[1] Connecting to Challenge 2...")
        connection_info = await adapter.connect()
        print(f"[OK] Connected to: {connection_info['server_info']['name']}")
        print(f"     Version: {connection_info['server_info']['version']}")
        print(f"     Protocol: {connection_info['protocol_version']}\n")

        # List tools
        print("[2] Listing tools...")
        tools = await adapter.list_tools()
        print(f"[OK] Found {len(tools)} tools:")
        for tool in tools:
            print(f"     - {tool['name']}")
        print()

        # List resources
        print("[3] Listing resources...")
        resources = await adapter.list_resources()
        print(f"[OK] Found {len(resources)} resources:")
        for resource in resources:
            print(f"     - {resource['uri']}")
        print()

        # Save capture
        adapter.save_capture("captures/test_challenge2.ndjson")
        print(f"[4] Saved capture to: captures/test_challenge2.ndjson")
        print(f"    Events captured: {len(adapter.get_capture_log())}\n")

        print("=== Adapter works with different MCP server! ===")

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
