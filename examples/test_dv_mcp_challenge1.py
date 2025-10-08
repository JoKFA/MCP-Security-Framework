#!/usr/bin/env python3
"""
Test script for MCP SDK-based adapter

Tests connection to DV-MCP Challenge 1 using the official MCP client
"""

import sys
import asyncio
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from adapters.mcp_client_adapter import McpClientAdapter


async def main():
    print("=== MCP Security Testing Framework - MCP SDK Adapter Test ===\n")

    # Create adapter for SSE transport
    adapter = McpClientAdapter(
        transport="sse",
        url="http://localhost:9001/sse"
    )

    try:
        # Step 1: Connect
        print("[1] Connecting to DV-MCP Challenge 1...")
        connection_info = await adapter.connect()
        print(f"[OK] Connected to: {connection_info['server_info']['name']}")
        print(f"     Version: {connection_info['server_info']['version']}")
        print(f"     Protocol: {connection_info['protocol_version']}")
        print(f"     Capabilities: {json.dumps(connection_info['capabilities'], indent=6)}\n")

        # Step 2: List available resources
        print("[2] Listing available resources...")
        resources = await adapter.list_resources()
        print(f"[OK] Found {len(resources)} resources:")
        for resource in resources:
            print(f"     - {resource['uri']}")
            if resource.get('description'):
                print(f"       {resource['description']}")
        print()

        # Step 3: List available tools
        print("[3] Listing available tools...")
        tools = await adapter.list_tools()
        print(f"[OK] Found {len(tools)} tools:")
        for tool in tools:
            print(f"     - {tool['name']}: {tool.get('description', 'No description')}")
        print()

        # Step 4: Read a resource (attempt to read credentials)
        print("[4] Reading resource: internal://credentials")
        try:
            resource_data = await adapter.read_resource("internal://credentials")
            print(f"[OK] Resource content:")
            for content in resource_data['contents']:
                if content.get('text'):
                    print(f"     {content['text'][:200]}...")
        except Exception as e:
            print(f"[ERROR] Failed to read resource: {e}")
        print()

        # Step 5: Call a tool
        print("[5] Calling tool: get_user_info")
        try:
            result = await adapter.call_tool("get_user_info", {"username": "admin"})
            print(f"[OK] Tool result:")
            for item in result['content']:
                if item.get('text'):
                    print(f"     {item['text']}")
        except Exception as e:
            print(f"[ERROR] Failed to call tool: {e}")
        print()

        # Step 6: Save capture
        capture_file = "captures/test_mcp_challenge1.ndjson"
        adapter.save_capture(capture_file)
        print(f"[6] Saved capture to: {capture_file}")
        print(f"    Total events captured: {len(adapter.get_capture_log())}\n")

        print("=== Test Complete ===")
        print("\nCapture log contains:")
        for event in adapter.get_capture_log():
            print(f"  - {event['type']} at {event['ts']}")

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
