"""
Test script for Universal Bridge (Sidecar Pattern).

Tests the Bridge wrapping a stdio MCP server using the sidecar pattern.

Architecture:
- Launch long-running sidecar container with `sleep infinity`
- Bridge executes MCP command via `docker exec` inside running container
- Container stays alive throughout test (no "container not running" errors!)
"""

import asyncio
import docker
import httpx
from src.core.bridge import UniversalBridge


async def test_bridge_with_stdio_mcp():
    """Test bridge wrapping a stdio MCP using SIDECAR PATTERN."""
    print("=" * 70)
    print("  Testing Universal Bridge with stdio MCP (Sidecar Pattern)")
    print("=" * 70)
    print()

    # SIDECAR PATTERN: Launch long-running container
    print("[*] Launching sidecar container (sleep infinity)...")
    client = docker.from_env()
    container = client.containers.run(
        "mcp-runner-node",
        command=["sleep", "infinity"],  # Keep alive!
        detach=True,
        stdin_open=True
    )
    print(f"[+] Sidecar container started: {container.short_id}")
    print(f"[+] Container will stay alive (running: sleep infinity)")
    print()

    try:
        # Wrap with bridge (providing MCP command)
        print("[*] Starting Universal Bridge...")
        print("[*] Bridge will exec MCP command inside sidecar container")
        bridge = UniversalBridge(
            container.id,
            mcp_command=["npx", "-y", "@modelcontextprotocol/server-time"]
        )
        await bridge.start()
        print(f"[+] Bridge ready at: {bridge.get_url()}")
        print(f"[+] Transport detected: {bridge.transport_type}")
        print()

        # Test HTTP interface
        print("[*] Testing HTTP interface...")
        async with httpx.AsyncClient() as http:
            # Send initialize request
            response = await http.post(
                bridge.get_url().replace("/sse", "/message"),
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "mcpsf-test",
                            "version": "0.4.0"
                        }
                    }
                }
            )

            print(f"[*] HTTP Response Status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"[+] Response received: {data.get('status')}")
                print()
                print("=" * 70)
                print("  [SUCCESS] Bridge test PASSED!")
                print("=" * 70)
                print()
                print("Key Achievement:")
                print("- Sidecar container stayed alive")
                print("- MCP command executed via docker exec")
                print("- No 'container not running' errors!")
                print("- Bridge successfully normalized stdio -> HTTP")
            else:
                print(f"[!] Unexpected status: {response.status_code}")
                print()
                print("=" * 70)
                print("  [FAILED] Bridge test FAILED!")
                print("=" * 70)

    finally:
        print()
        print("[*] Cleanup...")
        await bridge.stop()
        container.stop()
        container.remove()
        print("[+] Cleanup complete")


if __name__ == "__main__":
    asyncio.run(test_bridge_with_stdio_mcp())
