"""Quick test to verify Discovery picks SSE server."""

from src.core.discovery import SourceDiscovery

discovery = SourceDiscovery()
configs = discovery.discover("./targets/vulnerable/dv-mcp/challenges/easy/challenge1")

print("=" * 70)
print("  Discovery Test - Challenge 1")
print("=" * 70)
print(f"Found {len(configs)} config(s)")
for i, config in enumerate(configs):
    print(f"\nConfig {i+1}:")
    print(f"  Name: {config.name}")
    print(f"  Transport: {config.transport}")
    print(f"  Entry Point: {' '.join(config.entry_point)}")
    print(f"  Language: {config.language}")
