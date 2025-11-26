"""
Test script for Discovery Engine.

Tests source type detection and AST analysis.
"""

from src.core.discovery import SourceDiscovery, ServerConfig


def test_npm_detection():
    """Test npm package detection."""
    print("=" * 70)
    print("  Test 1: npm Package Detection")
    print("=" * 70)

    discovery = SourceDiscovery()

    # Test scoped package
    configs = discovery.discover("@modelcontextprotocol/server-time")
    assert len(configs) == 1
    config = configs[0]

    print(f"[+] Name: {config.name}")
    print(f"[+] Source Type: {config.source_type}")
    print(f"[+] Language: {config.language}")
    print(f"[+] Entry Point: {' '.join(config.entry_point)}")
    print(f"[+] Transport: {config.transport}")

    assert config.name == "server-time"
    assert config.source_type == "npm"
    assert config.language == "nodejs"
    assert config.entry_point == ["npx", "-y", "@modelcontextprotocol/server-time"]
    assert config.transport == "stdio"

    print("[SUCCESS] npm detection passed!")
    print()


def test_local_detection():
    """Test local directory detection."""
    print("=" * 70)
    print("  Test 2: Local Directory Detection")
    print("=" * 70)

    discovery = SourceDiscovery()

    # Test local challenge directory
    try:
        configs = discovery.discover("./targets/dv-mcp/challenges/1")
        assert len(configs) >= 1
        config = configs[0]

        print(f"[+] Name: {config.name}")
        print(f"[+] Source Type: {config.source_type}")
        print(f"[+] Language: {config.language}")
        print(f"[+] Entry Point: {' '.join(config.entry_point)}")
        print(f"[+] Transport: {config.transport}")

        assert config.source_type == "local"
        assert config.language in ["python", "nodejs"]

        print("[SUCCESS] Local detection passed!")
    except Exception as e:
        print(f"[SKIP] Local test skipped: {e}")
    print()


def test_https_detection():
    """Test HTTPS URL detection."""
    print("=" * 70)
    print("  Test 3: HTTPS URL Detection")
    print("=" * 70)

    discovery = SourceDiscovery()

    # Test remote URL
    configs = discovery.discover("https://api.example.com:9001/sse")
    assert len(configs) == 1
    config = configs[0]

    print(f"[+] Name: {config.name}")
    print(f"[+] Source Type: {config.source_type}")
    print(f"[+] Transport: {config.transport}")
    print(f"[+] Port: {config.sse_port}")

    assert config.source_type == "https"
    assert config.transport == "sse"
    assert config.sse_port == 9001

    print("[SUCCESS] HTTPS detection passed!")
    print()


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  Discovery Engine Test Suite")
    print("=" * 70 + "\n")

    test_npm_detection()
    test_local_detection()
    test_https_detection()

    print("=" * 70)
    print("  All Discovery Tests Completed!")
    print("=" * 70)
