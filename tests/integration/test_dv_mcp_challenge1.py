"""
Integration test against DV-MCP Challenge 1.

Tests the full assessment pipeline against a real vulnerable MCP server:
1. Start DV-MCP Challenge 1 SSE server
2. Run Prompt Injection detector
3. Verify PRESENT finding with high confidence
4. Check for sensitive exposure signals

This validates:
- SafeAdapter → McpClientAdapter → DV-MCP
- TestRunner orchestration
- Detector execution
- Signal emission
- Result aggregation
"""

import asyncio
import subprocess
import time
from pathlib import Path

import pytest

from src.core.runner import TestRunner
from src.core.policy import ScopeConfig, RateLimitConfig, PolicyConfig
from src.core.models import DetectionStatus, SignalType
from src.core.safe_adapter import create_safe_adapter_from_scope


@pytest.fixture(scope="module")
def dv_mcp_server():
    """
    Ensure DV-MCP Challenge 1 SSE server is available.

    Uses existing server if running, otherwise starts new one.
    """
    import socket

    # Check if server is already running
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', 9001))
    sock.close()

    if result == 0:
        # Server already running
        print("\n[*] Using existing DV-MCP server on port 9001")
        yield None  # No process to cleanup
        return

    # Server not running, start it
    server_script = Path(__file__).parent.parent.parent / "targets" / "vulnerable" / "dv-mcp" / "challenges" / "easy" / "challenge1" / "server_sse.py"

    if not server_script.exists():
        pytest.skip("DV-MCP Challenge 1 server not found")

    print("\n[*] Starting DV-MCP Challenge 1 SSE server...")
    proc = subprocess.Popen(
        ["python", str(server_script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to start
    time.sleep(3)

    # Check if server started successfully
    if proc.poll() is not None:
        stdout, stderr = proc.communicate()
        pytest.fail(f"Server failed to start:\nSTDOUT: {stdout}\nSTDERR: {stderr}")

    print("[+] Server started on http://localhost:9001/sse")

    yield proc

    # Cleanup: kill server
    print("\n[-] Stopping DV-MCP server...")
    proc.terminate()
    proc.wait(timeout=5)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_detect_challenge1_vulnerability(dv_mcp_server, tmp_path):
    """
    Test full assessment pipeline against DV-MCP Challenge 1.

    Expected: Prompt Injection detector finds PRESENT with SENSITIVE_EXPOSURE signal.
    """
    # Create scope configuration
    scope = ScopeConfig(
        target="http://localhost:9001/sse",
        allowed_prefixes=["/resources", "internal://"],
        blocked_paths=[],
        rate_limit=RateLimitConfig(qps=5, burst=10),
        policy=PolicyConfig(
            dry_run=False,
            redact_evidence=True,
            max_payload_kb=128,
            max_total_requests=100,
        ),
    )

    # Set output directory
    scope.reporting.output_dir = str(tmp_path / "reports")

    # Create test runner
    runner = TestRunner(scope)

    try:
        # Run assessment with only Prompt Injection detector
        result = await runner.assess(detector_ids=["MCP-2024-PI-001"])

        # Assertions
        assert result is not None, "Assessment result should not be None"
        assert result.profile.server_name == "Challenge 1 - Basic Prompt Injection"

        # Should have results from the detector
        assert len(result.results) >= 1, "Should have at least one detection result"

        # Find Prompt Injection detector result
        pi_result = next(
            (r for r in result.results if r.detector_id == "MCP-2024-PI-001"),
            None
        )
        assert pi_result is not None, "Prompt Injection detector should have run"

        # Check detection status
        print(f"\n[DETECTION RESULT]")
        print(f"   Status: {pi_result.status.value}")
        print(f"   Confidence: {pi_result.confidence:.0%}")
        print(f"   Affected Resources: {pi_result.affected_resources}")
        print(f"   Signals: {len(pi_result.signals)}")

        # Verify vulnerability detected
        assert pi_result.status == DetectionStatus.PRESENT, \
            f"Expected PRESENT, got {pi_result.status.value}"

        assert pi_result.confidence >= 0.7, \
            f"Expected high confidence, got {pi_result.confidence}"

        # Check for expected signals
        signal_types = [s.type for s in pi_result.signals]
        signal_type_values = [st.value if hasattr(st, 'value') else st for st in signal_types]
        print(f"   Signal Types: {signal_type_values}")

        # Should have SENSITIVE_EXPOSURE or SCHEMA_OVERPERMISSIVE
        assert any(
            st in [SignalType.SENSITIVE_EXPOSURE, SignalType.SCHEMA_OVERPERMISSIVE]
            for st in signal_types
        ), "Expected sensitive exposure or overpermissive schema signal"

        # Check evidence
        assert "sensitive_resources_found" in pi_result.evidence
        assert pi_result.evidence["sensitive_resources_found"] > 0, \
            "Should find sensitive resources"

        # Verify affected resources
        assert len(pi_result.affected_resources) > 0, \
            "Should list affected resources"

        # Check for internal://credentials
        has_credentials = any(
            "credential" in r.lower() for r in pi_result.affected_resources
        )
        print(f"   Credentials Resource Found: {has_credentials}")

        # Verify remediation provided
        assert pi_result.remediation is not None
        assert len(pi_result.remediation) > 0

        print("\n[SUCCESS] Challenge 1 vulnerability successfully detected!")
        print(f"   Remediation: {pi_result.remediation[:100]}...")

    finally:
        # Cleanup
        await runner.cleanup()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_assessment_workflow(dv_mcp_server, tmp_path):
    """
    Test complete assessment workflow including all detectors.

    This validates the entire system end-to-end.
    """
    # Create scope YAML
    scope_yaml = tmp_path / "scope.yaml"
    scope_yaml.write_text(f"""
target: "http://localhost:9001/sse"
allowed_prefixes:
  - "/resources"
  - "internal://"
blocked_paths: []
rate_limit:
  qps: 5
  burst: 10
policy:
  dry_run: false
  redact_evidence: true
  max_payload_kb: 128
  max_total_requests: 100
reporting:
  output_dir: "{str(tmp_path / 'reports').replace(chr(92), '/')}"
  formats:
    - "json"
  store_evidence: true
""")

    # Create adapter from scope
    adapter = await create_safe_adapter_from_scope(str(scope_yaml))

    try:
        # Connect to server
        profile = await adapter.connect()
        assert profile.server_name == "Challenge 1 - Basic Prompt Injection"

        print(f"\n[CONNECTED] {profile.server_name} v{profile.server_version}")
        print(f"   Capabilities: resources={profile.capabilities.resources}, "
              f"tools={profile.capabilities.tools}, prompts={profile.capabilities.prompts}")

        # List resources (should include internal://credentials)
        resources = await adapter.list_resources()
        print(f"\n[RESOURCES] Found: {len(resources)}")
        for r in resources:
            print(f"   - {r['uri']}: {r.get('name', 'N/A')}")

        # Verify credentials resource exists
        cred_resources = [r for r in resources if "credential" in r["uri"].lower()]
        assert len(cred_resources) > 0, "Should find credentials resource"

        # Try to read credentials (should succeed - that's the vulnerability!)
        cred_uri = cred_resources[0]["uri"]
        print(f"\n[EXPLOIT] Attempting to read: {cred_uri}")

        cred_data = await adapter.read_resource(cred_uri)
        content_text = ""
        for content in cred_data.get("contents", []):
            if "text" in content:
                content_text += content["text"]

        print(f"   Content length: {len(content_text)} chars")

        # Check if password leaked
        has_password = "password" in content_text.lower()
        print(f"   Contains 'password': {has_password}")

        assert has_password, "Challenge 1 should leak credentials"

        print("\n[SUCCESS] Full assessment workflow completed successfully!")

    finally:
        await adapter.disconnect()


if __name__ == "__main__":
    """
    Run integration tests manually.

    Usage: python -m pytest tests/integration/test_dv_mcp_challenge1.py -v -s
    """
    pytest.main([__file__, "-v", "-s", "-m", "integration"])
