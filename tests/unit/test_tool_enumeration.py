"""
Unit tests for ToolEnumerationDetector (adapted from josh-test)
"""

import pytest
from unittest.mock import AsyncMock

from src.modules.detectors.tool_enumeration import ToolEnumerationDetector
from src.core.models import (
    DetectionStatus,
    SignalType,
    ServerProfile,
)


@pytest.fixture
def detector():
    """Create detector instance"""
    return ToolEnumerationDetector()


@pytest.fixture
def mock_adapter():
    """Create mock adapter"""
    adapter = AsyncMock()
    return adapter


@pytest.fixture
def server_profile():
    """Create server profile with tools capability"""
    from src.core.models import ServerCapabilities
    return ServerProfile(
        server_name="Test Server",
        server_version="1.0.0",
        protocol_version="2024-11-05",
        capabilities=ServerCapabilities(tools=True),
        transport="sse"
    )


class TestToolEnumerationDetectorMetadata:
    """Test detector metadata"""

    def test_metadata_fields(self, detector):
        """Test all metadata fields are properly set"""
        meta = detector.metadata
        assert meta.id == "MCP-2024-TE-001"
        assert meta.name == "Tool Enumeration Analyzer"
        assert meta.version == "1.0.0"
        assert meta.prerequisites == {"tools": True}
        assert meta.timeout_s == 20
        assert meta.severity_default == "MEDIUM"

    def test_standards_mapping(self, detector):
        """Test standards are properly mapped"""
        standards = detector.metadata.standards
        assert standards.cwe == "CWE-250"
        assert standards.owasp_api == "API4"
        assert standards.asvs == ["V4.1"]
        assert standards.cvss.base_score == 6.5
        assert standards.cvss.severity == "MEDIUM"


class TestToolRiskAnalysis:
    """Test tool risk analysis logic"""

    def test_dangerous_tool_execute_keyword(self, detector):
        """Test detection of tool with 'execute' keyword"""
        tool = {
            "name": "execute_command",
            "description": "Execute system commands",
            "inputSchema": {"properties": {}}
        }
        risks = detector._analyze_tool_for_risks(tool)
        assert len(risks) > 0
        assert any(r['type'] == 'dangerous_tool' and r['keyword'] == 'execute' for r in risks)

    def test_dangerous_tool_shell_keyword(self, detector):
        """Test detection of tool with 'shell' keyword"""
        tool = {
            "name": "shell_access",
            "description": "Provides shell access",
            "inputSchema": {}
        }
        risks = detector._analyze_tool_for_risks(tool)
        assert len(risks) > 0
        assert any(r['type'] == 'dangerous_tool' and r['keyword'] == 'shell' for r in risks)

    def test_dangerous_tool_delete_keyword(self, detector):
        """Test detection of tool with 'delete' keyword"""
        tool = {
            "name": "delete_files",
            "description": "Delete files from system",
            "inputSchema": {}
        }
        risks = detector._analyze_tool_for_risks(tool)
        assert len(risks) > 0
        assert any(r['type'] == 'dangerous_tool' and r['keyword'] == 'delete' for r in risks)

    def test_dangerous_tool_admin_keyword(self, detector):
        """Test detection of tool with 'admin' keyword"""
        tool = {
            "name": "admin_panel",
            "description": "Administrative control panel",
            "inputSchema": {}
        }
        risks = detector._analyze_tool_for_risks(tool)
        assert len(risks) > 0
        assert any(r['type'] == 'dangerous_tool' and r['keyword'] == 'admin' for r in risks)

    def test_tool_no_input_validation(self, detector):
        """Test detection of tool with empty input schema"""
        tool = {
            "name": "some_tool",
            "description": "A tool",
            "inputSchema": {"properties": {}}
        }
        risks = detector._analyze_tool_for_risks(tool)
        assert any(r['type'] == 'no_input_validation' for r in risks)

    def test_tool_missing_input_schema(self, detector):
        """Test detection of tool with no input schema"""
        tool = {
            "name": "unsafe_tool",
            "description": "Tool without schema"
        }
        risks = detector._analyze_tool_for_risks(tool)
        assert any(r['type'] == 'missing_input_schema' for r in risks)

    def test_safe_tool_with_schema(self, detector):
        """Test that safe tool with proper schema has no risks"""
        tool = {
            "name": "get_weather",
            "description": "Get weather information",
            "inputSchema": {
                "properties": {
                    "location": {"type": "string"}
                }
            }
        }
        risks = detector._analyze_tool_for_risks(tool)
        # Should have no dangerous keyword risks, and has proper schema
        assert len(risks) == 0

    def test_multiple_risks_detected(self, detector):
        """Test tool with multiple risk factors"""
        tool = {
            "name": "execute_admin_command",
            "description": "Execute administrative commands",
            "inputSchema": {}  # Missing schema too
        }
        risks = detector._analyze_tool_for_risks(tool)
        # Should detect both 'execute' and 'admin' keywords
        assert len(risks) >= 2
        dangerous_risks = [r for r in risks if r['type'] == 'dangerous_tool']
        assert len(dangerous_risks) >= 2


class TestSignalTypeMapping:
    """Test signal type mapping"""

    def test_map_dangerous_tool(self, detector):
        """Test mapping for dangerous tool"""
        signal_type = detector._get_signal_type_for_risk('dangerous_tool')
        assert signal_type == SignalType.SCHEMA_OVERPERMISSIVE

    def test_map_no_input_validation(self, detector):
        """Test mapping for no input validation"""
        signal_type = detector._get_signal_type_for_risk('no_input_validation')
        assert signal_type == SignalType.SCHEMA_OVERPERMISSIVE

    def test_map_missing_input_schema(self, detector):
        """Test mapping for missing input schema"""
        signal_type = detector._get_signal_type_for_risk('missing_input_schema')
        assert signal_type == SignalType.SCHEMA_OVERPERMISSIVE

    def test_map_unknown_type(self, detector):
        """Test mapping for unknown risk type"""
        signal_type = detector._get_signal_type_for_risk('unknown_type')
        assert signal_type == SignalType.REFLECTION  # Default fallback


class TestToolEnumerationDetection:
    """Test main detection logic"""

    @pytest.mark.asyncio
    async def test_detect_dangerous_tools(self, detector, mock_adapter, server_profile):
        """Test detection of dangerous tools"""
        mock_adapter.list_tools.return_value = [
            {
                "name": "execute_command",
                "description": "Execute system commands",
                "inputSchema": {}
            },
            {
                "name": "safe_tool",
                "description": "Safe operation",
                "inputSchema": {"properties": {"input": {"type": "string"}}}
            }
        ]

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.detector_id == "MCP-2024-TE-001"
        assert result.status == DetectionStatus.PRESENT
        assert result.confidence == 0.90
        assert len(result.signals) > 0
        assert result.evidence['tools_analyzed'] == 2
        assert len(result.evidence['dangerous_tools']) > 0

    @pytest.mark.asyncio
    async def test_no_tools_available(self, detector, mock_adapter, server_profile):
        """Test when no tools are available"""
        mock_adapter.list_tools.return_value = []

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.ABSENT
        assert result.confidence == 0.0
        assert result.evidence['tools_analyzed'] == 0

    @pytest.mark.asyncio
    async def test_all_safe_tools(self, detector, mock_adapter, server_profile):
        """Test when all tools are safe"""
        mock_adapter.list_tools.return_value = [
            {
                "name": "get_weather",
                "description": "Get weather information",
                "inputSchema": {"properties": {"location": {"type": "string"}}}
            },
            {
                "name": "calculate",
                "description": "Perform calculation",
                "inputSchema": {"properties": {"expression": {"type": "string"}}}
            }
        ]

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.ABSENT
        assert len(result.signals) == 0

    @pytest.mark.asyncio
    async def test_tools_without_validation(self, detector, mock_adapter, server_profile):
        """Test detection of tools without input validation"""
        mock_adapter.list_tools.return_value = [
            {
                "name": "some_tool",
                "description": "A tool",
                "inputSchema": {"properties": {}}
            }
        ]

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.PRESENT
        assert len(result.evidence['tools_without_validation']) > 0

    @pytest.mark.asyncio
    async def test_multiple_dangerous_keywords(self, detector, mock_adapter, server_profile):
        """Test tool with multiple dangerous keywords"""
        mock_adapter.list_tools.return_value = [
            {
                "name": "admin_shell_execute",
                "description": "Administrative shell execution",
                "inputSchema": {}
            }
        ]

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.PRESENT
        # Should detect admin, shell, and execute
        assert len(result.signals) >= 3
        assert result.evidence['risk_summary']['dangerous_tool'] >= 3

    @pytest.mark.asyncio
    async def test_error_handling(self, detector, mock_adapter, server_profile):
        """Test error handling in detector"""
        mock_adapter.list_tools.side_effect = Exception("Connection failed")

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.UNKNOWN
        assert result.confidence == 0.0
        assert 'error' in result.evidence
        assert 'Connection failed' in result.evidence['error']

    @pytest.mark.asyncio
    async def test_signal_context_contains_rationale(self, detector, mock_adapter, server_profile):
        """Test that signals contain detailed context"""
        mock_adapter.list_tools.return_value = [
            {
                "name": "delete_files",
                "description": "Delete files",
                "inputSchema": {}
            }
        ]

        result = await detector.run(mock_adapter, None, server_profile)

        assert len(result.signals) > 0
        signal = result.signals[0]
        assert 'rationale' in signal.context
        assert 'tool_name' in signal.context
        assert signal.context['tool_name'] == 'delete_files'

    @pytest.mark.asyncio
    async def test_evidence_risk_summary(self, detector, mock_adapter, server_profile):
        """Test that evidence contains risk summary"""
        mock_adapter.list_tools.return_value = [
            {
                "name": "execute_command",
                "description": "Execute commands",
                "inputSchema": {}
            },
            {
                "name": "admin_access",
                "description": "Admin access",
                "inputSchema": {"properties": {}}
            }
        ]

        result = await detector.run(mock_adapter, None, server_profile)

        assert 'risk_summary' in result.evidence
        assert 'dangerous_tool' in result.evidence['risk_summary']
        assert result.evidence['risk_summary']['dangerous_tool'] >= 2

    @pytest.mark.asyncio
    async def test_successful_detection_completes(self, detector, mock_adapter, server_profile):
        """Test that detector completes successfully with clean tools"""
        mock_adapter.list_tools.return_value = [
            {
                "name": "safe_tool",
                "description": "Safe",
                "inputSchema": {"properties": {"x": {"type": "string"}}}
            }
        ]

        result = await detector.run(mock_adapter, None, server_profile)

        assert result.status == DetectionStatus.ABSENT
        assert result.confidence == 0.90
        assert result.detector_id == "MCP-2024-TE-001"
