"""
Unit tests for core models.

Tests validation, serialization, and JSON round-trip behavior.
"""

import json
from datetime import datetime
import pytest

from src.core.models import (
    DetectionStatus,
    SignalType,
    Signal,
    CVSSVector,
    StandardsMapping,
    DetectionResult,
    ServerCapabilities,
    ServerProfile,
    AttackChain,
    RemediationAction,
    ThreatModel,
    AssessmentResult,
    ModuleMetadata,
)


class TestDetectionStatus:
    """Test DetectionStatus enum."""

    def test_all_statuses(self):
        assert DetectionStatus.PRESENT == "PRESENT"
        assert DetectionStatus.ABSENT == "ABSENT"
        assert DetectionStatus.UNKNOWN == "UNKNOWN"
        assert DetectionStatus.NOT_APPLICABLE == "NOT_APPLICABLE"


class TestSignal:
    """Test Signal model."""

    def test_signal_creation(self):
        signal = Signal(
            type=SignalType.REFLECTION,
            value=True,
            context={"canary": "MCP_TEST_123", "uri": "/resources/test"}
        )
        assert signal.type == SignalType.REFLECTION
        assert signal.value is True
        assert signal.context["canary"] == "MCP_TEST_123"
        assert isinstance(signal.timestamp, datetime)

    def test_signal_json_roundtrip(self):
        signal = Signal(
            type=SignalType.ERROR_SIGNATURE,
            value="StackTrace: /internal/path/server.py:123",
            context={"method": "read_resource"}
        )
        json_str = signal.model_dump_json()
        reconstructed = Signal.model_validate_json(json_str)
        assert reconstructed.type == signal.type
        assert reconstructed.value == signal.value


class TestStandardsMapping:
    """Test StandardsMapping model."""

    def test_cvss_vector_validation(self):
        cvss = CVSSVector(
            vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            base_score=7.5,
            severity="HIGH"
        )
        assert cvss.base_score == 7.5
        assert cvss.severity == "HIGH"

    def test_cvss_score_bounds(self):
        with pytest.raises(Exception):  # Pydantic ValidationError
            CVSSVector(
                vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                base_score=11.0,  # Invalid: > 10
                severity="CRITICAL"
            )

    def test_cvss_severity_validation(self):
        with pytest.raises(Exception):  # Pydantic ValidationError
            CVSSVector(
                vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                base_score=7.5,
                severity="SUPER_CRITICAL"  # Invalid severity
            )

    def test_standards_mapping_complete(self):
        mapping = StandardsMapping(
            cwe="CWE-74",
            owasp_llm="LLM01",
            owasp_api="API8:2023",
            asvs=["V5.1", "V9.1"],
            capec=["CAPEC-242"],
            cvss=CVSSVector(
                vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                base_score=7.5,
                severity="HIGH"
            )
        )
        assert mapping.cwe == "CWE-74"
        assert "V5.1" in mapping.asvs


class TestDetectionResult:
    """Test DetectionResult model."""

    def test_minimal_result(self):
        result = DetectionResult(
            detector_id="MCP-2024-001",
            detector_name="Test Detector",
            detector_version="1.0.0",
            status=DetectionStatus.ABSENT,
            confidence=0.95
        )
        assert result.status == DetectionStatus.ABSENT
        assert result.confidence == 0.95
        assert len(result.signals) == 0

    def test_result_with_signals(self):
        signal1 = Signal(type=SignalType.REFLECTION, value=True, context={})
        signal2 = Signal(type=SignalType.AUTH_MISMATCH, value=True, context={})

        result = DetectionResult(
            detector_id="MCP-2024-PI-001",
            detector_name="Prompt Injection Detector",
            detector_version="1.0.0",
            status=DetectionStatus.PRESENT,
            confidence=0.90,
            affected_resources=["/resources/credentials"],
            signals=[signal1, signal2],
            evidence={"canary_reflected": True, "response_hash": "abc123"},
            standards=StandardsMapping(cwe="CWE-74", owasp_llm="LLM01"),
            remediation="Implement input validation on resource parameters"
        )
        assert result.status == DetectionStatus.PRESENT
        assert len(result.signals) == 2
        assert result.remediation is not None

    def test_result_json_roundtrip(self):
        result = DetectionResult(
            detector_id="MCP-2024-001",
            detector_name="Test",
            detector_version="1.0.0",
            status=DetectionStatus.UNKNOWN,
            confidence=0.3,
            execution_time_ms=1234.56
        )
        json_str = result.model_dump_json()
        reconstructed = DetectionResult.model_validate_json(json_str)
        assert reconstructed.detector_id == result.detector_id
        assert reconstructed.execution_time_ms == result.execution_time_ms


class TestServerProfile:
    """Test ServerProfile model."""

    def test_server_profile_creation(self):
        profile = ServerProfile(
            server_name="DV-MCP Challenge 1",
            server_version="1.16.0",
            protocol_version="2024-11-05",
            capabilities=ServerCapabilities(resources=True, tools=True),
            transport="sse",
            endpoint="http://localhost:9001/sse",
            auth_type="none",
            exposure="local"
        )
        assert profile.server_name == "DV-MCP Challenge 1"
        assert profile.capabilities.resources is True
        assert profile.transport == "sse"

    def test_server_profile_json(self):
        profile = ServerProfile(
            server_name="Test Server",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            transport="stdio"
        )
        json_str = profile.model_dump_json()
        data = json.loads(json_str)
        assert data["server_name"] == "Test Server"


class TestThreatModel:
    """Test ThreatModel and AttackChain models."""

    def test_attack_chain_creation(self):
        signal1 = Signal(type=SignalType.AUTH_MISMATCH, value=True, context={})
        signal2 = Signal(type=SignalType.SENSITIVE_EXPOSURE, value=True, context={})

        chain = AttackChain(
            name="Unauthorized Data Access",
            severity="CRITICAL",
            required_signals=[SignalType.AUTH_MISMATCH, SignalType.SENSITIVE_EXPOSURE],
            detected_signals=[signal1, signal2],
            affected_resources=["/resources/credentials"],
            impact="Potential data breach via unauthenticated access",
            likelihood="HIGH",
            uplift_score=1.0
        )
        assert chain.severity == "CRITICAL"
        assert len(chain.detected_signals) == 2
        assert chain.uplift_score == 1.0

    def test_remediation_action(self):
        action = RemediationAction(
            action="Implement authentication on all resource endpoints",
            effort="MEDIUM",
            impact="HIGH",
            priority=1
        )
        assert action.effort == "MEDIUM"
        assert action.impact == "HIGH"

    def test_threat_model(self):
        chain = AttackChain(
            name="Test Chain",
            severity="HIGH",
            required_signals=[SignalType.REFLECTION],
            detected_signals=[],
            impact="Test impact",
            likelihood="MEDIUM",
            uplift_score=0.5
        )

        model = ThreatModel(
            overall_risk=7.5,
            risk_level="HIGH",
            chains=[chain],
            prioritized_mitigations=[
                RemediationAction(
                    action="Fix issue 1",
                    effort="LOW",
                    impact="HIGH",
                    priority=1
                )
            ],
            summary="Test threat model"
        )
        assert model.overall_risk == 7.5
        assert model.risk_level == "HIGH"
        assert len(model.chains) == 1


class TestAssessmentResult:
    """Test AssessmentResult (top-level output)."""

    def test_assessment_result_minimal(self):
        now = datetime.utcnow()
        profile = ServerProfile(
            server_name="Test",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            transport="stdio"
        )

        assessment = AssessmentResult(
            assessment_id="test-123",
            started_at=now,
            completed_at=now,
            scope={"target": "stdio://test"},
            profile=profile,
            summary={"present": 1, "absent": 2, "unknown": 0, "not_applicable": 1}
        )
        assert assessment.assessment_id == "test-123"
        assert assessment.profile.server_name == "Test"
        assert assessment.summary["present"] == 1

    def test_assessment_result_json_roundtrip(self):
        now = datetime.utcnow()
        profile = ServerProfile(
            server_name="Test",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            transport="stdio"
        )

        assessment = AssessmentResult(
            assessment_id="test-456",
            started_at=now,
            completed_at=now,
            scope={},
            profile=profile
        )

        json_str = assessment.model_dump_json()
        reconstructed = AssessmentResult.model_validate_json(json_str)
        assert reconstructed.assessment_id == assessment.assessment_id


class TestModuleMetadata:
    """Test ModuleMetadata model."""

    def test_module_metadata_creation(self):
        metadata = ModuleMetadata(
            id="MCP-2024-PI-001",
            name="Prompt Injection Detector",
            version="1.0.0",
            description="Detects prompt injection via resource parameters",
            prerequisites={"resources": True},
            timeout_s=30,
            severity_default="HIGH",
            standards=StandardsMapping(cwe="CWE-74", owasp_llm="LLM01")
        )
        assert metadata.id == "MCP-2024-PI-001"
        assert metadata.prerequisites["resources"] is True
        assert metadata.severity_default == "HIGH"

    def test_severity_validation(self):
        with pytest.raises(Exception):  # Pydantic ValidationError
            ModuleMetadata(
                id="TEST",
                name="Test",
                version="1.0.0",
                description="Test",
                severity_default="EXTREME"  # Invalid
            )
