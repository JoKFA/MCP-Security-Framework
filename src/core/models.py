"""
Core data models for MCP Security Framework.

All models use Pydantic for validation, serialization, and JSON round-trip guarantees.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict


# ============================================================================
# Detection Status & Signals
# ============================================================================

class DetectionStatus(str, Enum):
    """
    Status of a detection module's assessment.

    - PRESENT: Vulnerability or misconfiguration detected with high confidence
    - ABSENT: Detector ran successfully; no issues found
    - UNKNOWN: Inconclusive (timeouts, ambiguous responses, partial data)
    - NOT_APPLICABLE: Target lacks required capabilities (e.g., no resources/list)
    """
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SignalType(str, Enum):
    """
    Normalized signal types emitted by detectors.

    These are consumed by the composite correlator to build attack chains.
    """
    REFLECTION = "reflection"  # Canary echoed in response
    ERROR_SIGNATURE = "error_signature"  # Stack traces, internal paths leaked
    AUTH_MISMATCH = "auth_mismatch"  # Unauth access to auth-required resource
    TIMING_ANOMALY = "timing_anomaly"  # Consistent timing differential
    CORS_PERMISSIVE = "cors_permissive"  # Wildcard CORS with credentials
    SCHEMA_OVERPERMISSIVE = "schema_overpermissive"  # Tool/resource grants excessive access
    EGRESS_MISSING = "egress_missing"  # No egress controls detected
    SENSITIVE_EXPOSURE = "sensitive_exposure"  # Credentials/keys in response


class Signal(BaseModel):
    """
    A normalized observation from a detector.

    Signals are emitted during detection and consumed by the correlator.
    """
    model_config = ConfigDict(use_enum_values=True)

    type: SignalType = Field(..., description="Signal type from enum")
    value: Union[bool, str, float, int] = Field(
        ..., description="Signal value (bool for binary, str for tokens, float for timing)"
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context (e.g., resource URI, canary token)"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When signal was captured (UTC)"
    )


class ProofOfConcept(BaseModel):
    """
    Proof of concept demonstrating successful exploitation.

    After passive detection identifies a potential vulnerability,
    the detector attempts a controlled exploit to prove it's exploitable.
    This captures the actual attack payload and response.
    """
    target: str = Field(..., description="Target resource/tool that was exploited")

    attack_type: str = Field(..., description="Type of attack (e.g., 'credential_exposure', 'prompt_injection', 'tool_abuse')")

    payload: Dict[str, Any] = Field(
        ...,
        description="The actual payload sent (e.g., injection string, tool call parameters)"
    )

    response: Dict[str, Any] = Field(
        ...,
        description="Server response showing successful exploitation"
    )

    success: bool = Field(..., description="Whether the exploit succeeded")

    impact_demonstrated: str = Field(
        ...,
        description="What the PoC demonstrates (e.g., 'Retrieved admin credentials', 'Executed system command')"
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When PoC was executed (UTC)"
    )


# ============================================================================
# Standards Mapping
# ============================================================================

class CVSSVector(BaseModel):
    """CVSS v3.1 scoring vector."""
    version: str = Field(default="3.1", description="CVSS version")
    vector: str = Field(..., description="CVSS vector string (e.g., AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)")
    base_score: float = Field(..., ge=0.0, le=10.0, description="CVSS base score (0-10)")
    severity: str = Field(..., description="CVSS severity label (NONE, LOW, MEDIUM, HIGH, CRITICAL)")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.upper()


class StandardsMapping(BaseModel):
    """
    Maps a finding to recognized security standards.

    Used for compliance reporting and remediation prioritization.
    """
    cwe: Optional[str] = Field(None, description="CWE ID (e.g., CWE-74)")
    owasp_llm: Optional[str] = Field(None, description="OWASP LLM Top 10 (e.g., LLM01)")
    owasp_api: Optional[str] = Field(None, description="OWASP API Top 10 (e.g., API2:2023)")
    asvs: List[str] = Field(default_factory=list, description="ASVS requirements (e.g., V5.1, V2.1)")
    capec: List[str] = Field(default_factory=list, description="CAPEC IDs (e.g., CAPEC-242)")
    cvss: Optional[CVSSVector] = Field(None, description="CVSS scoring vector")


# ============================================================================
# Detection Result
# ============================================================================

class DetectionResult(BaseModel):
    """
    Result from a single detector module.

    This is the primary contract between detectors and the orchestrator.
    """
    detector_id: str = Field(..., description="Unique detector ID (e.g., MCP-2024-001)")
    detector_name: str = Field(..., description="Human-readable detector name")
    detector_version: str = Field(..., description="Detector version (semver)")

    status: DetectionStatus = Field(..., description="Detection outcome")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0.0-1.0)")

    affected_resources: List[str] = Field(
        default_factory=list,
        description="Affected resource URIs or tool names"
    )

    signals: List[Signal] = Field(
        default_factory=list,
        description="Signals emitted during detection"
    )

    proof_of_concepts: List[ProofOfConcept] = Field(
        default_factory=list,
        description="Proof of concept exploits demonstrating the vulnerability"
    )

    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Minimal evidence (redacted by default; hashes for large payloads)"
    )

    standards: StandardsMapping = Field(
        default_factory=StandardsMapping,
        description="Standards mapping for this finding"
    )

    remediation: Optional[str] = Field(
        None,
        description="Actionable remediation guidance"
    )

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When detection completed (UTC)"
    )

    execution_time_ms: Optional[float] = Field(
        None,
        ge=0.0,
        description="Detector execution time in milliseconds"
    )


# ============================================================================
# Server Profile
# ============================================================================

class ServerCapabilities(BaseModel):
    """MCP server capabilities."""
    resources: bool = Field(default=False, description="Supports resources/list and resources/read")
    tools: bool = Field(default=False, description="Supports tools/list and tools/call")
    prompts: bool = Field(default=False, description="Supports prompts/list and prompts/get")
    logging: bool = Field(default=False, description="Supports logging/setLevel")
    sampling: bool = Field(default=False, description="Supports sampling/createMessage")


class ServerProfile(BaseModel):
    """
    Profile of the target MCP server.

    Captured during handshake and used for capability gating.
    """
    server_name: str = Field(..., description="MCP server name from initialize response")
    server_version: str = Field(..., description="Server version string")

    protocol_version: str = Field(..., description="MCP protocol version (e.g., 2024-11-05)")

    capabilities: ServerCapabilities = Field(
        default_factory=ServerCapabilities,
        description="Server capabilities"
    )

    transport: str = Field(..., description="Transport used (stdio, sse, ws)")

    endpoint: Optional[str] = Field(
        None,
        description="Endpoint URL for HTTP/SSE/WS transports"
    )

    auth_type: Optional[str] = Field(
        None,
        description="Authentication type detected (none, api_key, oauth, mtls)"
    )

    exposure: str = Field(
        default="unknown",
        description="Exposure level (local, internal, internet, unknown)"
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional server metadata"
    )

    profiled_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Profile timestamp (UTC)"
    )


# ============================================================================
# Threat Model & Attack Chains
# ============================================================================

class AttackChain(BaseModel):
    """
    A composite attack derived from multiple signals.

    Example: "Unauthorized Data Access" = auth_mismatch + info_disclosure
    """
    name: str = Field(..., description="Chain name (e.g., Unauthorized Data Access)")

    severity: str = Field(..., description="Chain severity (LOW, MEDIUM, HIGH, CRITICAL)")

    required_signals: List[SignalType] = Field(
        ...,
        description="Signal types that compose this chain"
    )

    detected_signals: List[Signal] = Field(
        ...,
        description="Actual signals detected"
    )

    affected_resources: List[str] = Field(
        default_factory=list,
        description="Resources involved in chain"
    )

    impact: str = Field(..., description="Business/security impact description")

    likelihood: str = Field(..., description="Exploitation likelihood (LOW, MEDIUM, HIGH)")

    uplift_score: float = Field(
        default=0.0,
        ge=0.0,
        le=2.0,
        description="Risk score uplift from chain correlation (0-2.0)"
    )

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.upper()


class RemediationAction(BaseModel):
    """A prioritized remediation action."""
    action: str = Field(..., description="Remediation action description")
    effort: str = Field(..., description="Implementation effort (LOW, MEDIUM, HIGH)")
    impact: str = Field(..., description="Risk reduction impact (LOW, MEDIUM, HIGH)")
    priority: int = Field(..., ge=1, description="Priority rank (1=highest)")

    @field_validator("effort", "impact")
    @classmethod
    def validate_level(cls, v: str) -> str:
        allowed = {"LOW", "MEDIUM", "HIGH"}
        if v.upper() not in allowed:
            raise ValueError(f"value must be one of {allowed}")
        return v.upper()


class ThreatModel(BaseModel):
    """
    Overall threat model and risk assessment.

    Combines individual findings and attack chains into prioritized recommendations.
    """
    overall_risk: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="Overall risk score (0-10, CVSS-style)"
    )

    risk_level: str = Field(..., description="Risk level label (LOW, MEDIUM, HIGH, CRITICAL)")

    chains: List[AttackChain] = Field(
        default_factory=list,
        description="Detected attack chains"
    )

    prioritized_mitigations: List[RemediationAction] = Field(
        default_factory=list,
        description="Remediation actions sorted by priority"
    )

    exposure_modifiers: Dict[str, Any] = Field(
        default_factory=dict,
        description="Risk modifiers (internet-exposed, unauth endpoints, data sensitivity)"
    )

    summary: str = Field(
        default="",
        description="Executive summary of threat landscape"
    )

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"risk_level must be one of {allowed}")
        return v.upper()


# ============================================================================
# Assessment Result (Complete Output)
# ============================================================================

class AssessmentResult(BaseModel):
    """
    Complete assessment output.

    This is the top-level object written to JSON reports.
    """
    assessment_id: str = Field(..., description="Unique assessment ID (UUID or hash)")

    started_at: datetime = Field(..., description="Assessment start time (UTC)")
    completed_at: datetime = Field(..., description="Assessment completion time (UTC)")

    scope: Dict[str, Any] = Field(..., description="Scope configuration used")

    profile: ServerProfile = Field(..., description="Target server profile")

    results: List[DetectionResult] = Field(
        default_factory=list,
        description="Individual detector results"
    )

    threat_model: Optional[ThreatModel] = Field(
        None,
        description="Threat model (if correlation enabled)"
    )

    summary: Dict[str, int] = Field(
        default_factory=dict,
        description="Result counts by status (present, absent, unknown, not_applicable)"
    )

    audit_log_path: Optional[str] = Field(
        None,
        description="Path to audit JSONL file"
    )

    framework_version: str = Field(
        default="0.2.0",
        description="MCP Security Framework version"
    )


# ============================================================================
# Module Metadata (for detector registry)
# ============================================================================

class ModuleMetadata(BaseModel):
    """
    Metadata for a detector module.

    Used by the registry and runner for capability gating and orchestration.
    """
    id: str = Field(..., description="Unique module ID (e.g., MCP-2024-PI-001)")
    name: str = Field(..., description="Module display name")
    version: str = Field(..., description="Module version (semver)")

    description: str = Field(..., description="Module description")

    prerequisites: Dict[str, bool] = Field(
        default_factory=dict,
        description="Required capabilities (e.g., {'resources': True})"
    )

    timeout_s: int = Field(default=30, ge=1, description="Module timeout in seconds")

    severity_default: str = Field(
        default="MEDIUM",
        description="Default severity if PRESENT (LOW, MEDIUM, HIGH, CRITICAL)"
    )

    standards: StandardsMapping = Field(
        default_factory=StandardsMapping,
        description="Standards mapping for this module"
    )

    @field_validator("severity_default")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"severity_default must be one of {allowed}")
        return v.upper()
