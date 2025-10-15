"""
Base detector class for all security modules.

All detector modules must inherit from Detector and implement the abstract methods.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict
from datetime import datetime, timezone

from src.core.models import (
    DetectionResult,
    DetectionStatus,
    ModuleMetadata,
    ServerProfile,
)


class Detector(ABC):
    """
    Abstract base class for all detectors.

    Detectors are self-contained security test modules that:
    1. Declare their ID, name, version, and prerequisites
    2. Run non-destructive probes via a safe adapter
    3. Emit normalized signals
    4. Return a DetectionResult with standards mapping

    Example:
        class MyDetector(Detector):
            @property
            def metadata(self) -> ModuleMetadata:
                return ModuleMetadata(
                    id="MCP-2024-001",
                    name="My Detector",
                    version="1.0.0",
                    description="Detects something",
                    prerequisites={"resources": True}
                )

            async def run(self, adapter, scope, profile) -> DetectionResult:
                # Run probes
                return DetectionResult(...)
    """

    @property
    @abstractmethod
    def metadata(self) -> ModuleMetadata:
        """
        Return module metadata.

        This property is called by the registry and runner for:
        - Capability gating (prerequisites check)
        - Timeout enforcement
        - Report generation (ID, name, standards)
        """
        pass

    @abstractmethod
    async def run(
        self,
        adapter: Any,  # Will be SafeAdapter once implemented
        scope: Dict[str, Any],  # Parsed scope.yaml
        profile: ServerProfile,
    ) -> DetectionResult:
        """
        Execute the detector.

        Args:
            adapter: Safe adapter wrapper (enforces QPS, redaction, scope)
            scope: Scope configuration (target, allowed_prefixes, policy, etc.)
            profile: Target server profile (capabilities, version, transport)

        Returns:
            DetectionResult with status, signals, evidence, and standards

        Raises:
            asyncio.TimeoutError: If execution exceeds metadata.timeout_s
            Exception: On unexpected errors (caught by runner, returns UNKNOWN)

        Implementation guidelines:
        - Check prerequisites before running (though runner should gate)
        - Use benign canaries only (e.g., "MCP_CANARY_123")
        - Emit signals for correlator consumption
        - Redact evidence by default (adapter handles this)
        - Return UNKNOWN on ambiguous results, not PRESENT
        - Set confidence score honestly (0.0-1.0)
        """
        pass

    def check_prerequisites(self, profile: ServerProfile) -> bool:
        """
        Check if target meets prerequisites.

        Returns:
            True if detector can run, False otherwise

        Called by runner before executing detector.
        """
        prereqs = self.metadata.prerequisites
        caps = profile.capabilities

        # Check each prerequisite
        if prereqs.get("resources") and not caps.resources:
            return False
        if prereqs.get("tools") and not caps.tools:
            return False
        if prereqs.get("prompts") and not caps.prompts:
            return False

        return True

    def _create_not_applicable_result(self, reason: str = "") -> DetectionResult:
        """
        Helper to create NOT_APPLICABLE result.

        Used when prerequisites are not met.
        """
        meta = self.metadata
        return DetectionResult(
            detector_id=meta.id,
            detector_name=meta.name,
            detector_version=meta.version,
            status=DetectionStatus.NOT_APPLICABLE,
            confidence=1.0,
            evidence={"reason": reason or "Prerequisites not met"},
            standards=meta.standards,
        )

    def _create_unknown_result(
        self, reason: str, confidence: float = 0.3
    ) -> DetectionResult:
        """
        Helper to create UNKNOWN result.

        Used when test is inconclusive (timeouts, ambiguous responses).
        """
        meta = self.metadata
        return DetectionResult(
            detector_id=meta.id,
            detector_name=meta.name,
            detector_version=meta.version,
            status=DetectionStatus.UNKNOWN,
            confidence=confidence,
            evidence={"reason": reason},
            standards=meta.standards,
        )


class DetectorError(Exception):
    """Base exception for detector errors."""
    pass


class PrerequisiteError(DetectorError):
    """Raised when prerequisites are not met."""
    pass


class AdapterError(DetectorError):
    """Raised when adapter interaction fails."""
    pass
