"""
Dummy detector for testing registry and runner.

This detector always returns ABSENT and is used for integration testing.
"""

from typing import Any, Dict

from src.core.models import (
    DetectionResult,
    DetectionStatus,
    ModuleMetadata,
    ServerProfile,
    StandardsMapping,
)
from src.modules.base import Detector


class DummyDetector(Detector):
    """
    Test detector that always returns ABSENT.

    Used for testing registry loading and runner orchestration.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-DUMMY-001",
            name="Dummy Detector",
            version="1.0.0",
            description="Test detector for registry validation",
            prerequisites={"resources": True},
            timeout_s=5,
            severity_default="LOW",
            standards=StandardsMapping(cwe="CWE-0", owasp_llm="LLM00"),
        )

    async def run(
        self, adapter: Any, scope: Dict[str, Any], profile: ServerProfile
    ) -> DetectionResult:
        """Always returns ABSENT."""

        # Check prerequisites (should be done by runner, but defensive)
        if not self.check_prerequisites(profile):
            return self._create_not_applicable_result("resources capability required")

        # Simulate a successful test that finds nothing
        return DetectionResult(
            detector_id=self.metadata.id,
            detector_name=self.metadata.name,
            detector_version=self.metadata.version,
            status=DetectionStatus.ABSENT,
            confidence=1.0,
            evidence={"test": "passed", "probes_sent": 0},
            standards=self.metadata.standards,
            remediation="No issues found",
            execution_time_ms=0.0,
        )
