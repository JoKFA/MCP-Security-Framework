"""
Test runner - orchestrates detector execution and assessment workflow.

Coordinates:
- SafeAdapter connection and profiling
- Detector loading and capability filtering
- Per-detector timeout enforcement
- Result aggregation
- Assessment result generation
"""

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.core.models import (
    AssessmentResult,
    DetectionResult,
    DetectionStatus,
    ServerProfile,
)
from src.core.safe_adapter import SafeAdapter, create_safe_adapter_from_scope
from src.core.policy import ScopeConfig, load_scope_config
from src.modules.registry import DetectorRegistry, get_registry
from src.modules.base import Detector


class TestRunnerError(Exception):
    """Base exception for test runner errors."""
    pass


class TestRunner:
    """
    Orchestrates security assessment workflow.

    Responsibilities:
    - Connect to target via SafeAdapter
    - Profile server capabilities
    - Load and filter detectors by capabilities
    - Execute detectors with timeout enforcement
    - Aggregate results into AssessmentResult
    """

    def __init__(
        self,
        scope: ScopeConfig,
        registry: Optional[DetectorRegistry] = None,
    ):
        """
        Initialize test runner.

        Args:
            scope: Scope configuration
            registry: Detector registry (uses global if None)
        """
        self.scope = scope
        self.registry = registry or get_registry()

        self.adapter: Optional[SafeAdapter] = None
        self.server_profile: Optional[ServerProfile] = None

        # Assessment state
        self.assessment_id = str(uuid.uuid4())
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.results: List[DetectionResult] = []

    async def assess(
        self,
        adapter: Optional[SafeAdapter] = None,
        detector_ids: Optional[List[str]] = None,
    ) -> AssessmentResult:
        """
        Run full security assessment.

        Args:
            adapter: SafeAdapter instance (creates one if None)
            detector_ids: Specific detector IDs to run (runs all compatible if None)

        Returns:
            AssessmentResult with all findings

        Raises:
            TestRunnerError: On assessment failure
        """
        self.started_at = datetime.now(timezone.utc)

        try:
            # Step 1: Connect and profile server
            if adapter is None:
                adapter = await self._create_adapter()

            self.adapter = adapter

            if not adapter.get_server_profile():
                self.server_profile = await adapter.connect()
            else:
                self.server_profile = adapter.get_server_profile()

            # Step 2: Load and filter detectors
            detectors = self._load_detectors(detector_ids)

            # Step 3: Execute detectors
            await self._execute_detectors(detectors)

            # Step 4: Generate assessment result
            self.completed_at = datetime.now(timezone.utc)
            return self._build_assessment_result()

        except Exception as e:
            self.completed_at = datetime.now(timezone.utc)
            raise TestRunnerError(f"Assessment failed: {e}") from e

    async def run(
        self,
        adapter: Optional[SafeAdapter] = None,
        detector_ids: Optional[List[str]] = None,
    ) -> AssessmentResult:
        """
        Backwards-compatible alias for assess().
        """
        return await self.assess(adapter=adapter, detector_ids=detector_ids)

    async def _create_adapter(self) -> SafeAdapter:
        """Create SafeAdapter from scope configuration."""
        # Parse target and create base adapter
        # Convert target to string (Pydantic AnyUrl type)
        target_str = str(self.scope.target)

        if target_str.startswith("http://") or target_str.startswith("https://"):
            from src.adapters.mcp_client_adapter import McpClientAdapter
            base_adapter = McpClientAdapter(transport="sse", url=target_str)
        elif target_str.startswith("stdio://"):
            from src.adapters.mcp_client_adapter import McpClientAdapter
            parts = target_str[8:].split("/")
            command = parts[0] if parts else "npx"
            args = parts[1:] if len(parts) > 1 else []
            base_adapter = McpClientAdapter(transport="stdio", command=command, args=args)
        else:
            raise ValueError(f"Unknown target format: {target_str}")

        # Create SafeAdapter with audit log in captures/
        captures_dir = Path("captures")
        captures_dir.mkdir(parents=True, exist_ok=True)
        audit_log = captures_dir / f"audit_{self.assessment_id}.jsonl"

        return SafeAdapter(base_adapter, self.scope, audit_log)

    def _load_detectors(self, detector_ids: Optional[List[str]] = None) -> List[Detector]:
        """
        Load detectors filtered by scope and capabilities.

        Args:
            detector_ids: Specific IDs to load (None = all compatible)

        Returns:
            List of detector instances
        """
        # Load registry
        self.registry.load_detectors()

        # Apply scope include/exclude filters
        if self.scope.detectors:
            include = self.scope.detectors.get("include", [])
            exclude = self.scope.detectors.get("exclude", [])

            if include:
                # Only include specified detectors
                available_ids = [d for d in self.registry.list_detector_ids() if d in include]
            else:
                # All detectors except excluded
                available_ids = [d for d in self.registry.list_detector_ids() if d not in exclude]
        else:
            # No scope filters - use all
            available_ids = self.registry.list_detector_ids()

        # Apply detector_ids filter if provided
        if detector_ids:
            available_ids = [d for d in available_ids if d in detector_ids]

        # Load detector instances
        detectors = [self.registry.get_detector(d_id) for d_id in available_ids]

        # Filter by capabilities
        if self.server_profile:
            capabilities = {
                "resources": self.server_profile.capabilities.resources,
                "tools": self.server_profile.capabilities.tools,
                "prompts": self.server_profile.capabilities.prompts,
            }
            compatible = []
            for detector in detectors:
                if detector.check_prerequisites(self.server_profile):
                    compatible.append(detector)

            return compatible

        return detectors

    async def _execute_detectors(self, detectors: List[Detector]) -> None:
        """
        Execute detectors with timeout enforcement.

        Args:
            detectors: List of detector instances

        Updates:
            self.results with DetectionResult from each detector
        """
        for detector in detectors:
            metadata = detector.metadata
            print(f"Running detector: {metadata.id} ({metadata.name})")

            try:
                # Execute with timeout
                result = await asyncio.wait_for(
                    detector.run(
                        adapter=self.adapter,
                        scope=self.scope.model_dump(),
                        profile=self.server_profile,
                    ),
                    timeout=metadata.timeout_s,
                )

                self.results.append(result)
                print(f"  Status: {result.status.value} (confidence: {result.confidence:.2f})")

            except asyncio.TimeoutError:
                # Detector timed out - return UNKNOWN
                print(f"  Timeout ({metadata.timeout_s}s)")
                result = detector._create_unknown_result(
                    f"Detector timed out after {metadata.timeout_s}s",
                    confidence=0.0,
                )
                self.results.append(result)

            except Exception as e:
                # Detector crashed - return UNKNOWN
                print(f"  Error: {e}")
                result = detector._create_unknown_result(
                    f"Detector raised exception: {str(e)}",
                    confidence=0.0,
                )
                self.results.append(result)

    def _build_assessment_result(self) -> AssessmentResult:
        """
        Build final AssessmentResult from collected data.

        Returns:
            AssessmentResult with all findings and summary
        """
        # Count results by status
        summary = {
            "present": sum(1 for r in self.results if r.status == DetectionStatus.PRESENT),
            "absent": sum(1 for r in self.results if r.status == DetectionStatus.ABSENT),
            "unknown": sum(1 for r in self.results if r.status == DetectionStatus.UNKNOWN),
            "not_applicable": sum(
                1 for r in self.results if r.status == DetectionStatus.NOT_APPLICABLE
            ),
        }

        # Get audit log path
        audit_log_path = None
        if self.adapter:
            audit_log_path = str(self.adapter.get_audit_log_path())

        return AssessmentResult(
            assessment_id=self.assessment_id,
            started_at=self.started_at,
            completed_at=self.completed_at,
            scope=self.scope.model_dump(),
            profile=self.server_profile,
            results=self.results,
            threat_model=None,  # TODO: Implement in Phase 2C
            summary=summary,
            audit_log_path=audit_log_path,
            framework_version="0.2.0",
        )

    async def cleanup(self) -> None:
        """Clean up resources (disconnect adapter)."""
        if self.adapter:
            await self.adapter.disconnect()


# Helper function for simple assessment workflow
async def run_assessment(
    scope_path: str,
    detector_ids: Optional[List[str]] = None,
) -> AssessmentResult:
    """
    Run assessment from scope file.

    Args:
        scope_path: Path to scope.yaml
        detector_ids: Specific detector IDs to run (None = all)

    Returns:
        AssessmentResult

    Usage:
        result = await run_assessment("samples/scope.yaml")
        print(f"Found {result.summary['present']} issues")
    """
    scope = load_scope_config(scope_path)
    runner = TestRunner(scope)

    try:
        return await runner.assess(detector_ids=detector_ids)
    finally:
        await runner.cleanup()
