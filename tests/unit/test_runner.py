"""
Unit tests for TestRunner.

Tests orchestration, detector execution, timeout handling, and result aggregation.
"""

import asyncio
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.runner import TestRunner, TestRunnerError, run_assessment
from src.core.policy import ScopeConfig, RateLimitConfig, PolicyConfig
from src.core.models import (
    DetectionResult,
    DetectionStatus,
    ModuleMetadata,
    ServerProfile,
    ServerCapabilities,
    StandardsMapping,
)
from src.modules.base import Detector
from src.modules.registry import DetectorRegistry


# Mock detectors for testing
class PassingDetector(Detector):
    """Detector that always returns ABSENT."""

    @property
    def metadata(self):
        return ModuleMetadata(
            id="TEST-001",
            name="Passing Test",
            version="1.0.0",
            description="Test detector",
            prerequisites={"resources": True},
            timeout_s=5,
        )

    async def run(self, adapter, scope, profile):
        await asyncio.sleep(0.01)  # Simulate work
        return DetectionResult(
            detector_id=self.metadata.id,
            detector_name=self.metadata.name,
            detector_version=self.metadata.version,
            status=DetectionStatus.ABSENT,
            confidence=1.0,
            standards=self.metadata.standards,
        )


class FailingDetector(Detector):
    """Detector that raises an exception."""

    @property
    def metadata(self):
        return ModuleMetadata(
            id="TEST-002",
            name="Failing Test",
            version="1.0.0",
            description="Test detector that fails",
            prerequisites={},
            timeout_s=5,
        )

    async def run(self, adapter, scope, profile):
        raise Exception("Detector crashed!")


class SlowDetector(Detector):
    """Detector that times out."""

    @property
    def metadata(self):
        return ModuleMetadata(
            id="TEST-003",
            name="Slow Test",
            version="1.0.0",
            description="Test detector that times out",
            prerequisites={},
            timeout_s=1,  # 1 second timeout
        )

    async def run(self, adapter, scope, profile):
        await asyncio.sleep(10)  # Sleep longer than timeout
        return DetectionResult(
            detector_id=self.metadata.id,
            detector_name=self.metadata.name,
            detector_version=self.metadata.version,
            status=DetectionStatus.ABSENT,
            confidence=1.0,
            standards=self.metadata.standards,
        )


class CapabilityGatedDetector(Detector):
    """Detector that requires tools capability."""

    @property
    def metadata(self):
        return ModuleMetadata(
            id="TEST-004",
            name="Capability Gated Test",
            version="1.0.0",
            description="Test detector requiring tools",
            prerequisites={"tools": True},  # Requires tools
            timeout_s=5,
        )

    async def run(self, adapter, scope, profile):
        return DetectionResult(
            detector_id=self.metadata.id,
            detector_name=self.metadata.name,
            detector_version=self.metadata.version,
            status=DetectionStatus.ABSENT,
            confidence=1.0,
            standards=self.metadata.standards,
        )


# Mock registry
class MockRegistry(DetectorRegistry):
    """Mock registry for testing."""

    def __init__(self):
        super().__init__()
        self._detectors = {
            "TEST-001": PassingDetector,
            "TEST-002": FailingDetector,
            "TEST-003": SlowDetector,
            "TEST-004": CapabilityGatedDetector,
        }
        self._loaded = True


# Mock SafeAdapter
class MockSafeAdapter:
    """Mock SafeAdapter for testing."""

    def __init__(self, profile: ServerProfile):
        self.profile = profile
        self.connected = False
        self.audit_log_path = Path("/tmp/audit.jsonl")

    async def connect(self):
        self.connected = True
        return self.profile

    def get_server_profile(self):
        return self.profile if self.connected else None

    def get_audit_log_path(self):
        return self.audit_log_path

    async def disconnect(self):
        self.connected = False


@pytest.fixture
def test_scope():
    """Create test scope."""
    return ScopeConfig(
        target="http://localhost:9001/sse",
        allowed_prefixes=["/resources"],
        rate_limit=RateLimitConfig(qps=10, burst=5),
        policy=PolicyConfig(dry_run=False, max_total_requests=100),
    )


@pytest.fixture
def test_profile():
    """Create test server profile."""
    return ServerProfile(
        server_name="Test Server",
        server_version="1.0.0",
        protocol_version="2024-11-05",
        transport="sse",
        capabilities=ServerCapabilities(
            resources=True,
            tools=False,  # No tools capability
            prompts=False,
        ),
    )


@pytest.fixture
def mock_adapter(test_profile):
    """Create mock adapter."""
    return MockSafeAdapter(test_profile)


@pytest.fixture
def mock_registry():
    """Create mock registry."""
    return MockRegistry()


class TestTestRunnerBasics:
    """Test basic TestRunner functionality."""

    async def test_runner_initialization(self, test_scope, mock_registry):
        runner = TestRunner(test_scope, registry=mock_registry)

        assert runner.scope == test_scope
        assert runner.registry == mock_registry
        assert runner.adapter is None
        assert runner.server_profile is None
        assert len(runner.results) == 0

    async def test_assess_with_adapter(self, test_scope, mock_adapter, mock_registry):
        runner = TestRunner(test_scope, registry=mock_registry)

        # Run assessment with provided adapter
        result = await runner.assess(adapter=mock_adapter, detector_ids=["TEST-001"])

        assert result.assessment_id is not None
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.profile.server_name == "Test Server"
        assert len(result.results) == 1
        assert result.results[0].detector_id == "TEST-001"
        assert result.results[0].status == DetectionStatus.ABSENT


class TestDetectorLoading:
    """Test detector loading and filtering."""

    async def test_load_all_detectors(self, test_scope, mock_adapter, mock_registry):
        runner = TestRunner(test_scope, registry=mock_registry)
        runner.server_profile = mock_adapter.profile

        detectors = runner._load_detectors()

        # Should load all detectors, but filter by capabilities
        # Only TEST-001 (PassingDetector) requires resources (available)
        # TEST-004 requires tools (not available), so it's filtered out
        detector_ids = [d.metadata.id for d in detectors]

        # TEST-001 requires resources: True (available)
        # TEST-002, TEST-003 have no prerequisites (should pass)
        # TEST-004 requires tools: True (not available, filtered out)
        assert "TEST-001" in detector_ids
        assert "TEST-002" in detector_ids
        assert "TEST-003" in detector_ids
        assert "TEST-004" not in detector_ids  # Filtered by capability

    async def test_load_specific_detectors(
        self, test_scope, mock_adapter, mock_registry
    ):
        runner = TestRunner(test_scope, registry=mock_registry)
        runner.server_profile = mock_adapter.profile

        detectors = runner._load_detectors(detector_ids=["TEST-001"])

        assert len(detectors) == 1
        assert detectors[0].metadata.id == "TEST-001"

    async def test_scope_include_filter(self, test_scope, mock_adapter, mock_registry):
        # Add include filter to scope
        test_scope.detectors = {"include": ["TEST-001", "TEST-002"]}

        runner = TestRunner(test_scope, registry=mock_registry)
        runner.server_profile = mock_adapter.profile

        detectors = runner._load_detectors()

        detector_ids = [d.metadata.id for d in detectors]
        assert "TEST-001" in detector_ids
        assert "TEST-002" in detector_ids
        assert "TEST-003" not in detector_ids  # Not in include list

    async def test_scope_exclude_filter(self, test_scope, mock_adapter, mock_registry):
        # Add exclude filter to scope
        test_scope.detectors = {"exclude": ["TEST-003"]}

        runner = TestRunner(test_scope, registry=mock_registry)
        runner.server_profile = mock_adapter.profile

        detectors = runner._load_detectors()

        detector_ids = [d.metadata.id for d in detectors]
        assert "TEST-001" in detector_ids
        assert "TEST-002" in detector_ids
        assert "TEST-003" not in detector_ids  # Excluded


class TestDetectorExecution:
    """Test detector execution and error handling."""

    async def test_successful_detector_execution(
        self, test_scope, mock_adapter, mock_registry
    ):
        runner = TestRunner(test_scope, registry=mock_registry)

        result = await runner.assess(adapter=mock_adapter, detector_ids=["TEST-001"])

        assert len(result.results) == 1
        assert result.results[0].detector_id == "TEST-001"
        assert result.results[0].status == DetectionStatus.ABSENT

    async def test_failing_detector_returns_unknown(
        self, test_scope, mock_adapter, mock_registry
    ):
        runner = TestRunner(test_scope, registry=mock_registry)

        result = await runner.assess(adapter=mock_adapter, detector_ids=["TEST-002"])

        assert len(result.results) == 1
        assert result.results[0].detector_id == "TEST-002"
        assert result.results[0].status == DetectionStatus.UNKNOWN
        assert "exception" in result.results[0].evidence["reason"].lower()

    async def test_timeout_detector_returns_unknown(
        self, test_scope, mock_adapter, mock_registry
    ):
        runner = TestRunner(test_scope, registry=mock_registry)

        result = await runner.assess(adapter=mock_adapter, detector_ids=["TEST-003"])

        assert len(result.results) == 1
        assert result.results[0].detector_id == "TEST-003"
        assert result.results[0].status == DetectionStatus.UNKNOWN
        assert "timed out" in result.results[0].evidence["reason"].lower()


class TestAssessmentResult:
    """Test assessment result generation."""

    async def test_assessment_result_structure(
        self, test_scope, mock_adapter, mock_registry
    ):
        runner = TestRunner(test_scope, registry=mock_registry)

        result = await runner.assess(
            adapter=mock_adapter, detector_ids=["TEST-001", "TEST-002"]
        )

        # Check structure
        assert result.assessment_id is not None
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.started_at <= result.completed_at

        assert result.profile.server_name == "Test Server"
        assert result.scope["target"] == "http://localhost:9001/sse"

        assert len(result.results) == 2
        assert result.audit_log_path is not None
        assert result.framework_version == "0.2.0"

    async def test_summary_counts(self, test_scope, mock_adapter, mock_registry):
        runner = TestRunner(test_scope, registry=mock_registry)

        result = await runner.assess(
            adapter=mock_adapter,
            detector_ids=["TEST-001", "TEST-002", "TEST-003"],  # 1 pass, 2 unknown
        )

        assert result.summary["absent"] == 1  # TEST-001
        assert result.summary["unknown"] == 2  # TEST-002, TEST-003
        assert result.summary["present"] == 0
        assert result.summary["not_applicable"] == 0


class TestCleanup:
    """Test cleanup and resource management."""

    async def test_cleanup_disconnects_adapter(
        self, test_scope, mock_adapter, mock_registry
    ):
        runner = TestRunner(test_scope, registry=mock_registry)

        await runner.assess(adapter=mock_adapter, detector_ids=["TEST-001"])

        assert mock_adapter.connected is True

        await runner.cleanup()

        assert mock_adapter.connected is False


class TestHelperFunctions:
    """Test helper functions."""

    async def test_run_assessment_helper(self, tmp_path, mock_registry):
        # Create scope.yaml
        scope_yaml = tmp_path / "scope.yaml"
        scope_yaml.write_text("""
target: "http://localhost:9001/sse"
allowed_prefixes:
  - "/resources"
""")

        # Mock the adapter creation
        test_profile = ServerProfile(
            server_name="Test",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            transport="sse",
            capabilities=ServerCapabilities(resources=True),
        )
        mock_adapter = MockSafeAdapter(test_profile)

        with patch("src.core.runner.TestRunner._create_adapter", return_value=mock_adapter):
            with patch("src.core.runner.get_registry", return_value=mock_registry):
                result = await run_assessment(
                    str(scope_yaml), detector_ids=["TEST-001"]
                )

                assert result.profile.server_name == "Test"
                assert len(result.results) >= 1
