"""
Tests for detector base class and registry.

Validates that the detector contract is enforced and registry works correctly.
"""

import pytest

from src.core.models import ServerProfile, ServerCapabilities
from src.modules.base import Detector
from src.modules.registry import DetectorRegistry, get_registry
from src.modules.detectors.dummy_detector import DummyDetector


class TestDetectorBase:
    """Test Detector base class."""

    @pytest.mark.asyncio
    async def test_dummy_detector_instantiation(self):
        detector = DummyDetector()
        assert detector.metadata.id == "MCP-2024-DUMMY-001"
        assert detector.metadata.name == "Dummy Detector"
        assert detector.metadata.version == "1.0.0"

    def test_check_prerequisites(self):
        detector = DummyDetector()

        # Profile with resources capability
        profile_with_resources = ServerProfile(
            server_name="Test",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            transport="stdio",
            capabilities=ServerCapabilities(resources=True, tools=False),
        )
        assert detector.check_prerequisites(profile_with_resources) is True

        # Profile without resources capability
        profile_without_resources = ServerProfile(
            server_name="Test",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            transport="stdio",
            capabilities=ServerCapabilities(resources=False, tools=True),
        )
        assert detector.check_prerequisites(profile_without_resources) is False

    def test_create_not_applicable_result(self):
        detector = DummyDetector()
        result = detector._create_not_applicable_result("Test reason")

        assert result.detector_id == "MCP-2024-DUMMY-001"
        assert result.status.value == "NOT_APPLICABLE"
        assert result.confidence == 1.0
        assert "reason" in result.evidence

    def test_create_unknown_result(self):
        detector = DummyDetector()
        result = detector._create_unknown_result("Ambiguous response", confidence=0.5)

        assert result.status.value == "UNKNOWN"
        assert result.confidence == 0.5
        assert result.evidence["reason"] == "Ambiguous response"

    @pytest.mark.asyncio
    async def test_dummy_detector_run(self):
        detector = DummyDetector()

        profile = ServerProfile(
            server_name="Test",
            server_version="1.0.0",
            protocol_version="2024-11-05",
            transport="stdio",
            capabilities=ServerCapabilities(resources=True),
        )

        result = await detector.run(
            adapter=None,  # Dummy detector doesn't use adapter
            scope={},
            profile=profile,
        )

        assert result.status.value == "ABSENT"
        assert result.confidence == 1.0
        assert result.detector_id == "MCP-2024-DUMMY-001"


class TestDetectorRegistry:
    """Test DetectorRegistry."""

    def test_registry_load_detectors(self):
        registry = DetectorRegistry()
        registry.load_detectors()

        detector_ids = registry.list_detector_ids()
        assert "MCP-2024-DUMMY-001" in detector_ids

    def test_get_detector_by_id(self):
        registry = DetectorRegistry()
        registry.load_detectors()

        detector = registry.get_detector("MCP-2024-DUMMY-001")
        assert isinstance(detector, DummyDetector)
        assert detector.metadata.name == "Dummy Detector"

    def test_get_detector_not_found(self):
        registry = DetectorRegistry()
        registry.load_detectors()

        with pytest.raises(KeyError):
            registry.get_detector("NONEXISTENT-DETECTOR")

    def test_get_all_detectors(self):
        registry = DetectorRegistry()
        registry.load_detectors()

        detectors = registry.get_all_detectors()
        assert len(detectors) >= 1  # At least DummyDetector

        # All should be Detector instances
        for detector in detectors:
            assert isinstance(detector, Detector)

    def test_filter_detectors_by_capabilities(self):
        registry = DetectorRegistry()
        registry.load_detectors()

        # Filter by resources capability (DummyDetector requires it)
        compatible = registry.filter_detectors_by_capabilities({"resources": True})
        detector_ids = [d.metadata.id for d in compatible]
        assert "MCP-2024-DUMMY-001" in detector_ids

        # Filter without resources capability (should exclude DummyDetector)
        incompatible = registry.filter_detectors_by_capabilities({"resources": False})
        detector_ids = [d.metadata.id for d in incompatible]
        assert "MCP-2024-DUMMY-001" not in detector_ids

    def test_global_registry_singleton(self):
        registry1 = get_registry()
        registry2 = get_registry()
        assert registry1 is registry2  # Same instance
