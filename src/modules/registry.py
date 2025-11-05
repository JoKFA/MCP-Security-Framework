"""
Detector registry - loads and manages detector modules.

Automatically discovers detector modules in src/modules/detectors/
and provides them to the test runner.
"""

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Dict, List, Type

from src.modules.base import Detector


class DetectorRegistry:
    """
    Registry for detector modules.

    Discovers detector classes by scanning src/modules/detectors/*.py files.
    Only loads classes that:
    1. Inherit from Detector
    2. Are not abstract (implement all required methods)
    3. Are defined in the detectors/ directory (not imported from elsewhere)
    """

    def __init__(self):
        self._detectors: Dict[str, Type[Detector]] = {}
        self._loaded = False

    def load_detectors(self, detectors_path: str = None) -> None:
        """
        Load all detector modules from detectors directory.
        
        Each detector performs both passive analysis and active confirmation testing.

        Args:
            detectors_path: Path to detectors directory (default: src/modules/detectors)

        Raises:
            ImportError: If module import fails
            ValueError: If detector class is invalid
        """
        if self._loaded:
            return  # Already loaded

        # Load from unified detectors directory
        registry_dir = Path(__file__).parent
        detectors_dir = registry_dir / "detectors"
        
        if detectors_dir.exists():
            print("Loading detectors...")
            self._load_detector_directory("src.modules.detectors", detectors_dir)
        else:
            # Fallback to old structure for backward compatibility
            print("Warning: detectors/ directory not found. Checking for old structure...")
            passive_dir = registry_dir / "passive_detectors"
            active_dir = registry_dir / "active_detectors"
            
            if passive_dir.exists():
                print("Loading PASSIVE detectors (legacy)...")
                self._load_detector_directory("src.modules.passive_detectors", passive_dir)
            
            if active_dir.exists():
                print("Loading ACTIVE detectors (legacy)...")
                self._load_detector_directory("src.modules.active_detectors", active_dir)

        self._loaded = True

    def _load_detector_directory(self, package_name: str, detectors_dir: Path) -> None:
        """
        Load detectors from a specific directory.
        
        Args:
            package_name: Full module path (e.g., "src.modules.passive_detectors")
            detectors_dir: Directory path to scan
        """
        if not detectors_dir.exists():
            print(f"Warning: Detectors directory not found: {detectors_dir}")
            return

        try:
            package = importlib.import_module(package_name)
        except ImportError as e:
            print(f"Warning: Failed to import {package_name}: {e}")
            return

        # Iterate through all modules in the package
        for importer, module_name, is_pkg in pkgutil.iter_modules(
            package.__path__, prefix=f"{package_name}."
        ):
            if is_pkg:
                continue  # Skip sub-packages

            try:
                module = importlib.import_module(module_name)
            except Exception as e:
                print(f"Warning: Failed to import {module_name}: {e}")
                continue

            # Find all Detector subclasses in this module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Must be a subclass of Detector (but not Detector itself)
                if not issubclass(obj, Detector) or obj is Detector:
                    continue

                # Must not be abstract
                if inspect.isabstract(obj):
                    continue

                # Must be defined in this module (not imported from elsewhere)
                if obj.__module__ != module_name:
                    continue

                # Instantiate to get metadata
                try:
                    instance = obj()
                    detector_id = instance.metadata.id

                    if detector_id in self._detectors:
                        print(
                            f"Warning: Duplicate detector ID '{detector_id}' "
                            f"in {module_name}. Skipping."
                        )
                        continue

                    self._detectors[detector_id] = obj
                    print(f"  ✓ {detector_id} ({instance.metadata.name})")

                except Exception as e:
                    print(
                        f"Warning: Failed to instantiate {name} from {module_name}: {e}"
                    )
                    continue

    def get_detector(self, detector_id: str) -> Detector:
        """
        Get a detector instance by ID.

        Args:
            detector_id: Detector ID (e.g., "MCP-2024-001")

        Returns:
            New detector instance

        Raises:
            KeyError: If detector not found
        """
        if not self._loaded:
            self.load_detectors()

        if detector_id not in self._detectors:
            raise KeyError(f"Detector not found: {detector_id}")

        # Return new instance
        return self._detectors[detector_id]()

    def get_all_detectors(self) -> List[Detector]:
        """
        Get instances of all registered detectors.

        Returns:
            List of detector instances
        """
        if not self._loaded:
            self.load_detectors()

        return [cls() for cls in self._detectors.values()]

    def list_detector_ids(self) -> List[str]:
        """
        List all registered detector IDs.

        Returns:
            Sorted list of detector IDs
        """
        if not self._loaded:
            self.load_detectors()

        return sorted(self._detectors.keys())

    def filter_detectors_by_capabilities(
        self, capabilities: Dict[str, bool]
    ) -> List[Detector]:
        """
        Filter detectors by required capabilities.

        Args:
            capabilities: Dict of capabilities (e.g., {"resources": True, "tools": False})

        Returns:
            List of detector instances that can run with these capabilities
        """
        if not self._loaded:
            self.load_detectors()

        compatible = []
        for detector_cls in self._detectors.values():
            instance = detector_cls()
            prereqs = instance.metadata.prerequisites

            # Check if all prerequisites are met
            can_run = True
            for cap, required in prereqs.items():
                if required and not capabilities.get(cap, False):
                    can_run = False
                    break

            if can_run:
                compatible.append(instance)

        return compatible


# Global registry instance
_registry = DetectorRegistry()


def get_registry() -> DetectorRegistry:
    """Get the global detector registry instance."""
    return _registry
