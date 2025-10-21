"""
Module loader for dynamically loading and managing security test modules
"""

import os
import importlib
import inspect
from typing import Dict, List, Type, Optional, Any
from pathlib import Path

from src.modules.base import BaseSecurityModule, TestResult


class ModuleLoader:
    """Loads and manages security test modules"""
    
    def __init__(self, modules_directory: Optional[str] = None):
        """
        Initialize the module loader
        
        Args:
            modules_directory: Path to modules directory (defaults to src/modules/)
        """
        if modules_directory is None:
            # Default to src/modules/ relative to this file
            current_dir = Path(__file__).parent
            modules_directory = str(current_dir)
        
        self.modules_directory = Path(modules_directory)
        self.loaded_modules: Dict[str, Type[BaseSecurityModule]] = {}
        self.module_instances: Dict[str, BaseSecurityModule] = {}
    
    def discover_modules(self) -> List[str]:
        """
        Discover all available modules in the modules directory
        
        Returns:
            List of module names (Python file names without .py)
        """
        modules = []
        
        if not self.modules_directory.exists():
            return modules
        
        for file_path in self.modules_directory.iterdir():
            if (file_path.is_file() and 
                file_path.suffix == '.py' and 
                not file_path.name.startswith('_') and
                file_path.name != 'base.py'):
                modules.append(file_path.stem)
        
        return modules
    
    def load_module(self, module_name: str) -> Optional[Type[BaseSecurityModule]]:
        """
        Load a specific module by name
        
        Args:
            module_name: Name of the module to load
            
        Returns:
            Module class if successful, None if failed
        """
        try:
            # Import the module
            module_path = f"src.modules.{module_name}"
            module = importlib.import_module(module_path)
            
            # Find classes that inherit from BaseSecurityModule
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, BaseSecurityModule) and 
                    obj != BaseSecurityModule):
                    self.loaded_modules[module_name] = obj
                    return obj
            
            print(f"Warning: No valid security module found in {module_name}")
            return None
            
        except Exception as e:
            print(f"Error loading module {module_name}: {e}")
            return None
    
    def load_all_modules(self) -> Dict[str, Type[BaseSecurityModule]]:
        """
        Load all available modules
        
        Returns:
            Dictionary mapping module names to module classes
        """
        module_names = self.discover_modules()
        
        for module_name in module_names:
            self.load_module(module_name)
        
        return self.loaded_modules
    
    def get_module_instance(self, module_name: str) -> Optional[BaseSecurityModule]:
        """
        Get an instance of a loaded module
        
        Args:
            module_name: Name of the module
            
        Returns:
            Module instance if successful, None if failed
        """
        if module_name not in self.loaded_modules:
            if not self.load_module(module_name):
                return None
        
        if module_name not in self.module_instances:
            try:
                module_class = self.loaded_modules[module_name]
                self.module_instances[module_name] = module_class()
            except Exception as e:
                print(f"Error creating instance of {module_name}: {e}")
                return None
        
        return self.module_instances[module_name]
    
    def get_modules_by_tag(self, tag: str) -> List[str]:
        """
        Get modules that have a specific tag
        
        Args:
            tag: Tag to search for
            
        Returns:
            List of module names with the specified tag
        """
        matching_modules = []
        
        for module_name in self.loaded_modules:
            instance = self.get_module_instance(module_name)
            if instance and tag in instance.tags:
                matching_modules.append(module_name)
        
        return matching_modules
    
    def get_module_info(self, module_name: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a specific module
        
        Args:
            module_name: Name of the module
            
        Returns:
            Module metadata if successful, None if failed
        """
        instance = self.get_module_instance(module_name)
        if instance:
            return instance.get_metadata()
        return None
    
    def list_loaded_modules(self) -> List[Dict[str, Any]]:
        """
        Get information about all loaded modules
        
        Returns:
            List of module metadata dictionaries
        """
        modules_info = []
        
        for module_name in self.loaded_modules:
            info = self.get_module_info(module_name)
            if info:
                modules_info.append(info)
        
        return modules_info
    
    async def run_module(self, module_name: str, adapter) -> Optional[TestResult]:
        """
        Run a specific module against an MCP server
        
        Args:
            module_name: Name of the module to run
            adapter: McpClientAdapter instance
            
        Returns:
            TestResult if successful, None if failed
        """
        instance = self.get_module_instance(module_name)
        if not instance:
            return None
        
        try:
            return await instance.run(adapter)
        except Exception as e:
            print(f"Error running module {module_name}: {e}")
            return TestResult(
                findings=[],
                success=False,
                error_message=str(e)
            )
    
    def reload_module(self, module_name: str) -> bool:
        """
        Reload a specific module
        
        Args:
            module_name: Name of the module to reload
            
        Returns:
            True if successful, False if failed
        """
        try:
            # Remove from loaded modules
            if module_name in self.loaded_modules:
                del self.loaded_modules[module_name]
            if module_name in self.module_instances:
                del self.module_instances[module_name]
            
            # Reload
            return self.load_module(module_name) is not None
            
        except Exception as e:
            print(f"Error reloading module {module_name}: {e}")
            return False
