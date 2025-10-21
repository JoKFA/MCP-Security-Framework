#!/usr/bin/env python3
"""
Simple module loader test
"""

import sys
import asyncio
import importlib
import inspect
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from modules.base import BaseSecurityModule, TestResult, Finding, Severity
from adapters import McpClientAdapter


class SimpleModuleLoader:
    """Simple module loader for testing"""
    
    def __init__(self):
        self.modules_directory = Path(__file__).parent.parent / "src" / "modules"
        self.loaded_modules = {}
    
    def discover_modules(self):
        """Discover available modules"""
        modules = []
        
        for file_path in self.modules_directory.iterdir():
            if (file_path.is_file() and 
                file_path.suffix == '.py' and 
                not file_path.name.startswith('_') and
                file_path.name != 'base.py'):
                modules.append(file_path.stem)
        
        return modules
    
    def load_module(self, module_name):
        """Load a specific module"""
        try:
            module_path = f"modules.{module_name}"
            module = importlib.import_module(module_path)
            
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, BaseSecurityModule) and 
                    obj != BaseSecurityModule):
                    self.loaded_modules[module_name] = obj
                    return obj
            
            return None
            
        except Exception as e:
            print(f"Error loading module {module_name}: {e}")
            return None
    
    def load_all_modules(self):
        """Load all available modules"""
        module_names = self.discover_modules()
        
        for module_name in module_names:
            self.load_module(module_name)
        
        return self.loaded_modules
    
    async def run_module(self, module_name, adapter):
        """Run a specific module"""
        if module_name not in self.loaded_modules:
            if not self.load_module(module_name):
                return None
        
        try:
            module_class = self.loaded_modules[module_name]
            instance = module_class()
            return await instance.run(adapter)
        except Exception as e:
            print(f"Error running module {module_name}: {e}")
            return TestResult(
                findings=[],
                success=False,
                error_message=str(e)
            )


async def test_module_loader():
    """Test the module loader functionality"""
    
    print("="*70)
    print("  MCP Security Framework - Module Loader Test")
    print("="*70)
    
    # Initialize module loader
    loader = SimpleModuleLoader()
    
    # Discover and load modules
    print("\n[*] Discovering modules...")
    module_names = loader.discover_modules()
    print(f"[+] Found {len(module_names)} modules: {module_names}")
    
    print("\n[*] Loading modules...")
    loaded_modules = loader.load_all_modules()
    print(f"[+] Loaded {len(loaded_modules)} modules")
    
    for module_name, module_class in loaded_modules.items():
        instance = module_class()
        print(f"    - {instance.name} v{instance.version}")
        print(f"      Tags: {', '.join(instance.tags)}")
        print(f"      Description: {instance.description}")
        print()
    
    # Connect to DV-MCP Challenge 1
    print("[*] Connecting to DV-MCP Challenge 1...")
    adapter = McpClientAdapter(transport="sse", url="http://localhost:9001/sse")
    
    try:
        connection_info = await adapter.connect()
        print(f"[+] Connected to: {connection_info['server_info']['name']}")
        
        # Run credential exposure module
        print("\n[*] Running Credential Exposure Detector via module loader...")
        result = await loader.run_module("credential_exposure", adapter)
        
        if result and result.success:
            print(f"[+] Module executed successfully!")
            print(f"[+] Found {len(result.findings)} security issues")
            
            for i, finding in enumerate(result.findings, 1):
                print(f"\nFinding #{i}: {finding.type} [{finding.severity.value}]")
                print(f"  Resource: {finding.resource}")
                print(f"  Description: {finding.description}")
                if finding.metadata and finding.metadata.get('secrets_found'):
                    secrets = finding.metadata['secrets_found']
                    print(f"  Secrets found:")
                    for secret_type, values in secrets.items():
                        if values:
                            print(f"    - {secret_type}: {len(values)} found")
        else:
            print("[-] Module execution failed")
            if result and result.error_message:
                print(f"    Error: {result.error_message}")
        
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        print("    Make sure DV-MCP Challenge 1 is running on port 9001")
    
    finally:
        await adapter.disconnect()
        print("\n[*] Connection closed")


if __name__ == "__main__":
    asyncio.run(test_module_loader())
