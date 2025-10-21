#!/usr/bin/env python3
"""
Example script demonstrating the MCP Security Framework module loader
"""

import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from adapters import McpClientAdapter
from core.test_runner import TestRunner
from core.module_loader import ModuleLoader


async def main():
    """Demonstrate the module loader functionality"""
    
    print("="*70)
    print("  MCP Security Framework - Module Loader Demo")
    print("="*70)
    
    # Initialize test runner
    runner = TestRunner()
    
    # Load all available modules
    print("\n[*] Loading security modules...")
    loaded_modules = runner.load_modules()
    
    if not loaded_modules:
        print("[-] No modules found! Make sure modules are in src/modules/")
        return
    
    print(f"[+] Loaded {len(loaded_modules)} modules:")
    for module in loaded_modules:
        print(f"    - {module['name']} v{module['version']}")
        print(f"      Tags: {', '.join(module['tags'])}")
        print(f"      Description: {module['description']}")
        print()
    
    # Connect to DV-MCP Challenge 1
    print("[*] Connecting to DV-MCP Challenge 1...")
    adapter = McpClientAdapter(transport="sse", url="http://localhost:9001/sse")
    
    try:
        connection_info = await adapter.connect()
        print(f"[+] Connected to: {connection_info['server_info']['name']}")
        
        # Run credential exposure detector
        print("\n[*] Running Credential Exposure Detector...")
        result = await runner.run_single_module("credential_exposure", adapter)
        
        if result and result.success:
            print(f"[+] Module executed successfully in {result.execution_time:.2f}s")
            print(f"[+] Found {len(result.findings)} security issues")
            
            for i, finding in enumerate(result.findings, 1):
                print(f"\nFinding #{i}: {finding.type} [{finding.severity.value}]")
                print(f"  Resource: {finding.resource}")
                print(f"  Description: {finding.description}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:200]}...")
        else:
            print("[-] Module execution failed")
            if result and result.error_message:
                print(f"    Error: {result.error_message}")
        
        # Generate report
        print("\n[*] Generating security report...")
        report = runner.generate_report(
            {"credential_exposure": result} if result else {},
            "http://localhost:9001/sse",
            "reports/module_loader_demo.json"
        )
        
        print(f"[+] Report saved to: reports/module_loader_demo.json")
        print(f"[+] Risk Rating: {report['summary']['risk_rating']}")
        
        # Print summary
        runner.print_summary({"credential_exposure": result} if result else {})
        
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        print("    Make sure DV-MCP Challenge 1 is running on port 9001")
    
    finally:
        await adapter.disconnect()
        print("\n[*] Connection closed")


if __name__ == "__main__":
    asyncio.run(main())
