#!/usr/bin/env python3
"""
Simple test script for the module loader
"""

import sys
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import directly to avoid circular import issues
from modules.base import BaseSecurityModule, TestResult, Finding, Severity
from modules.credential_exposure import CredentialExposureDetector
from adapters import McpClientAdapter


async def test_module_directly():
    """Test the credential exposure module directly"""
    
    print("="*70)
    print("  MCP Security Framework - Direct Module Test")
    print("="*70)
    
    # Create module instance
    print("\n[*] Creating Credential Exposure Detector...")
    detector = CredentialExposureDetector()
    
    print(f"[+] Module: {detector.name}")
    print(f"[+] Version: {detector.version}")
    print(f"[+] Author: {detector.author}")
    print(f"[+] Tags: {', '.join(detector.tags)}")
    print(f"[+] Description: {detector.description}")
    
    # Connect to DV-MCP Challenge 1
    print("\n[*] Connecting to DV-MCP Challenge 1...")
    adapter = McpClientAdapter(transport="sse", url="http://localhost:9001/sse")
    
    try:
        connection_info = await adapter.connect()
        print(f"[+] Connected to: {connection_info['server_info']['name']}")
        
        # Run the module
        print("\n[*] Running Credential Exposure Detector...")
        result = await detector.run(adapter)
        
        if result and result.success:
            print(f"[+] Module executed successfully!")
            print(f"[+] Found {len(result.findings)} security issues")
            
            if result.metadata:
                print(f"[+] Resources scanned: {result.metadata.get('resources_scanned', 'N/A')}")
                print(f"[+] Sensitive resources found: {result.metadata.get('sensitive_resources_found', 'N/A')}")
            
            for i, finding in enumerate(result.findings, 1):
                print(f"\nFinding #{i}: {finding.type} [{finding.severity.value}]")
                print(f"  Resource: {finding.resource}")
                print(f"  Description: {finding.description}")
                if finding.evidence:
                    print(f"  Evidence: {finding.evidence[:200]}...")
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
    asyncio.run(test_module_directly())
