#!/usr/bin/env python3
"""
Comprehensive module loader test - runs all available modules
"""

import sys
import asyncio
import importlib
import inspect
import argparse
from pathlib import Path
from datetime import datetime
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from modules.base import BaseSecurityModule, TestResult, Finding, Severity
from adapters import McpClientAdapter


class ComprehensiveModuleLoader:
    """Comprehensive module loader for testing all modules"""
    
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
    
    async def run_all_modules(self, adapter):
        """Run all loaded modules"""
        results = {}
        
        for module_name in self.loaded_modules:
            print(f"\n[*] Running {module_name}...")
            try:
                module_class = self.loaded_modules[module_name]
                instance = module_class()
                result = await instance.run(adapter)
                results[module_name] = result
                
                if result and result.success:
                    print(f"[+] {instance.name}: {len(result.findings)} findings")
                else:
                    print(f"[-] {module_name}: Failed")
                    if result and result.error_message:
                        print(f"    Error: {result.error_message}")
                        
            except Exception as e:
                print(f"[-] {module_name}: Exception - {e}")
                results[module_name] = TestResult(
                    findings=[],
                    success=False,
                    error_message=str(e)
                )
        
        return results
    
    def generate_comprehensive_report(self, results, target_url):
        """Generate a comprehensive security report"""
        # Aggregate all findings
        all_findings = []
        total_modules = len(results)
        successful_modules = sum(1 for r in results.values() if r.success)
        
        for module_name, result in results.items():
            if result.findings:
                for finding in result.findings:
                    finding.metadata = finding.metadata or {}
                    finding.metadata['module'] = module_name
                    all_findings.append(finding)
        
        # Calculate severity counts
        severity_counts = {}
        for finding in all_findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Determine overall risk rating
        risk_rating = "LOW"
        if severity_counts.get("CRITICAL", 0) > 0:
            risk_rating = "CRITICAL"
        elif severity_counts.get("HIGH", 0) > 0:
            risk_rating = "HIGH"
        elif severity_counts.get("MEDIUM", 0) > 0:
            risk_rating = "MEDIUM"
        
        # Create comprehensive report
        report = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'test_type': 'Comprehensive Security Scan',
            'framework_version': '0.2.0',
            'summary': {
                'total_modules': total_modules,
                'successful_modules': successful_modules,
                'failed_modules': total_modules - successful_modules,
                'total_findings': len(all_findings),
                'risk_rating': risk_rating,
                'severity_breakdown': severity_counts
            },
            'findings': [
                {
                    'type': f.type,
                    'severity': f.severity.value,
                    'resource': f.resource,
                    'description': f.description,
                    'evidence': f.evidence,
                    'attack_vector': f.attack_vector,
                    'attack_chain': f.attack_chain,
                    'impact': f.impact,
                    'remediation': f.remediation,
                    'metadata': f.metadata
                }
                for f in all_findings
            ],
            'module_results': {
                module_name: {
                    'success': result.success,
                    'findings_count': len(result.findings),
                    'error_message': result.error_message,
                    'metadata': result.metadata
                }
                for module_name, result in results.items()
            }
        }
        
        return report


async def comprehensive_test(target_url, transport="sse", stdio_command=None, stdio_args=None, output_file=None):
    """Run comprehensive security test with all modules"""
    
    print("="*70)
    print("  MCP Security Framework - Comprehensive Security Scan")
    print("="*70)
    
    # Initialize module loader
    loader = ComprehensiveModuleLoader()
    
    # Discover and load modules
    print("\n[*] Discovering and loading security modules...")
    loaded_modules = loader.load_all_modules()
    print(f"[+] Loaded {len(loaded_modules)} security modules")
    
    for module_name, module_class in loaded_modules.items():
        instance = module_class()
        print(f"    - {instance.name} v{instance.version}")
        print(f"      Tags: {', '.join(instance.tags)}")
    
    # Connect to target MCP server
    print(f"\n[*] Connecting to target MCP server...")
    print(f"    Transport: {transport}")
    print(f"    Target: {target_url}")
    
    if transport == "stdio":
        if not stdio_command:
            raise ValueError("stdio_command is required for stdio transport")
        adapter = McpClientAdapter(
            transport="stdio",
            command=stdio_command,
            args=stdio_args or []
        )
    else:
        adapter = McpClientAdapter(transport="sse", url=target_url)
    
    try:
        connection_info = await adapter.connect()
        print(f"[+] Connected to: {connection_info['server_info']['name']}")
        print(f"[+] Server capabilities: {', '.join([k for k, v in connection_info['capabilities'].items() if v])}")
        
        # Run all modules
        print(f"\n[*] Running comprehensive security scan...")
        results = await loader.run_all_modules(adapter)
        
        # Generate comprehensive report
        print(f"\n[*] Generating comprehensive security report...")
        report = loader.generate_comprehensive_report(results, target_url)
        
        # Save report
        if output_file:
            report_file = output_file
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"reports/comprehensive_scan_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print(f"\n" + "="*70)
        print("  SECURITY SCAN SUMMARY")
        print("="*70)
        print(f"Target: {report['target']}")
        print(f"Modules Executed: {report['summary']['total_modules']}")
        print(f"Successful: {report['summary']['successful_modules']}")
        print(f"Failed: {report['summary']['failed_modules']}")
        print(f"Total Findings: {report['summary']['total_findings']}")
        print(f"Risk Rating: {report['summary']['risk_rating']}")
        
        if report['summary']['severity_breakdown']:
            print(f"\nFindings by Severity:")
            for severity, count in sorted(report['summary']['severity_breakdown'].items(), 
                                        key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x[0])):
                print(f"  {severity}: {count}")
        
        print(f"\n[+] Comprehensive report saved to: {report_file}")
        
        # Show critical findings
        critical_findings = [f for f in report['findings'] if f['severity'] == 'CRITICAL']
        if critical_findings:
            print(f"\n" + "!"*70)
            print("  CRITICAL FINDINGS REQUIRING IMMEDIATE ATTENTION")
            print("!"*70)
            for i, finding in enumerate(critical_findings, 1):
                print(f"\nCritical Finding #{i}: {finding['type']}")
                print(f"  Resource: {finding['resource']}")
                print(f"  Description: {finding['description']}")
                if finding['impact']:
                    print(f"  Impact: {finding['impact']}")
        
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        print(f"    Make sure the MCP server is running and accessible at: {target_url}")
    
    finally:
        await adapter.disconnect()
        print("\n[*] Connection closed")


def main():
    """Main entry point with command line argument parsing"""
    parser = argparse.ArgumentParser(
        description="MCP Security Framework - Comprehensive Security Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan DV-MCP Challenge 1 (SSE)
  python comprehensive_security_scan.py --url http://localhost:9001/sse

  # Scan a custom MCP server (SSE)
  python comprehensive_security_scan.py --url http://your-server.com:8080/sse

  # Scan using stdio transport
  python comprehensive_security_scan.py --transport stdio --command python --args -m mcp_server_time

  # Scan with custom report name
  python comprehensive_security_scan.py --url http://localhost:9001/sse --output my_scan_report.json
        """
    )
    
    # Transport selection
    transport_group = parser.add_mutually_exclusive_group(required=True)
    transport_group.add_argument(
        "--url", 
        help="MCP server URL (for SSE transport)"
    )
    transport_group.add_argument(
        "--transport", 
        choices=["stdio"], 
        help="Use stdio transport"
    )
    
    # STDIO-specific arguments
    parser.add_argument(
        "--command",
        required=False,
        help="Command to run for stdio transport (e.g., 'python', 'node')"
    )
    parser.add_argument(
        "--args",
        nargs="*",
        help="Arguments for stdio command (e.g., '-m mcp_server_time')"
    )
    
    # Output options
    parser.add_argument(
        "--output",
        help="Custom output filename for the report"
    )
    
    args, unknown_args = parser.parse_known_args()
    
    # If we have unknown args and using stdio transport, they might be command args
    if args.transport == "stdio" and unknown_args:
        if not args.args:
            args.args = unknown_args
        else:
            args.args.extend(unknown_args)
    
    # Determine transport and target
    if args.url:
        transport = "sse"
        target_url = args.url
        stdio_command = None
        stdio_args = None
    else:
        transport = "stdio"
        if not args.command:
            parser.error("--command is required when using --transport stdio")
        target_url = f"stdio://{args.command} {' '.join(args.args or [])}"
        stdio_command = args.command
        stdio_args = args.args
    
    # Run the comprehensive test
    asyncio.run(comprehensive_test(
        target_url=target_url,
        transport=transport,
        stdio_command=stdio_command,
        stdio_args=stdio_args,
        output_file=args.output
    ))


if __name__ == "__main__":
    main()
