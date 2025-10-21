"""
Test Runner for orchestrating security tests against MCP servers
"""

import asyncio
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from src.adapters import McpClientAdapter
from src.core.module_loader import ModuleLoader
from src.modules.base import TestResult, Finding


class TestRunner:
    """Orchestrates security testing against MCP servers"""
    
    def __init__(self, modules_directory: Optional[str] = None):
        """
        Initialize the test runner
        
        Args:
            modules_directory: Path to modules directory
        """
        self.module_loader = ModuleLoader(modules_directory)
        self.results: List[Dict[str, Any]] = []
    
    def load_modules(self) -> Dict[str, Any]:
        """
        Load all available security modules
        
        Returns:
            Dictionary of loaded modules with metadata
        """
        loaded_modules = self.module_loader.load_all_modules()
        return self.module_loader.list_loaded_modules()
    
    def get_modules_by_tag(self, tag: str) -> List[str]:
        """
        Get modules that match a specific tag
        
        Args:
            tag: Tag to search for (e.g., 'credentials', 'injection')
            
        Returns:
            List of module names
        """
        return self.module_loader.get_modules_by_tag(tag)
    
    async def run_single_module(self, 
                              module_name: str, 
                              adapter: McpClientAdapter) -> Optional[TestResult]:
        """
        Run a single module against an MCP server
        
        Args:
            module_name: Name of the module to run
            adapter: MCP client adapter
            
        Returns:
            TestResult if successful, None if failed
        """
        start_time = time.time()
        
        try:
            result = await self.module_loader.run_module(module_name, adapter)
            
            if result:
                result.execution_time = time.time() - start_time
            
            return result
            
        except Exception as e:
            return TestResult(
                findings=[],
                success=False,
                error_message=f"Module execution failed: {str(e)}",
                execution_time=time.time() - start_time
            )
    
    async def run_all_modules(self, 
                            adapter: McpClientAdapter,
                            module_filter: Optional[List[str]] = None) -> Dict[str, TestResult]:
        """
        Run all loaded modules against an MCP server
        
        Args:
            adapter: MCP client adapter
            module_filter: Optional list of module names to run (if None, runs all)
            
        Returns:
            Dictionary mapping module names to TestResults
        """
        results = {}
        
        # Get modules to run
        if module_filter:
            modules_to_run = module_filter
        else:
            modules_to_run = list(self.module_loader.loaded_modules.keys())
        
        # Run each module
        for module_name in modules_to_run:
            print(f"Running module: {module_name}")
            result = await self.run_single_module(module_name, adapter)
            if result:
                results[module_name] = result
        
        return results
    
    async def run_modules_by_tag(self, 
                               adapter: McpClientAdapter,
                               tag: str) -> Dict[str, TestResult]:
        """
        Run modules that match a specific tag
        
        Args:
            adapter: MCP client adapter
            tag: Tag to filter modules by
            
        Returns:
            Dictionary mapping module names to TestResults
        """
        modules_to_run = self.get_modules_by_tag(tag)
        return await self.run_all_modules(adapter, modules_to_run)
    
    def generate_report(self, 
                       results: Dict[str, TestResult],
                       target_url: str,
                       output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive security test report
        
        Args:
            results: Dictionary of module results
            target_url: Target MCP server URL
            output_file: Optional file path to save report
            
        Returns:
            Report dictionary
        """
        # Aggregate findings
        all_findings = []
        total_modules = len(results)
        successful_modules = sum(1 for r in results.values() if r.success)
        failed_modules = total_modules - successful_modules
        
        for module_name, result in results.items():
            if result.findings:
                for finding in result.findings:
                    finding.metadata = finding.metadata or {}
                    finding.metadata['module'] = module_name
                    finding.metadata['execution_time'] = result.execution_time
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
        
        # Create report
        report = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'test_type': 'Automated Security Scan',
            'summary': {
                'total_modules': total_modules,
                'successful_modules': successful_modules,
                'failed_modules': failed_modules,
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
                    'execution_time': result.execution_time,
                    'error_message': result.error_message,
                    'metadata': result.metadata
                }
                for module_name, result in results.items()
            }
        }
        
        # Save report if output file specified
        if output_file:
            import json
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
        
        return report
    
    def print_summary(self, results: Dict[str, TestResult]):
        """Print a summary of test results"""
        print("\n" + "="*70)
        print("  MCP Security Framework - Test Results Summary")
        print("="*70)
        
        total_modules = len(results)
        successful_modules = sum(1 for r in results.values() if r.success)
        total_findings = sum(len(r.findings) for r in results.values())
        
        print(f"Modules Executed: {total_modules}")
        print(f"Successful: {successful_modules}")
        print(f"Failed: {total_modules - successful_modules}")
        print(f"Total Findings: {total_findings}")
        
        if total_findings > 0:
            print("\nFindings by Severity:")
            severity_counts = {}
            for result in results.values():
                for finding in result.findings:
                    severity = finding.severity.value
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity, count in sorted(severity_counts.items(), 
                                        key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x[0])):
                print(f"  {severity}: {count}")
        
        print("="*70)
