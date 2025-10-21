"""
Tool Enumeration Module

Enumerates and analyzes MCP server tools for security issues
"""

from typing import List, Dict, Any

from .base import BaseSecurityModule, TestResult, Finding, Severity


class ToolEnumerationModule(BaseSecurityModule):
    """Enumerates and analyzes MCP server tools for security issues"""
    
    def get_name(self) -> str:
        return "Tool Enumeration Analyzer"
    
    def get_description(self) -> str:
        return "Enumerates MCP server tools and analyzes them for potential security issues"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_author(self) -> str:
        return "MCP Security Framework Team"
    
    def get_tags(self) -> List[str]:
        return ["tools", "enumeration", "analysis", "permissions"]
    
    def _analyze_tool_for_risks(self, tool: Dict[str, Any]) -> List[Finding]:
        """Analyze a single tool for security risks"""
        findings = []
        tool_name = tool.get('name', 'Unknown')
        tool_description = tool.get('description', '')
        tool_schema = tool.get('inputSchema', {})
        
        # Check for dangerous tool names
        dangerous_keywords = [
            'execute', 'command', 'shell', 'system', 'admin', 'root',
            'delete', 'remove', 'drop', 'truncate', 'format', 'wipe'
        ]
        
        tool_name_lower = tool_name.lower()
        tool_desc_lower = tool_description.lower()
        
        for keyword in dangerous_keywords:
            if keyword in tool_name_lower or keyword in tool_desc_lower:
                finding = self.create_finding(
                    finding_type="Potentially Dangerous Tool",
                    severity=Severity.MEDIUM,
                    resource=f"tool://{tool_name}",
                    description=f"Tool '{tool_name}' contains potentially dangerous keywords ('{keyword}') "
                               f"in name or description. This could indicate system-level access capabilities.",
                    evidence=f"Tool Name: {tool_name}\nDescription: {tool_description}",
                    attack_vector=f"Tool call: {tool_name}",
                    attack_chain=[
                        "1. Attacker enumerates available tools",
                        "2. Attacker identifies potentially dangerous tool",
                        "3. Attacker analyzes tool capabilities",
                        "4. Attacker attempts to exploit tool functionality"
                    ],
                    impact="Potential for system-level access or destructive operations through tool usage.",
                    remediation="Review tool permissions and capabilities. Implement proper access controls "
                              "and input validation for all tools.",
                    metadata={
                        'tool_name': tool_name,
                        'tool_description': tool_description,
                        'dangerous_keyword': keyword,
                        'input_schema': tool_schema
                    }
                )
                findings.append(finding)
        
        # Check for tools with broad permissions
        if 'inputSchema' in tool_schema:
            properties = tool_schema.get('properties', {})
            if len(properties) == 0:
                finding = self.create_finding(
                    finding_type="Tool with No Input Validation",
                    severity=Severity.LOW,
                    resource=f"tool://{tool_name}",
                    description=f"Tool '{tool_name}' has no defined input schema, which could indicate "
                               f"lack of input validation or overly permissive access.",
                    evidence=f"Tool Name: {tool_name}\nInput Schema: {tool_schema}",
                    attack_vector=f"Tool call with arbitrary input: {tool_name}",
                    impact="Potential for input injection or unexpected behavior due to lack of validation.",
                    remediation="Define proper input schemas for all tools. Implement input validation "
                              "and sanitization.",
                    metadata={
                        'tool_name': tool_name,
                        'tool_description': tool_description,
                        'input_schema': tool_schema,
                        'has_validation': False
                    }
                )
                findings.append(finding)
        
        return findings
    
    async def run(self, adapter) -> TestResult:
        """Execute the tool enumeration analysis"""
        findings = []
        
        try:
            # Get all available tools
            tools = await adapter.list_tools()
            
            for tool in tools:
                tool_findings = self._analyze_tool_for_risks(tool)
                findings.extend(tool_findings)
            
            # Create summary finding if no specific issues found
            if not findings:
                summary_finding = self.create_finding(
                    finding_type="Tool Enumeration Summary",
                    severity=Severity.INFO,
                    resource="tools://all",
                    description=f"Successfully enumerated {len(tools)} tools. No obvious security issues detected "
                               f"in tool names or descriptions.",
                    evidence=f"Tools found: {[tool.get('name', 'Unknown') for tool in tools]}",
                    metadata={
                        'total_tools': len(tools),
                        'tools_analyzed': [tool.get('name', 'Unknown') for tool in tools],
                        'findings_count': 0
                    }
                )
                findings.append(summary_finding)
            
            return TestResult(
                findings=findings,
                success=True,
                metadata={
                    'tools_enumerated': len(tools),
                    'tools_analyzed': [tool.get('name', 'Unknown') for tool in tools],
                    'total_findings': len(findings)
                }
            )
            
        except Exception as e:
            return TestResult(
                findings=[],
                success=False,
                error_message=f"Error during tool enumeration: {str(e)}"
            )
