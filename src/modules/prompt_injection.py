"""
Prompt Injection Detector Module

Detects prompt injection vulnerabilities in MCP server resources
"""

from typing import List, Dict, Any
import re

from .base import BaseSecurityModule, TestResult, Finding, Severity


class PromptInjectionDetector(BaseSecurityModule):
    """Detects prompt injection vulnerabilities in MCP server resources"""
    
    def get_name(self) -> str:
        return "Prompt Injection Detector"
    
    def get_description(self) -> str:
        return "Scans MCP server resources for prompt injection vulnerabilities and unsanitized user input"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_author(self) -> str:
        return "MCP Security Framework Team"
    
    def get_tags(self) -> List[str]:
        return ["prompt-injection", "input-validation", "injection", "resources"]
    
    def _detect_injection_patterns(self, text: str) -> List[str]:
        """Detect common prompt injection patterns"""
        injection_patterns = [
            r'(?i)ignore\s+(previous\s+)?instructions',
            r'(?i)forget\s+(everything|all)',
            r'(?i)you\s+are\s+now\s+(admin|root|administrator)',
            r'(?i)system\s*:\s*you\s+are',
            r'(?i)assistant\s*:\s*',
            r'(?i)human\s*:\s*',
            r'(?i)override\s+(safety|security)',
            r'(?i)jailbreak',
            r'(?i)roleplay\s+as',
            r'(?i)pretend\s+to\s+be',
            r'(?i)act\s+as\s+if',
            r'(?i)simulate\s+being',
            r'(?i)bypass\s+(restrictions|limitations)',
            r'(?i)ignore\s+(safety|security)\s+guidelines'
        ]
        
        found_patterns = []
        for pattern in injection_patterns:
            matches = re.findall(pattern, text)
            if matches:
                found_patterns.append(pattern)
        
        return found_patterns
    
    def _is_parameterized_resource(self, resource_uri: str) -> bool:
        """Check if a resource URI contains parameterized input"""
        return '{' in resource_uri and '}' in resource_uri
    
    def _extract_parameters(self, resource_uri: str) -> List[str]:
        """Extract parameter names from a parameterized resource URI"""
        import re
        params = re.findall(r'\{([^}]+)\}', resource_uri)
        return params
    
    async def run(self, adapter) -> TestResult:
        """Execute the prompt injection detection test"""
        findings = []
        
        try:
            # Get all available resources
            resources = await adapter.list_resources()
            
            for resource in resources:
                resource_uri = str(resource.get('uri', ''))
                resource_name = resource.get('name', 'Unknown')
                resource_description = resource.get('description', '')
                
                # Check if this is a parameterized resource (potential injection point)
                if self._is_parameterized_resource(resource_uri):
                    parameters = self._extract_parameters(resource_uri)
                    
                    # Create finding for parameterized resource
                    finding = self.create_finding(
                        finding_type="Parameterized Resource",
                        severity=Severity.MEDIUM,
                        resource=resource_uri,
                        description=f"Resource '{resource_name}' accepts parameterized input through parameters: {', '.join(parameters)}. "
                                   f"This could be vulnerable to prompt injection if input is not properly validated.",
                        evidence=f"Resource URI: {resource_uri}\nParameters: {', '.join(parameters)}",
                        attack_vector=f"Parameter injection: {resource_uri}",
                        attack_chain=[
                            "1. Attacker identifies parameterized resource",
                            "2. Attacker crafts malicious input for parameters",
                            "3. Attacker injects prompt manipulation instructions",
                            "4. Server processes injected input without validation",
                            "5. LLM executes injected instructions"
                        ],
                        impact="Potential prompt injection allowing attackers to manipulate LLM behavior, "
                              "bypass safety restrictions, or access unauthorized resources.",
                        remediation="Implement strict input validation and sanitization for all parameters. "
                                  "Use allowlists for valid parameter values. "
                                  "Implement proper escaping and encoding.",
                        metadata={
                            'parameters': parameters,
                            'resource_name': resource_name,
                            'resource_description': resource_description,
                            'is_parameterized': True
                        }
                    )
                    findings.append(finding)
                
                # Try to read the resource to check for injection patterns
                try:
                    resource_data = await adapter.read_resource(resource_uri)
                    
                    # Extract text content
                    content = ""
                    if 'contents' in resource_data:
                        for item in resource_data['contents']:
                            if item.get('text'):
                                content += item['text'] + "\n"
                    
                    if content.strip():
                        # Check for injection patterns in content
                        injection_patterns = self._detect_injection_patterns(content)
                        
                        if injection_patterns:
                            # Create finding for detected injection patterns
                            finding = self.create_finding(
                                finding_type="Prompt Injection Pattern Detected",
                                severity=Severity.HIGH,
                                resource=resource_uri,
                                description=f"Resource '{resource_name}' contains content that matches known prompt injection patterns. "
                                          f"Found {len(injection_patterns)} injection patterns.",
                                evidence=content[:500] + "..." if len(content) > 500 else content,
                                attack_vector=f"Direct resource access: {resource_uri}",
                                attack_chain=[
                                    "1. Attacker accesses resource with injection patterns",
                                    "2. Resource content contains prompt manipulation instructions",
                                    "3. LLM processes the injected content",
                                    "4. LLM executes the injected instructions",
                                    "5. Attacker gains unauthorized access or bypasses restrictions"
                                ],
                                impact="Direct prompt injection through resource content. "
                                      "Attacker can manipulate LLM behavior and bypass safety measures.",
                                remediation="Sanitize all resource content before serving to LLMs. "
                                          "Implement content filtering and validation. "
                                          "Remove or escape injection patterns.",
                                metadata={
                                    'injection_patterns': injection_patterns,
                                    'resource_name': resource_name,
                                    'resource_description': resource_description,
                                    'content_length': len(content)
                                }
                            )
                            findings.append(finding)
                
                except Exception as e:
                    # Resource might be protected or not accessible
                    pass
            
            return TestResult(
                findings=findings,
                success=True,
                metadata={
                    'resources_scanned': len(resources),
                    'parameterized_resources': len([r for r in resources if self._is_parameterized_resource(str(r.get('uri', '')))]),
                    'total_findings': len(findings)
                }
            )
            
        except Exception as e:
            return TestResult(
                findings=[],
                success=False,
                error_message=f"Error during prompt injection scan: {str(e)}"
            )
