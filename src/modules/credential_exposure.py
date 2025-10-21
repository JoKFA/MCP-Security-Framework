"""
Credential Exposure Detector Module

Detects exposed credentials in MCP server resources
"""

from typing import List, Dict, Any
import re

from .base import BaseSecurityModule, TestResult, Finding, Severity


class CredentialExposureDetector(BaseSecurityModule):
    """Detects exposed credentials in MCP server resources"""
    
    def get_name(self) -> str:
        return "Credential Exposure Detector"
    
    def get_description(self) -> str:
        return "Scans MCP server resources for exposed credentials, passwords, API keys, and other sensitive data"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_author(self) -> str:
        return "MCP Security Framework Team"
    
    def get_tags(self) -> List[str]:
        return ["credentials", "secrets", "exposure", "resources"]
    
    def _extract_secrets(self, text: str) -> Dict[str, List[str]]:
        """Extract potential secrets from text using pattern matching"""
        secrets = {
            'passwords': [],
            'api_keys': [],
            'tokens': [],
            'connection_strings': [],
            'private_keys': [],
            'database_urls': []
        }
        
        # Pattern matching for different types of secrets
        patterns = {
            'passwords': [
                r'(?i)(password|passwd|pwd)[\s:=]+([^\s\n]+)',
                r'(?i)(secret)[\s:=]+([^\s\n]+)',
                r'(?i)(key)[\s:=]+([^\s\n]+)'
            ],
            'api_keys': [
                r'(?i)(api[_-]?key|apikey)[\s:=]+([^\s\n]+)',
                r'(?i)(access[_-]?key)[\s:=]+([^\s\n]+)',
                r'sk-[a-zA-Z0-9]{20,}',
                r'ak_[a-zA-Z0-9]{20,}'
            ],
            'tokens': [
                r'(?i)(token)[\s:=]+([^\s\n]+)',
                r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',  # JWT
                r'[a-zA-Z0-9]{32,}'  # Generic token pattern
            ],
            'connection_strings': [
                r'(?i)(postgresql|mysql|mongodb|redis)://([^\s\n]+)',
                r'(?i)(database[_-]?url)[\s:=]+([^\s\n]+)',
                r'(?i)(connection[_-]?string)[\s:=]+([^\s\n]+)'
            ],
            'private_keys': [
                r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----',
                r'-----BEGIN OPENSSH PRIVATE KEY-----'
            ],
            'database_urls': [
                r'(?i)(db[_-]?url|database[_-]?url)[\s:=]+([^\s\n]+)',
                r'(?i)(connection[_-]?string)[\s:=]+([^\s\n]+)'
            ]
        }
        
        for secret_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, text)
                for match in matches:
                    if isinstance(match, tuple):
                        # Extract the actual secret value
                        secret_value = match[1] if len(match) > 1 else match[0]
                    else:
                        secret_value = match
                    
                    if secret_value and len(secret_value) > 3:  # Filter out very short matches
                        secrets[secret_type].append(secret_value)
        
        # Remove duplicates
        for secret_type in secrets:
            secrets[secret_type] = list(set(secrets[secret_type]))
        
        return secrets
    
    def _is_sensitive_resource(self, resource_uri: str) -> bool:
        """Check if a resource URI suggests it contains sensitive data"""
        sensitive_keywords = [
            'credential', 'password', 'secret', 'token', 'key', 
            'private', 'confidential', 'internal', 'admin', 'auth'
        ]
        
        uri_lower = resource_uri.lower()
        return any(keyword in uri_lower for keyword in sensitive_keywords)
    
    async def run(self, adapter) -> TestResult:
        """Execute the credential exposure detection test"""
        findings = []
        
        try:
            # Get all available resources
            resources = await adapter.list_resources()
            
            for resource in resources:
                resource_uri = str(resource.get('uri', ''))
                resource_name = resource.get('name', 'Unknown')
                resource_description = resource.get('description', '')
                
                # Check if this looks like a sensitive resource
                is_sensitive = self._is_sensitive_resource(resource_uri)
                
                if is_sensitive:
                    try:
                        # Try to read the resource
                        resource_data = await adapter.read_resource(resource_uri)
                        
                        # Extract text content
                        content = ""
                        if 'contents' in resource_data:
                            for item in resource_data['contents']:
                                if item.get('text'):
                                    content += item['text'] + "\n"
                        
                        if content.strip():
                            # Extract secrets from content
                            secrets = self._extract_secrets(content)
                            
                            # Check if any secrets were found
                            total_secrets = sum(len(secrets[key]) for key in secrets)
                            
                            if total_secrets > 0:
                                # Determine severity based on types of secrets found
                                severity = Severity.LOW
                                if secrets['passwords'] or secrets['api_keys']:
                                    severity = Severity.HIGH
                                if secrets['private_keys'] or secrets['connection_strings']:
                                    severity = Severity.CRITICAL
                                
                                # Create finding
                                finding = self.create_finding(
                                    finding_type="Credential Exposure",
                                    severity=severity,
                                    resource=resource_uri,
                                    description=f"Sensitive credentials found in resource '{resource_name}'. "
                                              f"Found {total_secrets} potential secrets including "
                                              f"{', '.join([k for k, v in secrets.items() if v])}.",
                                    evidence=content[:500] + "..." if len(content) > 500 else content,
                                    attack_vector=f"Direct resource access: {resource_uri}",
                                    attack_chain=[
                                        "1. Attacker enumerates available resources",
                                        "2. Attacker identifies sensitive resource by URI pattern",
                                        "3. Attacker reads resource content",
                                        "4. Attacker extracts credentials and sensitive data"
                                    ],
                                    impact=f"Exposure of {total_secrets} sensitive credentials including "
                                          f"passwords, API keys, and connection strings. "
                                          f"Complete compromise of authentication systems.",
                                    remediation="Implement proper access controls on sensitive resources. "
                                              "Use authentication and authorization. "
                                              "Store credentials in secure vaults, not in plain text.",
                                    metadata={
                                        'secrets_found': secrets,
                                        'total_secrets': total_secrets,
                                        'resource_name': resource_name,
                                        'resource_description': resource_description
                                    }
                                )
                                findings.append(finding)
                    
                    except Exception as e:
                        # Resource might be protected or not accessible
                        # This could be a finding if we expected it to be accessible
                        pass
            
            return TestResult(
                findings=findings,
                success=True,
                metadata={
                    'resources_scanned': len(resources),
                    'sensitive_resources_found': len([r for r in resources if self._is_sensitive_resource(str(r.get('uri', '')))]),
                    'total_findings': len(findings)
                }
            )
            
        except Exception as e:
            return TestResult(
                findings=[],
                success=False,
                error_message=f"Error during credential exposure scan: {str(e)}"
            )
