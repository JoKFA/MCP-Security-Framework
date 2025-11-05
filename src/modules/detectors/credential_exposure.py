"""
Credential Exposure Detector

Detects exposed credentials in MCP server resources using pattern matching.

How it works:
- Scans resource content for secret patterns (passwords, API keys, tokens, etc.)
- Uses regex patterns to identify different types of secrets
- Flags resources that contain sensitive data

Similar to tool_enumeration.py:
- Both enumerate everything (tools vs resources)
- Both analyze what they find (dangerous keywords vs secret patterns)
- Both are PASSIVE - just looking at metadata/content, not executing anything

Standards: CWE-522, OWASP LLM01, OWASP API2, CVSS 8.2 HIGH
"""

from typing import List, Dict, Any, Optional
import re
from datetime import datetime, timezone

from ..base import Detector
from ...core.models import (
    ModuleMetadata,
    DetectionResult,
    DetectionStatus,
    ProofOfConcept,
    Signal,
    SignalType,
    StandardsMapping,
    CVSSVector
)


class CredentialExposureDetector(Detector):
    """Detects exposed credentials in MCP server resources using pattern matching"""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-CE-001",
            name="Credential Exposure Detector",
            description="Scans MCP server resources for exposed credentials, passwords, API keys, and other sensitive data",
            version="1.0.0",
            prerequisites={"resources": True},
            timeout_s=30,
            severity_default="HIGH",
            standards=StandardsMapping(
                cwe="CWE-522",  # Insufficiently Protected Credentials
                owasp_llm="LLM01",  # Prompt Injection (sensitive data in prompts)
                owasp_api="API2",  # Broken Authentication
                asvs=["V2.1"],  # Password Security Requirements
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    base_score=8.2,
                    severity="HIGH"
                )
            )
        )

    def _extract_secrets(self, text: str) -> Dict[str, List[str]]:
        """
        Extract potential secrets from text using regex pattern matching.
        
        Scans for common secret patterns like passwords, API keys, tokens, etc.
        Returns dictionary mapping secret types to found values.
        """
        secrets = {
            'passwords': [],
            'api_keys': [],
            'tokens': [],
            'connection_strings': [],
            'private_keys': [],
            'database_urls': []
        }

        # Regex patterns for different types of secrets
        patterns = {
            'passwords': [
                r'(?i)(password|passwd|pwd)[\s:=]+([^\s\n]+)',
                r'(?i)(secret)[\s:=]+([^\s\n]+)',
                r'(?i)(key)[\s:=]+([^\s\n]+)'
            ],
            'api_keys': [
                r'(?i)(api[_-]?key|apikey)[\s:=]+([^\s\n]+)',
                r'(?i)(access[_-]?key)[\s:=]+([^\s\n]+)',
                r'sk-[a-zA-Z0-9]{20,}',  # OpenAI-style API keys
                r'ak_[a-zA-Z0-9]{20,}'   # Generic API key pattern
            ],
            'tokens': [
                r'(?i)(token)[\s:=]+([^\s\n]+)',
                r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',  # JWT tokens
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
                        # Extract the actual secret value (second group)
                        secret_value = match[1] if len(match) > 1 else match[0]
                    else:
                        secret_value = match

                    # Filter out very short matches (likely false positives)
                    if secret_value and len(secret_value) > 3:
                        secrets[secret_type].append(secret_value)

        # Remove duplicates
        for secret_type in secrets:
            secrets[secret_type] = list(set(secrets[secret_type]))

        return secrets

    def _is_sensitive_resource(self, resource_uri: str) -> bool:
        """
        Check if a resource URI suggests it contains sensitive data.

        This is a heuristic to prioritize which resources to scan.
        """
        sensitive_keywords = [
            'credential', 'password', 'secret', 'token', 'key',
            'private', 'confidential', 'internal', 'admin', 'auth',
            'login', 'session', 'oauth', 'jwt', 'api_key'
        ]

        uri_lower = resource_uri.lower()
        return any(keyword in uri_lower for keyword in sensitive_keywords)

    def _determine_severity(self, secrets: Dict[str, List[str]]) -> str:
        """
        Determine severity based on types of secrets found.

        Returns:
            "CRITICAL", "HIGH", "MEDIUM", or "LOW"
        """
        if secrets['private_keys'] or secrets['connection_strings']:
            return "CRITICAL"
        if secrets['passwords'] or secrets['api_keys']:
            return "HIGH"
        if secrets['tokens']:
            return "MEDIUM"
        return "LOW"

    async def run(
        self,
        adapter,
        scope: Optional[Any] = None,
        profile: Optional[Any] = None
    ) -> DetectionResult:
        """
        Main function - scans resources for exposed credentials.
        
        Flow: List resources → Read content → Scan for secrets → Report findings
        
        MCP Calls Made:
        - adapter.list_resources() → Gets list of all available resources
        - adapter.read_resource(uri) → Reads content of each resource
        
        What it looks for:
        - Passwords: "password: secret123", "pwd=mysecret"
        - API Keys: "api_key: sk-1234...", "apikey=ak_abcd..."
        - Tokens: "token: eyJ...", JWT tokens
        - Connection Strings: "postgresql://user:pass@host", database URLs
        - Private Keys: "-----BEGIN RSA PRIVATE KEY-----"
        """
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'resources_scanned': 0,
            'sensitive_resources_found': 0,
            'secrets_by_resource': {}
        }
        start_time = datetime.now(timezone.utc)

        try:
            # STEP 1: Get all resources from the server
            # This calls: adapter.list_resources() → MCP sends "resources/list" request
            # Returns: List of resource objects with URIs (e.g., "notes://user123", "internal://config")
            print("  [PASSIVE] Listing resources...")
            resources = await adapter.list_resources()
            evidence['resources_scanned'] = len(resources)
            print(f"  [PASSIVE] Found {len(resources)} resources")

            # STEP 2: Read each resource and scan for secrets
            print("  [PASSIVE] Scanning resources for credentials...")
            for resource in resources:
                resource_uri = str(resource.get('uri', ''))
                resource_name = resource.get('name', 'Unknown')
                resource_description = resource.get('description', '')

                # Check if resource URI suggests sensitive content (heuristic)
                is_sensitive = self._is_sensitive_resource(resource_uri)
                if is_sensitive:
                    evidence['sensitive_resources_found'] += 1

                # STEP 3: Read resource content
                # This calls: adapter.read_resource(uri) → MCP sends "resources/read" request
                # Returns: Resource content (text, JSON, etc.)
                try:
                    resource_data = await adapter.read_resource(resource_uri)

                    # Extract text content from resource
                    content = ""
                    if 'contents' in resource_data:
                        for item in resource_data['contents']:
                            if item.get('text'):
                                content += item['text'] + "\n"

                    if content.strip():
                        # STEP 4: Scan content for secret patterns using regex
                        # This runs regex patterns to find passwords, API keys, tokens, etc.
                        secrets = self._extract_secrets(content)
                        total_secrets = sum(len(v) for v in secrets.values())

                        if total_secrets > 0:
                            # Found secrets! Store findings
                            evidence['secrets_by_resource'][resource_uri] = {
                                'resource_name': resource_name,
                                'secret_types': [k for k, v in secrets.items() if v],
                                'total_count': total_secrets,
                                'severity': self._determine_severity(secrets),
                                'secrets': secrets  # Store for PoC generation
                            }

                            # Create signal (framework uses this for correlation/reporting)
                            signals.append(Signal(
                                type=SignalType.SENSITIVE_EXPOSURE,
                                value=True,
                                context={
                                    'resource_uri': resource_uri,
                                    'resource_name': resource_name,
                                    'secret_types': [k for k, v in secrets.items() if v],
                                    'total_secrets': total_secrets,
                                    'severity': self._determine_severity(secrets),
                                    'is_critical': bool(secrets['private_keys'] or secrets['connection_strings'])
                                }
                            ))
                            print(f"  [!] Found {total_secrets} secrets in {resource_uri}")

                except Exception:
                    # Resource might be protected or not accessible - skip it
                    pass

            # Generate PoCs from findings (these document what we found, not active testing)
            pocs = self._generate_pocs(evidence.get('secrets_by_resource', {}))

            # Build result
            status = DetectionStatus.PRESENT if signals else DetectionStatus.ABSENT
            confidence = 0.95 if evidence['resources_scanned'] > 0 else 0.0

            return DetectionResult(
                detector_id=self.metadata.id,
                detector_name=self.metadata.name,
                detector_version=self.metadata.version,
                status=status,
                confidence=confidence,
                signals=signals,
                proof_of_concepts=pocs,
                evidence=evidence,
                standards=self.metadata.standards,
                timestamp=start_time
            )

        except Exception as e:
            # Return error status
            return DetectionResult(
                detector_id=self.metadata.id,
                detector_name=self.metadata.name,
                detector_version=self.metadata.version,
                status=DetectionStatus.UNKNOWN,
                confidence=0.0,
                signals=[],
                evidence={'error': str(e)},
                standards=self.metadata.standards,
                timestamp=start_time
            )

    def _generate_pocs(self, secrets_by_resource: Dict[str, Any]) -> List[ProofOfConcept]:
        """Generate proof-of-concept documents from detected credentials (redacted samples)"""
        pocs = []
        for uri, secret_info in list(secrets_by_resource.items())[:3]:  # Max 3 PoCs
            # Get actual secrets
            secrets = secret_info.get('secrets', {})

            # Build response with sample secrets (redacted for safety)
            secret_samples = {}
            for secret_type, values in secrets.items():
                if values:
                    # Show first 2 secrets of each type, partially redacted
                    samples = []
                    for val in values[:2]:
                        # Redact middle portion: show first 6 and last 4 chars
                        if len(val) > 12:
                            redacted = f"{val[:6]}...{val[-4:]}"
                        else:
                            redacted = f"{val[:4]}{'*' * (len(val) - 4)}"
                        samples.append(redacted)
                    secret_samples[secret_type] = samples

            pocs.append(ProofOfConcept(
                target=uri,
                attack_type="credential_exposure",
                payload={"method": "read_resource", "uri": uri},
                response={
                    "secret_types": secret_info['secret_types'],
                    "total_secrets": secret_info['total_count'],
                    "samples": secret_samples  # Include actual samples (redacted)
                },
                success=True,
                impact_demonstrated=f"Retrieved {secret_info['total_count']} secrets ({', '.join(secret_info['secret_types'])}) from {uri}. Samples: {self._format_samples(secret_samples)}"
            ))
        return pocs

    def _format_samples(self, secret_samples: Dict[str, List[str]]) -> str:
        """Format secret samples for display"""
        parts = []
        for secret_type, samples in secret_samples.items():
            if samples:
                parts.append(f"{secret_type}=[{', '.join(samples)}]")
        return "; ".join(parts[:3])  # Show max 3 types
