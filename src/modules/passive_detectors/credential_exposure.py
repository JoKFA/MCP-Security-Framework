"""
Credential Exposure Detector (v0.2 Framework)

Adapted from josh-test branch credential_exposure.py
Detects exposed credentials in MCP server resources using pattern matching.

Detection method: PASSIVE - scans existing resource content for secret patterns
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
        Extract potential secrets from text using pattern matching.

        IMPORTANT: These patterns are preserved from josh-test for future active testing.
        Current implementation: PASSIVE detection (scans existing content)
        Future enhancement: ACTIVE testing (inject payloads to test validation)

        Args:
            text: Content to scan for secrets

        Returns:
            Dictionary mapping secret types to found values
        """
        secrets = {
            'passwords': [],
            'api_keys': [],
            'tokens': [],
            'connection_strings': [],
            'private_keys': [],
            'database_urls': []
        }

        # Pattern matching for different types of secrets
        # NOTE: These patterns are kept for future active injection testing
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
        Execute credential exposure detection.

        Detection strategy:
        1. List all resources
        2. Filter for resources with sensitive-looking URIs
        3. Read resource content
        4. Scan content for secret patterns
        5. Emit signals for each type of secret found

        Args:
            adapter: SafeAdapter instance (handles scope/rate limiting)
            scope: ScopeConfig (optional, adapter enforces it)
            profile: ServerProfile (optional metadata)

        Returns:
            DetectionResult with signals for detected credentials
        """
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'resources_scanned': 0,
            'sensitive_resources_found': 0,
            'secrets_by_resource': {}
        }
        start_time = datetime.now(timezone.utc)

        try:
            # Step 1: List all available resources
            resources = await adapter.list_resources()
            total_resources = len(resources)
            evidence['resources_scanned'] = total_resources

            # Step 2: Scan resources for credentials
            for resource in resources:
                resource_uri = str(resource.get('uri', ''))
                resource_name = resource.get('name', 'Unknown')
                resource_description = resource.get('description', '')

                # Prioritize resources with sensitive-looking URIs
                is_sensitive = self._is_sensitive_resource(resource_uri)
                if is_sensitive:
                    evidence['sensitive_resources_found'] += 1

                # Try to read the resource content
                try:
                    resource_data = await adapter.read_resource(resource_uri)

                    # Extract text content
                    content = ""
                    if 'contents' in resource_data:
                        for item in resource_data['contents']:
                            if item.get('text'):
                                content += item['text'] + "\n"

                    if content.strip():
                        # Scan for secrets using pattern matching
                        secrets = self._extract_secrets(content)

                        # Check if any secrets were found
                        total_secrets = sum(len(v) for v in secrets.values())

                        if total_secrets > 0:
                            # Store in evidence (with actual secrets for PoC generation)
                            evidence['secrets_by_resource'][resource_uri] = {
                                'resource_name': resource_name,
                                'secret_types': [k for k, v in secrets.items() if v],
                                'total_count': total_secrets,
                                'severity': self._determine_severity(secrets),
                                'secrets': secrets  # Store actual secrets for PoC
                            }

                            # Emit signal for sensitive exposure
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

                except Exception as e:
                    # Resource might be protected or not accessible
                    # This is not necessarily an error - it could indicate proper access control
                    # We don't emit a signal for this case
                    pass

            # Generate PoCs for resources with secrets
            pocs = self._generate_pocs(evidence.get('secrets_by_resource', {}))

            # Determine overall status
            status = DetectionStatus.PRESENT if signals else DetectionStatus.ABSENT
            confidence = 0.95 if total_resources > 0 else 0.0

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
        """Generate PoCs from detected credentials with actual secret samples"""
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
