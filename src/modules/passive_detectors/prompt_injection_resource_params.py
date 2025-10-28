"""
Prompt Injection via Resource Parameters Detector

Detects: CWE-74 (Injection), OWASP LLM01 (Prompt Injection)

Tests for prompt injection vulnerabilities in resource access where:
1. Parameterized resources exist without validation
2. Server reflects injected content or behaves unexpectedly
3. Sensitive resources become accessible without proper authorization

Methodology:
Phase 1 - Passive Detection:
- Lists available resources
- Identifies parameterized resources (potential injection points)
- Identifies sensitive resources by URI patterns
- Tests for unauthorized access to sensitive resources

Phase 2 - Active PoC Generation:
- Sends controlled injection payloads to parameterized resources
- Tests for canary reflection
- Detects error signatures
- Captures successful exploit as proof of concept

Designed for: DV-MCP Challenge 1 class vulnerabilities
"""

import re
from typing import Any, Dict, List

from src.core.models import (
    DetectionResult,
    DetectionStatus,
    ModuleMetadata,
    ProofOfConcept,
    ServerProfile,
    Signal,
    SignalType,
    StandardsMapping,
    CVSSVector,
)
from src.modules.base import Detector


class PromptInjectionResourceParamsDetector(Detector):
    """
    Detects prompt injection vulnerabilities in resource access.

    Target: DV-MCP Challenge 1 (Basic Prompt Injection)
    """

    # Canary strings for injection testing
    CANARIES = [
        "MCPSF_CANARY_001",
        "test_injection_marker",
        "__PROBE__",
    ]

    # Sensitive resource patterns (potential targets)
    SENSITIVE_PATTERNS = [
        r".*credential.*",
        r".*secret.*",
        r".*password.*",
        r".*token.*",
        r".*api[_-]?key.*",
        r".*private.*",
        r".*internal.*",
    ]

    def _is_parameterized_resource(self, resource_uri: str) -> bool:
        """
        Check if a resource URI contains parameterized input (from josh-test).

        Parameterized resources like 'file://{filename}' are potential injection points.

        Args:
            resource_uri: Resource URI to check

        Returns:
            True if URI contains parameter placeholders
        """
        return '{' in resource_uri and '}' in resource_uri

    def _extract_parameters(self, resource_uri: str) -> List[str]:
        """
        Extract parameter names from a parameterized resource URI (from josh-test).

        Example: 'file://{user_id}/data/{filename}' -> ['user_id', 'filename']

        Args:
            resource_uri: Parameterized resource URI

        Returns:
            List of parameter names
        """
        params = re.findall(r'\{([^}]+)\}', resource_uri)
        return params

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-PI-001",
            name="Prompt Injection via Resource Parameters",
            version="1.0.0",
            description=(
                "Detects prompt injection vulnerabilities in resource access. "
                "Tests for canary reflection, error signatures, and unauthorized "
                "access to sensitive resources via parameter manipulation."
            ),
            prerequisites={"resources": True},
            timeout_s=30,
            severity_default="HIGH",
            standards=StandardsMapping(
                cwe="CWE-74",
                owasp_llm="LLM01",
                owasp_api="API8:2023",
                asvs=["V5.1", "V9.1"],
                capec=["CAPEC-242"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    base_score=7.5,
                    severity="HIGH",
                ),
            ),
        )

    async def run(
        self,
        adapter: Any,
        scope: Dict[str, Any],
        profile: ServerProfile,
    ) -> DetectionResult:
        """
        Execute prompt injection detection.

        Strategy:
        1. List available resources
        2. Identify sensitive resources
        3. Attempt benign canary injections
        4. Check for reflection or error signatures
        5. Test unauthorized access patterns
        """
        # Check prerequisites
        if not self.check_prerequisites(profile):
            return self._create_not_applicable_result(
                "Server does not support resources capability"
            )

        # Note: scope is a dict from ScopeConfig.model_dump(), not ScopeConfig instance

        signals: List[Signal] = []
        affected_resources: List[str] = []
        evidence = {}

        try:
            # Step 1: List available resources
            resources = await adapter.list_resources()
            evidence["total_resources"] = len(resources)

            if not resources:
                return DetectionResult(
                    detector_id=self.metadata.id,
                    detector_name=self.metadata.name,
                    detector_version=self.metadata.version,
                    status=DetectionStatus.ABSENT,
                    confidence=0.8,
                    evidence={"reason": "No resources found to test"},
                    standards=self.metadata.standards,
                )

            # Step 2: Identify potentially sensitive resources
            sensitive_resources = self._find_sensitive_resources(resources)
            evidence["sensitive_resources_found"] = len(sensitive_resources)

            # Also check for parameterized resources (from josh-test)
            parameterized_resources = [r for r in resources if self._is_parameterized_resource(str(r.get('uri', '')))]
            evidence["parameterized_resources_found"] = len(parameterized_resources)

            if sensitive_resources:
                signals.append(
                    Signal(
                        type=SignalType.SCHEMA_OVERPERMISSIVE,
                        value=True,
                        context={
                            "reason": "Sensitive resources exposed",
                            "count": len(sensitive_resources),
                        },
                    )
                )

            # Flag parameterized resources as potential injection points
            for resource in parameterized_resources:
                uri = str(resource.get('uri', ''))
                params = self._extract_parameters(uri)
                signals.append(
                    Signal(
                        type=SignalType.SCHEMA_OVERPERMISSIVE,
                        value=True,
                        context={
                            "reason": "Parameterized resource detected",
                            "uri": uri,
                            "parameters": params,
                            "parameter_count": len(params),
                            "note": "Parameters could be injection points if not validated"
                        },
                    )
                )

            # Step 3: Test each sensitive resource for injection
            for resource in sensitive_resources:
                uri = resource.get("uri", "")

                # Attempt to read sensitive resource
                try:
                    result = await adapter.read_resource(uri)

                    # Check for sensitive content in response
                    content = self._extract_content_text(result)

                    # Check for sensitive data patterns (access control test)
                    if self._contains_sensitive_data(content):
                        signals.append(
                            Signal(
                                type=SignalType.SENSITIVE_EXPOSURE,
                                value=True,
                                context={
                                    "uri": uri,
                                    "content_length": len(content),
                                    "detection_type": "sensitive_data"
                                },
                            )
                        )
                        affected_resources.append(uri)

                    # Check for canary reflection (if any canary in content)
                    for canary in self.CANARIES:
                        if canary.lower() in content.lower():
                            signals.append(
                                Signal(
                                    type=SignalType.REFLECTION,
                                    value=True,
                                    context={
                                        "uri": uri,
                                        "canary": canary,
                                    },
                                )
                            )

                except Exception as e:
                    # Log errors as potential indicators
                    error_msg = str(e).lower()

                    # Check for error signatures (stack traces, internal paths)
                    if any(
                        sig in error_msg
                        for sig in ["traceback", "exception", "error:", "file", "line"]
                    ):
                        signals.append(
                            Signal(
                                type=SignalType.ERROR_SIGNATURE,
                                value=error_msg[:200],
                                context={"uri": uri},
                            )
                        )

            # Step 4: Generate PoC (Active Testing)
            pocs: List[ProofOfConcept] = []
            # Generate PoCs for both parameterized resources and sensitive resource access
            if parameterized_resources:
                pocs.extend(await self._generate_injection_pocs(adapter, parameterized_resources, sensitive_resources))
            if affected_resources:
                # Also create PoCs for unauthorized sensitive resource access
                pocs.extend(await self._generate_access_pocs(adapter, affected_resources))

            # Step 5: Determine result based on signals
            if not signals:
                return DetectionResult(
                    detector_id=self.metadata.id,
                    detector_name=self.metadata.name,
                    detector_version=self.metadata.version,
                    status=DetectionStatus.ABSENT,
                    confidence=0.9,
                    evidence={
                        "resources_tested": len(sensitive_resources),
                        "no_issues_found": True,
                    },
                    standards=self.metadata.standards,
                )

            # Check if we have high-confidence signals
            has_sensitive_exposure = any(
                s.type == SignalType.SENSITIVE_EXPOSURE for s in signals
            )
            has_reflection = any(s.type == SignalType.REFLECTION for s in signals)

            if has_sensitive_exposure or has_reflection:
                status = DetectionStatus.PRESENT
                confidence = 0.95 if has_sensitive_exposure else 0.85
                remediation = (
                    "Implement input validation and sanitization on resource URIs and parameters. "
                    "Restrict access to sensitive resources using authentication and authorization. "
                    "Do not expose internal resource paths directly to clients."
                )
            else:
                # Only overpermissive schema or error signatures
                status = DetectionStatus.PRESENT
                confidence = 0.7
                remediation = (
                    "Review resource access controls. Sensitive resource names are exposed "
                    "which may aid attackers in reconnaissance."
                )

            return DetectionResult(
                detector_id=self.metadata.id,
                detector_name=self.metadata.name,
                detector_version=self.metadata.version,
                status=status,
                confidence=confidence,
                affected_resources=affected_resources,
                signals=signals,
                proof_of_concepts=pocs,
                evidence=evidence,
                standards=self.metadata.standards,
                remediation=remediation,
            )

        except Exception as e:
            return self._create_unknown_result(
                f"Detector encountered unexpected error: {str(e)}",
                confidence=0.0,
            )

    def _find_sensitive_resources(self, resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify resources that match sensitive patterns.

        Args:
            resources: List of resource dicts from list_resources()

        Returns:
            List of potentially sensitive resources
        """
        sensitive = []

        for resource in resources:
            uri = resource.get("uri", "").lower()
            name = resource.get("name", "").lower()
            description = resource.get("description", "").lower()

            # Check if any sensitive pattern matches
            text = f"{uri} {name} {description}"
            for pattern in self.SENSITIVE_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    sensitive.append(resource)
                    break

        return sensitive

    def _extract_content_text(self, resource_data: Dict[str, Any]) -> str:
        """
        Extract text content from resource read result.

        Args:
            resource_data: Result from read_resource()

        Returns:
            Concatenated text content
        """
        texts = []

        contents = resource_data.get("contents", [])
        for content in contents:
            if "text" in content and content["text"]:
                texts.append(str(content["text"]))

        return " ".join(texts)

    def _contains_sensitive_data(self, text: str) -> bool:
        """
        Check if text contains sensitive data patterns.

        Args:
            text: Text content to analyze

        Returns:
            True if sensitive patterns detected
        """
        text_lower = text.lower()

        # Patterns indicating sensitive data
        sensitive_indicators = [
            r"password\s*[:=]",
            r"api[_-]?key\s*[:=]",
            r"secret\s*[:=]",
            r"token\s*[:=]",
            r"credential",
            r"private[_-]?key",
            r"-----BEGIN.*KEY-----",
        ]

        for pattern in sensitive_indicators:
            if re.search(pattern, text_lower):
                return True

        return False

    async def _generate_injection_pocs(
        self,
        adapter,
        parameterized_resources: List[Dict[str, Any]],
        sensitive_resources: List[Dict[str, Any]]
    ) -> List[ProofOfConcept]:
        """Generate PoCs by attempting controlled exploitation of parameterized resources"""
        pocs = []

        # Injection payloads to test
        payloads = [
            "../../../credentials",  # Path traversal
            "../../secret",
            self.CANARIES[0],  # Reflection test
        ]

        # Get sensitive resource names for targeting
        sensitive_names = [r.get('uri', '').split('/')[-1] for r in sensitive_resources]

        for resource in parameterized_resources[:2]:  # Limit to 2 to avoid abuse
            uri_template = str(resource.get('uri', ''))
            params = self._extract_parameters(uri_template)

            for payload in payloads:
                try:
                    # Replace first parameter with payload
                    test_uri = uri_template.replace(f'{{{params[0]}}}', payload) if params else uri_template

                    result = await adapter.read_resource(test_uri)
                    content = self._extract_content_text(result)

                    # Check if exploit succeeded
                    success = (
                        payload in content or  # Reflection
                        self._contains_sensitive_data(content) or  # Got sensitive data
                        any(name in test_uri for name in sensitive_names)  # Path traversal worked
                    )

                    if success:
                        pocs.append(ProofOfConcept(
                            target=uri_template,
                            attack_type="prompt_injection",
                            payload={"uri": test_uri, "injection": payload, "parameter": params[0] if params else "unknown"},
                            response={"content_preview": content[:200], "content_length": len(content)},
                            success=True,
                            impact_demonstrated=f"Injected '{payload}' via parameter - {'reflected in response' if payload in content else 'accessed sensitive data'}"
                        ))
                        break  # One PoC per resource is enough

                except Exception:
                    pass  # Failed exploit, continue

        return pocs

    async def _generate_access_pocs(
        self,
        adapter,
        affected_resources: List[str]
    ) -> List[ProofOfConcept]:
        """Generate PoCs by demonstrating unauthorized access to sensitive resources"""
        pocs = []

        for uri in affected_resources[:2]:  # Limit to 2 PoCs
            try:
                # Re-read the resource to capture actual content
                result = await adapter.read_resource(uri)
                content = self._extract_content_text(result)

                # Extract sensitive data patterns
                sensitive_patterns = []
                if re.search(r"password\s*[:=]", content, re.IGNORECASE):
                    sensitive_patterns.append("passwords")
                if re.search(r"api[_-]?key\s*[:=]", content, re.IGNORECASE):
                    sensitive_patterns.append("api_keys")
                if re.search(r"secret\s*[:=]", content, re.IGNORECASE):
                    sensitive_patterns.append("secrets")
                if re.search(r"token\s*[:=]", content, re.IGNORECASE):
                    sensitive_patterns.append("tokens")

                pocs.append(ProofOfConcept(
                    target=uri,
                    attack_type="unauthorized_access",
                    payload={"method": "read_resource", "uri": uri, "authentication": "none"},
                    response={
                        "content_length": len(content),
                        "content_preview": content[:300],
                        "sensitive_patterns_found": sensitive_patterns
                    },
                    success=True,
                    impact_demonstrated=f"Accessed sensitive resource '{uri}' without authentication. Contains: {', '.join(sensitive_patterns)}"
                ))

            except Exception:
                pass  # Failed to re-read, skip PoC

        return pocs
