"""
Active Prompt Injection Confirmation Detector

This detector ACTUALLY ATTEMPTS to exploit prompt injection by sending
malicious payloads and verifying the server response contains our injected marker.

Detection method: ACTIVE - sends test payloads and checks for reflection
Target: DV-MCP Challenge 1 and similar parameterized resource vulnerabilities
"""

import random
import secrets
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from src.modules.base import Detector
from src.core.models import (
    ModuleMetadata,
    DetectionResult,
    DetectionStatus,
    ProofOfConcept,
    Signal,
    SignalType,
    StandardsMapping,
    CVSSVector
)


class PromptInjectionActiveDetector(Detector):
    """
    ACTIVE detector that confirms prompt injection by attempting exploitation.
    
    How it works:
    1. Finds parameterized resources (e.g., "notes://{user_id}")
    2. Sends a unique canary marker as the parameter value
    3. Reads the response
    4. Checks if the canary appears in the response
    5. If yes → VULNERABILITY CONFIRMED (server reflects unsanitized input)
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-ACTIVE-PI-001",
            name="Active Prompt Injection Confirmation",
            description="ACTIVELY confirms prompt injection by sending test payloads and verifying reflection",
            version="1.0.0",
            prerequisites={"resources": True},
            timeout_s=30,
            severity_default="HIGH",
            standards=StandardsMapping(
                cwe="CWE-74",  # Injection
                owasp_llm="LLM01",  # Prompt Injection
                owasp_api="API8:2023",
                asvs=["V5.1", "V9.1"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    base_score=7.5,
                    severity="HIGH"
                )
            )
        )

    def _generate_canary(self) -> str:
        """Generate a unique marker that we'll inject"""
        random_str = secrets.token_hex(8)
        return f"MCPSF_INJECT_{random_str}"

    def _is_parameterized_resource(self, resource_uri: str) -> bool:
        """Check if resource URI has parameters like {user_id}"""
        return '{' in resource_uri and '}' in resource_uri

    def _extract_parameters(self, resource_uri: str) -> List[str]:
        """Extract parameter names from URI template"""
        import re
        params = re.findall(r'\{([^}]+)\}', resource_uri)
        return params

    def _extract_text_from_response(self, mcp_response: Dict[str, Any]) -> str:
        """Extract text content from MCP resource response"""
        if 'contents' not in mcp_response:
            return ""
        
        text_parts = []
        for item in mcp_response['contents']:
            if 'text' in item:
                text_parts.append(str(item['text']))
        
        return ' '.join(text_parts)

    async def run(
        self,
        adapter,
        scope: Optional[Any] = None,
        profile: Optional[Any] = None
    ) -> DetectionResult:
        """
        ACTIVE TEST: Actually attempts to exploit prompt injection.
        
        Steps:
        1. List all resources
        2. Find parameterized resources (e.g., "notes://{user_id}")
        3. For each parameterized resource:
           a. Generate unique canary marker
           b. Send canary as parameter value
           c. Read response
           d. Check if canary appears in response
           e. If yes → VULNERABILITY CONFIRMED
        """
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'resources_tested': 0,
            'parameterized_resources_found': 0,
            'vulnerable_resources': [],
            'exploit_attempts': [],
            'confirmations': []
        }
        start_time = datetime.now(timezone.utc)
        pocs: List[ProofOfConcept] = []

        try:
            # Step 1: List all available resources
            print("  [ACTIVE] Listing resources to find injection points...")
            resources = await adapter.list_resources()
            evidence['resources_tested'] = len(resources)

            if not resources:
                return DetectionResult(
                    detector_id=self.metadata.id,
                    detector_name=self.metadata.name,
                    detector_version=self.metadata.version,
                    status=DetectionStatus.ABSENT,
                    confidence=0.8,
                    evidence={"reason": "No resources available to test"},
                    standards=self.metadata.standards,
                    timestamp=start_time
                )

            # Step 2: Find parameterized resources
            # NOTE: Parameterized resources like "notes://{user_id}" may not appear
            # in list_resources(), so we need to test known template patterns
            
            parameterized = [
                r for r in resources 
                if self._is_parameterized_resource(str(r.get('uri', '')))
            ]
            
            # Additionally, try known vulnerable templates
            # Since "notes://{user_id}" exists but isn't in list_resources(), test it directly
            known_vulnerable_templates = [
                "notes://{user_id}",  # DV-MCP Challenge 1
            ]
            
            # Try each template
            for template in known_vulnerable_templates:
                # Try to construct a test URI
                params = self._extract_parameters(template)
                if params:
                    parameterized.append({'uri': template, 'source': 'known_template', 'params': params})
            
            evidence['parameterized_resources_found'] = len(parameterized)
            
            print(f"  [ACTIVE] Found {len(parameterized)} parameterized resources to test")

            # Step 3: ACTIVE EXPLOITATION - Send payloads and verify
            for resource in parameterized:
                resource_uri = str(resource.get('uri', ''))
                params = self._extract_parameters(resource_uri)
                
                if not params:
                    continue  # Skip if we can't extract parameters
                
                print(f"  [ACTIVE] Testing injection point: {resource_uri}")
                print(f"           Parameters: {params}")
                
                # Generate unique canary for this test
                canary = self._generate_canary()
                
                # Construct the exploit URI by replacing first parameter with canary
                test_uri = resource_uri.replace(f'{{{params[0]}}}', canary)
                
                print(f"           Sending canary: {canary}")
                print(f"           Request URI: {test_uri}")
                
                try:
                    # ACTIVE ATTACK: Send the canary and get response
                    response = await adapter.read_resource(test_uri)
                    
                    # Extract text from response
                    response_text = self._extract_text_from_response(response)
                    
                    print(f"           Response length: {len(response_text)} chars")
                    print(f"           Checking for canary reflection...")
                    
                    # CRITICAL CHECK: Does the response contain our canary?
                    if canary in response_text:
                        # ✅ VULNERABILITY CONFIRMED!
                        print(f"  [CONFIRMED] VULNERABILITY CONFIRMED: Canary reflected in response!")
                        
                        evidence['vulnerable_resources'].append({
                            'resource_uri': resource_uri,
                            'test_uri': test_uri,
                            'canary': canary,
                            'parameter': params[0],
                            'response_preview': response_text[:200]
                        })
                        
                        # Emit signal for confirmed vulnerability
                        signals.append(Signal(
                            type=SignalType.REFLECTION,
                            value=True,
                            context={
                                'resource_uri': resource_uri,
                                'parameter': params[0],
                                'canary': canary,
                                'attack_type': 'injection_test',
                                'vulnerable': True,
                                'proof': f"Canary '{canary}' reflected in server response"
                            }
                        ))
                        
                        # Create PoC showing the exploit
                        pocs.append(ProofOfConcept(
                            target=resource_uri,
                            attack_type="active_injection_test",
                            payload={
                                "method": "read_resource",
                                "uri": test_uri,
                                "canary_injected": canary,
                                "parameter": params[0]
                            },
                            response={
                                "canary_found": canary in response_text,
                                "response_preview": response_text[:300],
                                "vulnerable": True
                            },
                            success=True,
                            impact_demonstrated=(
                                f"CONFIRMED VULNERABILITY: Server reflects unsanitized input. "
                                f"Injected canary '{canary}' appears in response. "
                                f"This proves the server does not validate/sanitize parameter values."
                            )
                        ))
                        
                        evidence['confirmations'].append({
                            'canary': canary,
                            'confirmed': True,
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        })
                        
                    else:
                        # Canary not found - server may be safe (or filtered)
                        print(f"  [SAFE] Canary not reflected")
                        evidence['exploit_attempts'].append({
                            'resource_uri': resource_uri,
                            'canary': canary,
                            'reflected': False
                        })

                except Exception as e:
                    print(f"  [ERROR] Error during active test: {e}")
                    # Error during exploitation attempt
                    pass

            # Step 4: Determine result
            if evidence['confirmations']:
                status = DetectionStatus.PRESENT
                confidence = 0.98  # Very high confidence when we confirmed it
                print(f"  [!] ACTIVE CONFIRMATION: Found {len(evidence['confirmations'])} vulnerable resources!")
            elif evidence['parameterized_resources_found'] == 0:
                status = DetectionStatus.ABSENT
                confidence = 0.9  # High confidence when no injection points exist
                print(f"  [OK] No injection points found")
            else:
                status = DetectionStatus.ABSENT
                confidence = 0.6  # Medium confidence - tested but no reflection
                print(f"  [OK] Tested but no vulnerabilities confirmed")

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
            print(f"  [✗] Detector error: {e}")
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

