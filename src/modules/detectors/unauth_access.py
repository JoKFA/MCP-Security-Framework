"""
Unauthenticated Access Detector (Top 25 #5)

Detects if MCP servers are accessible without authentication.

How it works:
- Tries to list tools and resources without authentication
- If both succeed, server has no authentication (CRITICAL vulnerability)
- If either fails, server requires authentication (good)

Standards: CWE-284, OWASP API1, CVSS 10.0 CRITICAL
"""

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


class UnauthenticatedAccessDetector(Detector):
    """Detects if MCP server allows unauthenticated access (CRITICAL vulnerability)."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-UA-001",
            name="Unauthenticated Access Detector",
            description="Detects MCP servers that are accessible without authentication (Top 25 #5)",
            version="1.0.0",
            prerequisites={"tools": True, "resources": True},
            timeout_s=30,
            severity_default="CRITICAL",
            standards=StandardsMapping(
                cwe="CWE-284",
                owasp_api="API1",
                asvs=["V1.1"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=10.0,
                    severity="CRITICAL"
                )
            )
        )

    async def run(
        self,
        adapter: Any,
        scope: Optional[Any] = None,
        profile: Optional[Any] = None
    ) -> DetectionResult:
        """
        Main function - checks if server requires authentication.
        
        Flow: Try to list tools/resources → Check if auth required → Report findings
        """
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_accessible': False,
            'resources_accessible': False,
            'auth_required': False
        }
        start_time = datetime.now(timezone.utc)
        pocs: List[ProofOfConcept] = []

        try:
            tools = []
            resources = []
            
            # Try to list tools without authentication
            print("  [PASSIVE] Checking if tools are accessible without authentication...")
            try:
                tools = await adapter.list_tools()
                evidence['tools_accessible'] = True
                print(f"  [!] Found {len(tools)} tools accessible without authentication")
            except Exception:
                evidence['auth_required'] = True
                print(f"  [OK] Tools require authentication")

            # Try to list resources without authentication
            print("  [PASSIVE] Checking if resources are accessible without authentication...")
            try:
                resources = await adapter.list_resources()
                evidence['resources_accessible'] = True
                print(f"  [!] Found {len(resources)} resources accessible without authentication")
            except Exception:
                evidence['auth_required'] = True
                print(f"  [OK] Resources require authentication")

            # Determine vulnerability status
            if evidence['tools_accessible'] and evidence['resources_accessible']:
                # CRITICAL: Server has no authentication
                status = DetectionStatus.PRESENT
                confidence = 0.95
                
                # Create signal (framework uses this for correlation/reporting)
                signals.append(Signal(
                    type=SignalType.AUTH_MISMATCH,
                    value=True,
                    context={
                        'tools_accessible': True,
                        'resources_accessible': True,
                        'vulnerability': 'unauthenticated_access',
                        'severity': 'CRITICAL',
                        'allows_anyone_to_access': True
                    }
                ))
                
                # Create PoC (documents the finding)
                pocs.append(ProofOfConcept(
                    target="MCP Server",
                    attack_type="unauthenticated_access_test",
                    payload={
                        "method": "list_tools and list_resources",
                        "auth_required": False
                    },
                    response={
                        "tools_count": len(tools),
                        "resources_count": len(resources),
                        "vulnerable": True
                    },
                    success=True,
                    impact_demonstrated=(
                        f"CRITICAL: Server is accessible without authentication. "
                        f"Anyone can list tools ({len(tools)}) and resources ({len(resources)}). "
                        f"This violates authentication requirements."
                    )
                ))
                print(f"  [!] CRITICAL: Server has no authentication")
                
            elif evidence['auth_required']:
                # Server requires authentication (good!)
                status = DetectionStatus.ABSENT
                confidence = 0.9
                print(f"  [OK] Server requires authentication")
            else:
                # Partial access (some endpoints unprotected)
                status = DetectionStatus.PRESENT
                confidence = 0.7
                signals.append(Signal(
                    type=SignalType.AUTH_MISMATCH,
                    value=True,
                    context={
                        'tools_accessible': evidence['tools_accessible'],
                        'resources_accessible': evidence['resources_accessible'],
                        'vulnerability': 'partial_unauthenticated_access'
                    }
                ))
                print(f"  [!] WARNING: Partial unauthenticated access")

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

