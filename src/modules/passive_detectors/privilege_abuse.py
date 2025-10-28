"""
Privilege Abuse/Overbroad Permissions Detector (Top 25 #19)

Detects tools with excessive permissions that violate the principle of least privilege.

Detection method: PASSIVE - analyzes tool schemas for permission mismatches
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


class PrivilegeAbuseDetector(Detector):
    """
    Detects tools with excessive permissions.
    
    Example: A 'calculator' tool with file system access.
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-PA-001",
            name="Privilege Abuse Detector",
            description="Detects tools with excessive permissions violating least privilege (Top 25 #19)",
            version="1.0.0",
            prerequisites={"tools": True},
            timeout_s=30,
            severity_default="MEDIUM",
            standards=StandardsMapping(
                cwe="CWE-250",
                owasp_api="API4",
                asvs=["V4.1"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                    base_score=6.5,
                    severity="MEDIUM"
                )
            )
        )

    def _get_tool_permissions(self, tool: Dict[str, Any]) -> List[str]:
        """Analyze tool to determine what permissions it might have"""
        permissions = []
        
        name = tool.get('name', '').lower()
        desc = tool.get('description', '').lower()
        schema = tool.get('inputSchema', {})
        properties = schema.get('properties', {})
        
        # Check for file system access
        if any(keyword in name or keyword in desc for keyword in ['file', 'read', 'write', 'delete', 'path', 'directory']):
            if any('path' in prop.lower() or 'file' in prop.lower() for prop in properties.keys()):
                permissions.append('file_system_access')
        
        # Check for database access
        if any(keyword in name or keyword in desc for keyword in ['database', 'query', 'sql', 'db']):
            permissions.append('database_access')
        
        # Check for network access
        if any(keyword in name or keyword in desc for keyword in ['http', 'url', 'api', 'request', 'network']):
            permissions.append('network_access')
        
        # Check for command execution
        if any(keyword in name or keyword in desc for keyword in ['execute', 'command', 'shell', 'run', 'system']):
            permissions.append('command_execution')
        
        # Check for admin operations
        if any(keyword in name or keyword in desc for keyword in ['admin', 'manage', 'config', 'setting']):
            permissions.append('administrative_access')
        
        return permissions

    def _detect_privilege_mismatch(self, tool: Dict[str, Any]) -> Optional[str]:
        """
        Detect if tool has permissions that don't match its name/description.
        
        Returns reason if mismatch detected, None otherwise.
        """
        name = tool.get('name', '').lower()
        desc = tool.get('description', '').lower()
        permissions = self._get_tool_permissions(tool)
        
        # CRITICAL: Tools with read, write, AND delete access are dangerous
        if 'write' in desc and 'delete' in desc:
            return "Tool can read, write, and delete files - violates least privilege"
        
        # Simple tools that shouldn't have broad permissions
        simple_tools = ['calculate', 'calculator', 'math', 'add', 'subtract', 'multiply', 'divide']
        if any(st in name for st in simple_tools):
            if permissions and len(permissions) > 1:
                return f"Simple calculator tool has excessive permissions: {permissions}"
            if 'file_system_access' in permissions:
                return "Calculator tool has file system access"
        
        # Weather tools shouldn't access databases
        if 'weather' in name or 'forecast' in name:
            if 'database_access' in permissions:
                return "Weather tool has database access"
        
        # Simple read tools shouldn't have write access
        if 'read' in name or 'get' in name:
            if 'write' in desc or 'delete' in desc:
                return "Read-only tool has write/delete operations"
        
        # File manager tools should have scoped permissions
        if 'file_manager' in name or 'file_manager' in desc:
            if 'read' in desc and 'write' in desc and 'delete' in desc:
                return "File manager tool has unlimited file system access (read, write, delete)"
        
        # Tools with broad capabilities
        if len(permissions) > 3:
            return f"Tool has excessive permissions: {permissions}"
        
        return None

    async def run(
        self,
        adapter: Any,
        scope: Optional[Any] = None,
        profile: Optional[Any] = None
    ) -> DetectionResult:
        """Detect tools with excessive permissions"""
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,
            'tools_with_excessive_permissions': [],
            'privilege_mismatches': []
        }
        start_time = datetime.now(timezone.utc)
        pocs: List[ProofOfConcept] = []

        try:
            print("  [PASSIVE] Analyzing tools for excessive permissions...")
            tools = await adapter.list_tools()
            evidence['tools_analyzed'] = len(tools)

            for tool in tools:
                tool_name = tool.get('name', 'Unknown')
                tool_permissions = self._get_tool_permissions(tool)
                
                # Check for privilege mismatch
                mismatch = self._detect_privilege_mismatch(tool)
                
                if mismatch:
                    print(f"  [!] Found privilege mismatch: {tool_name}")
                    print(f"      Reason: {mismatch}")
                    
                    evidence['tools_with_excessive_permissions'].append({
                        'tool_name': tool_name,
                        'description': tool.get('description', ''),
                        'permissions': tool_permissions,
                        'issue': mismatch
                    })
                    
                    evidence['privilege_mismatches'].append({
                        'tool': tool_name,
                        'reason': mismatch
                    })
                    
                    # Emit signal
                    signals.append(Signal(
                        type=SignalType.SCHEMA_OVERPERMISSIVE,
                        value=True,
                        context={
                            'tool_name': tool_name,
                            'issue': mismatch,
                            'permissions': tool_permissions,
                            'excessive': True
                        }
                    ))
                    
                    # Create PoC
                    pocs.append(ProofOfConcept(
                        target=tool_name,
                        attack_type="privilege_mismatch_detection",
                        payload={
                            "tool_name": tool_name,
                            "description": tool.get('description', ''),
                            "detected_permissions": tool_permissions
                        },
                        response={
                            "issue": mismatch,
                            "violates_least_privilege": True
                        },
                        success=True,
                        impact_demonstrated=f"Tool '{tool_name}' has excessive permissions that don't match its intended function: {mismatch}"
                    ))

            if evidence['tools_with_excessive_permissions']:
                status = DetectionStatus.PRESENT
                confidence = 0.9
                print(f"  [!] Found {len(evidence['tools_with_excessive_permissions'])} tools with excessive permissions")
            else:
                status = DetectionStatus.ABSENT
                confidence = 0.8
                print(f"  [OK] No excessive permissions detected")

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

