"""
Privilege Abuse Detector (Top 25 #19)

Detects tools with excessive permissions that violate the principle of least privilege.

How it works:
- Analyzes tool names, descriptions, and schemas
- Checks if tools have permissions that don't match their intended function
- Example: A calculator tool shouldn't have file system access

Similar to tool_enumeration.py:
- Both enumerate tools (list_tools)
- Both analyze tool metadata (names, descriptions)
- BUT: tool_enumeration flags ANY tool with dangerous keywords
- privilege_abuse flags tools where permissions DON'T MATCH their purpose

Example difference:
- tool_enumeration: "execute_command" has "execute" → Dangerous!
- privilege_abuse: "calculator" tool has file_access → Mismatch! (calculator shouldn't access files)

Standards: CWE-250, OWASP API4, CVSS 6.5 MEDIUM
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
    """Detects tools with excessive permissions that violate least privilege."""

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
        """Analyze tool name/description/schema to determine what permissions it has"""
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
        """
        Main function - analyzes tools for excessive permissions.
        
        Flow: Get tools → Infer permissions → Check for mismatches → Report findings
        
        MCP Calls Made:
        - adapter.list_tools() → Gets list of all tools
        
        What it looks for:
        - Tools where permissions don't match their purpose
        - Example: "calculator" tool with file_system_access → Mismatch!
        - Example: "read_file" tool with write/delete → Mismatch!
        - Example: Tools with too many permissions (>3 types)
        
        Difference from tool_enumeration:
        - tool_enumeration: Flags ANY tool with dangerous keywords
        - privilege_abuse: Flags tools where permissions MISMATCH their purpose
        """
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,
            'tools_with_excessive_permissions': [],
            'privilege_mismatches': []
        }
        start_time = datetime.now(timezone.utc)
        pocs: List[ProofOfConcept] = []

        try:
            # Get all tools from the server
            print("  [PASSIVE] Analyzing tools for excessive permissions...")
            tools = await adapter.list_tools()
            evidence['tools_analyzed'] = len(tools)
            print(f"  [PASSIVE] Found {len(tools)} tools")

            # Check each tool for privilege mismatches
            for tool in tools:
                tool_name = tool.get('name', 'Unknown')
                tool_permissions = self._get_tool_permissions(tool)
                
                # Check if tool has permissions that don't match its purpose
                mismatch = self._detect_privilege_mismatch(tool)
                
                if mismatch:
                    print(f"  [!] Found privilege mismatch: {tool_name}")
                    print(f"      Reason: {mismatch}")
                    
                    # Track in evidence (for reports)
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
                    
                    # Create signal (framework uses this for correlation/reporting)
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
                    
                    # Create PoC (documents the finding, not active testing)
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

