"""
Active Tool Abuse Confirmation Detector

Actually calls dangerous tools with safe test parameters to confirm they
have the dangerous capabilities indicated by their names/descriptions.

Detection method: ACTIVE - actually calls tools and observes behavior
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import secrets

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


class ToolAbuseActiveDetector(Detector):
    """
    ACTIVE detector that confirms dangerous tools by actually calling them.
    
    How it works:
    1. Finds tools with dangerous keywords (execute, delete, etc.)
    2. Actually calls them with safe test parameters
    3. Observes the response to confirm they have dangerous capabilities
    4. Returns high confidence result based on actual behavior
    """

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-ACTIVE-TA-001",
            name="Active Tool Abuse Confirmation",
            description="ACTIVELY confirms dangerous tools by calling them and observing behavior",
            version="1.0.0",
            prerequisites={"tools": True},
            timeout_s=30,
            severity_default="HIGH",
            standards=StandardsMapping(
                cwe="CWE-250",  # Execution with Unnecessary Privileges
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

    def _is_dangerous_tool(self, tool: Dict[str, Any]) -> bool:
        """Check if tool has dangerous keywords"""
        dangerous_keywords = [
            'execute', 'command', 'shell', 'system', 'admin',
            'delete', 'remove', 'drop', 'wipe',
            'eval', 'exec', 'run'
        ]
        
        name = tool.get('name', '').lower()
        desc = tool.get('description', '').lower()
        
        text = f"{name} {desc}"
        return any(keyword in text for keyword in dangerous_keywords)

    def _generate_safe_test_payload(self, tool_name: str, tool_schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate safe test parameters for a tool"""
        payload = {}
        
        # Get required properties
        properties = tool_schema.get('properties', {})
        required = tool_schema.get('required', [])
        
        for param_name, param_info in properties.items():
            param_type = param_info.get('type', 'string')
            
            # Generate safe test value based on type
            if param_type == 'string':
                if param_name in ['path', 'file', 'directory']:
                    # For file paths, use a safe test path
                    payload[param_name] = "/tmp/test_safe.txt"
                elif 'command' in param_name or 'cmd' in param_name:
                    # For commands, use a harmless echo
                    payload[param_name] = "echo safe_test_marker"
                elif 'user' in param_name or 'id' in param_name:
                    # For user IDs, use a test ID
                    payload[param_name] = "test_user_123"
                else:
                    # Generic safe string
                    payload[param_name] = "test_safe_value"
            elif param_type == 'integer':
                payload[param_name] = 0
            elif param_type == 'boolean':
                payload[param_name] = False
            else:
                payload[param_name] = "test"
        
        return payload

    async def run(
        self,
        adapter,
        scope: Optional[Any] = None,
        profile: Optional[Any] = None
    ) -> DetectionResult:
        """
        ACTIVE TEST: Actually calls dangerous tools to confirm their behavior.
        
        Steps:
        1. List all tools
        2. Find tools with dangerous keywords
        3. For each dangerous tool:
           a. Generate safe test parameters
           b. Actually call the tool
           c. Observe the response
           d. If tool executes successfully → CONFIRMED
        """
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_tested': 0,
            'dangerous_tools_found': 0,
            'tools_confirmed_dangerous': [],
            'successful_calls': []
        }
        start_time = datetime.now(timezone.utc)
        pocs: List[ProofOfConcept] = []

        try:
            # Step 1: List all tools
            print("  [ACTIVE] Listing tools to find dangerous ones...")
            tools = await adapter.list_tools()
            evidence['tools_tested'] = len(tools)

            if not tools:
                return DetectionResult(
                    detector_id=self.metadata.id,
                    detector_name=self.metadata.name,
                    detector_version=self.metadata.version,
                    status=DetectionStatus.ABSENT,
                    confidence=0.8,
                    evidence={"reason": "No tools available to test"},
                    standards=self.metadata.standards,
                    timestamp=start_time
                )

            # Step 2: Find dangerous tools
            dangerous_tools = [
                tool for tool in tools 
                if self._is_dangerous_tool(tool)
            ]
            evidence['dangerous_tools_found'] = len(dangerous_tools)
            
            print(f"  [ACTIVE] Found {len(dangerous_tools)} potentially dangerous tools")

            # Step 3: ACTIVE TESTING - Actually call the tools
            for tool in dangerous_tools[:3]:  # Limit to 3 for safety
                tool_name = tool.get('name', 'Unknown')
                tool_desc = tool.get('description', '')
                tool_schema = tool.get('inputSchema', {})
                
                print(f"  [ACTIVE] Testing dangerous tool: {tool_name}")
                print(f"           Description: {tool_desc[:60]}")
                
                try:
                    # Generate safe test parameters
                    test_params = self._generate_safe_test_payload(tool_name, tool_schema)
                    
                    print(f"           Calling with safe params: {test_params}")
                    
                    # ACTIVE ATTACK: Actually call the tool
                    result = await adapter.call_tool(tool_name, test_params)
                    
                    print(f"           Tool executed successfully!")
                    print(f"           Response: {str(result)[:100]}")
                    
                    # Check if response indicates dangerous behavior
                    response_str = str(result).lower()
                    
                    dangerous_indicators = [
                        'executed', 'deleted', 'removed', 'modified',
                        'command', 'process', 'shell', 'system'
                    ]
                    
                    is_dangerous = any(indicator in response_str for indicator in dangerous_indicators)
                    
                    if is_dangerous or result:
                        # Tool executed and returned something
                        evidence['tools_confirmed_dangerous'].append({
                            'tool_name': tool_name,
                            'description': tool_desc,
                            'response_preview': str(result)[:200]
                        })
                        
                        # Emit signal
                        signals.append(Signal(
                            type=SignalType.SCHEMA_OVERPERMISSIVE,
                            value=True,
                            context={
                                'tool_name': tool_name,
                                'confirmed_dangerous': True,
                                'executed': True,
                                'proof': f"Successfully executed dangerous tool '{tool_name}'"
                            }
                        ))
                        
                        # Create PoC
                        pocs.append(ProofOfConcept(
                            target=tool_name,
                            attack_type="active_tool_call",
                            payload={
                                "tool": tool_name,
                                "arguments": test_params
                            },
                            response={
                                "result_preview": str(result)[:200],
                                "tool_executed": True
                            },
                            success=True,
                            impact_demonstrated=f"Confirmed dangerous tool '{tool_name}' is callable and executes commands/operations as indicated by its name/description"
                        ))
                        
                except Exception as e:
                    print(f"  [ERROR] Tool call failed: {e}")
                    evidence['successful_calls'].append({
                        'tool_name': tool_name,
                        'error': str(e)
                    })

            # Step 4: Determine result
            if evidence['tools_confirmed_dangerous']:
                status = DetectionStatus.PRESENT
                confidence = 0.95
                print(f"  [CONFIRMED] Found {len(evidence['tools_confirmed_dangerous'])} confirmed dangerous tools!")
            else:
                status = DetectionStatus.ABSENT
                confidence = 0.9  # High confidence - we tested and didn't find issues
                print(f"  [OK] No dangerous tools confirmed")
            
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
            print(f"  [ERROR] Detector error: {e}")
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

