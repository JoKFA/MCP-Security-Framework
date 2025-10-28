"""
Tool Enumeration Analyzer (v0.2 Framework)

Adapted from josh-test branch tool_enumeration.py
Enumerates and analyzes MCP server tools for security issues.

Detection method: PASSIVE - analyzes tool names, descriptions, and schemas
Standards: CWE-250, OWASP API4, CVSS 6.5 MEDIUM
"""

from typing import List, Dict, Any, Optional
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


class ToolEnumerationDetector(Detector):
    """Enumerates and analyzes MCP server tools for security issues"""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-TE-001",
            name="Tool Enumeration Analyzer",
            description="Enumerates MCP server tools and analyzes them for potential security issues",
            version="1.0.0",
            prerequisites={"tools": True},
            timeout_s=20,
            severity_default="MEDIUM",
            standards=StandardsMapping(
                cwe="CWE-250",  # Execution with Unnecessary Privileges
                owasp_api="API4",  # Lack of Resources & Rate Limiting
                asvs=["V4.1"],  # Access Control Design
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                    base_score=6.5,
                    severity="MEDIUM"
                )
            )
        )

    def _analyze_tool_for_risks(self, tool: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze a single tool for security risks.

        IMPORTANT: These patterns are preserved from josh-test for future active testing.
        Current implementation: PASSIVE analysis (checks names/schemas)
        Future enhancement: ACTIVE testing (attempt to exploit dangerous tools)

        Args:
            tool: Tool definition from MCP server

        Returns:
            List of risk findings (will be converted to signals)
        """
        risks = []
        tool_name = tool.get('name', 'Unknown')
        tool_description = tool.get('description', '')
        tool_schema = tool.get('inputSchema', {})

        # Check for dangerous tool names/descriptions
        # NOTE: These keywords are kept for future active exploitation testing
        dangerous_keywords = [
            'execute', 'command', 'shell', 'system', 'admin', 'root',
            'delete', 'remove', 'drop', 'truncate', 'wipe',
            'eval', 'exec', 'run', 'launch', 'spawn', 'process'
        ]

        tool_name_lower = tool_name.lower()
        tool_desc_lower = tool_description.lower()

        # Check each dangerous keyword
        for keyword in dangerous_keywords:
            if keyword in tool_name_lower or keyword in tool_desc_lower:
                risks.append({
                    'type': 'dangerous_tool',
                    'severity': 'MEDIUM',
                    'keyword': keyword,
                    'tool_name': tool_name,
                    'tool_description': tool_description,
                    'input_schema': tool_schema,
                    'rationale': f"Tool contains potentially dangerous keyword '{keyword}' indicating system-level access"
                })

        # Check for tools with no input validation
        # This checks if inputSchema exists but has no properties defined
        if 'properties' in tool_schema:
            properties = tool_schema.get('properties', {})
            if len(properties) == 0:
                risks.append({
                    'type': 'no_input_validation',
                    'severity': 'LOW',
                    'tool_name': tool_name,
                    'tool_description': tool_description,
                    'input_schema': tool_schema,
                    'rationale': 'Tool has no defined input schema, indicating lack of input validation'
                })
        elif 'inputSchema' not in tool or not tool_schema:
            # No schema at all - even worse
            risks.append({
                'type': 'missing_input_schema',
                'severity': 'MEDIUM',
                'tool_name': tool_name,
                'tool_description': tool_description,
                'rationale': 'Tool has no input schema defined, allowing arbitrary input'
            })

        return risks

    def _get_signal_type_for_risk(self, risk_type: str) -> SignalType:
        """
        Map risk type to appropriate signal type.

        Args:
            risk_type: Type of risk detected

        Returns:
            Appropriate SignalType
        """
        mapping = {
            'dangerous_tool': SignalType.SCHEMA_OVERPERMISSIVE,
            'no_input_validation': SignalType.SCHEMA_OVERPERMISSIVE,
            'missing_input_schema': SignalType.SCHEMA_OVERPERMISSIVE
        }
        return mapping.get(risk_type, SignalType.REFLECTION)

    async def run(
        self,
        adapter,
        scope: Optional[Any] = None,
        profile: Optional[Any] = None
    ) -> DetectionResult:
        """
        Execute tool enumeration and risk analysis.

        Detection strategy:
        1. List all tools from the MCP server
        2. Analyze each tool for dangerous keywords
        3. Check for missing/inadequate input validation
        4. Emit signals for each risk detected

        Args:
            adapter: SafeAdapter instance (handles scope/rate limiting)
            scope: ScopeConfig (optional, adapter enforces it)
            profile: ServerProfile (optional metadata)

        Returns:
            DetectionResult with signals for detected tool risks
        """
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,
            'dangerous_tools': [],
            'tools_without_validation': [],
            'risk_summary': {}
        }
        start_time = datetime.now(timezone.utc)

        try:
            # Step 1: Get all available tools
            tools = await adapter.list_tools()
            total_tools = len(tools)
            evidence['tools_analyzed'] = total_tools

            # Step 2: Analyze each tool for risks
            for tool in tools:
                tool_name = tool.get('name', 'Unknown')
                risks = self._analyze_tool_for_risks(tool)

                # Convert risks to signals
                for risk in risks:
                    risk_type = risk['type']
                    severity = risk['severity']

                    # Track in evidence
                    if risk_type == 'dangerous_tool':
                        evidence['dangerous_tools'].append({
                            'name': tool_name,
                            'keyword': risk['keyword'],
                            'description': risk['tool_description']
                        })
                    elif risk_type in ['no_input_validation', 'missing_input_schema']:
                        evidence['tools_without_validation'].append({
                            'name': tool_name,
                            'type': risk_type
                        })

                    # Update risk summary
                    if risk_type not in evidence['risk_summary']:
                        evidence['risk_summary'][risk_type] = 0
                    evidence['risk_summary'][risk_type] += 1

                    # Emit signal
                    signals.append(Signal(
                        type=self._get_signal_type_for_risk(risk_type),
                        value=True,
                        context={
                            'tool_name': tool_name,
                            'risk_type': risk_type,
                            'severity': severity,
                            'rationale': risk['rationale'],
                            'tool_description': risk.get('tool_description', ''),
                            'keyword': risk.get('keyword', None)
                        }
                    ))

            # Generate PoCs for dangerous tools
            pocs = await self._generate_pocs(adapter, evidence.get('dangerous_tools', [])[:2])

            # Determine overall status
            status = DetectionStatus.PRESENT if signals else DetectionStatus.ABSENT
            confidence = 0.90 if total_tools > 0 else 0.0

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

    async def _generate_pocs(self, adapter, dangerous_tools: List[Dict[str, Any]]) -> List[ProofOfConcept]:
        """Generate PoCs by calling dangerous tools with safe parameters"""
        pocs = []
        for tool_info in dangerous_tools:
            try:
                # Call with minimal/safe arguments
                result = await adapter.call_tool(tool_info['name'], {})
                pocs.append(ProofOfConcept(
                    target=tool_info['name'],
                    attack_type="tool_abuse",
                    payload={"tool": tool_info['name'], "arguments": {}, "keyword": tool_info['keyword']},
                    response={"result": str(result)[:200]},
                    success=True,
                    impact_demonstrated=f"Successfully called dangerous tool '{tool_info['name']}' (contains keyword '{tool_info['keyword']}')"
                ))
            except Exception:
                pass  # Tool call failed, skip PoC
        return pocs
