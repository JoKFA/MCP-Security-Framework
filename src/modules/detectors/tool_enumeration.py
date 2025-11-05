"""
Tool Enumeration Detector

What this does:
- Looks at all the tools an MCP server exposes
- Checks if any tools are dangerous or have bad security practices
- Flags tools based on metadata (names, descriptions, schemas) - no active testing

How it works:
PASSIVE ONLY: Just looking at the tool names and descriptions (metadata analysis)
No active testing - we can't prove danger with safe test parameters

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
    """
    This detector finds dangerous tools on MCP servers.
    
    Basically, we look at what tools the server exposes and check if they're sketchy.
    """

    """
    REQUIRED: This property tells the framework everything about this detector.
    
    This MUST follow this exact format - it's required by the base Detector class.
    
    Who reads this:
    - Registry (registry.py): Discovers detectors and reads detector.id, detector.name
    - Runner (runner.py): Checks prerequisites, sets timeouts, generates reports
    - Reports: Uses detector.id, detector.name, standards for report generation
    
    What it does:
    - Returns a ModuleMetadata object with detector info
    - Registry calls: instance.metadata.id to get detector ID
    - Runner calls: instance.metadata.prerequisites to check if it can run
    - Runner calls: instance.metadata.timeout_s to enforce timeouts
    
    Why @property?
    - Makes it accessible like a variable: detector.metadata (no parentheses needed)
    - Creates a fresh ModuleMetadata object each time it's accessed
    - Required by the abstract base class (Detector) - all detectors must have this
    """
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-TE-001",
            name="Tool Enumeration Analyzer",
            description="Finds dangerous tools on MCP servers",
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

    # ============================================================================
    # PASSIVE PHASE - Just looking at tool metadata, no actual calling
    # ============================================================================

    # Passive
    # Checks for dangerous keywords in name/description
    # Checks for missing input validation
    def _analyze_tool_for_risks(self, tool: Dict[str, Any]) -> List[Dict[str, Any]]:
        
        issues = []
        # Extract tool info from the tool object
        # 
        # MCP Tool fields (per official MCP protocol spec):
        # - name: REQUIRED - Unique identifier (e.g., "calculator_arithmetic")
        # - description: REQUIRED - Detailed explanation of what the tool does
        # - inputSchema: REQUIRED - JSON Schema defining expected input parameters
        # - title: OPTIONAL - Human-readable display name (e.g., "Calculator")
        #
        # NOTE: Our adapter (mcp_client_adapter.py) only extracts name, description, inputSchema.
        # The 'title' field exists in the protocol but our adapter doesn't extract it.
        # If a field doesn't exist, .get() returns the default value (second parameter)
        
        tool_name = tool.get('name', 'Unknown')           # REQUIRED - Tool identifier
        tool_description = tool.get('description', '')    # REQUIRED - Tool description
        tool_schema = tool.get('inputSchema', {})         # REQUIRED - Parameter schema (can be empty/missing = bad!)
        
        # Check for dangerous keywords
        dangerous_keywords = [
            'execute', 'command', 'shell', 'system', 'admin', 'root',
            'delete', 'remove', 'drop', 'truncate', 'wipe',
            'eval', 'exec', 'run', 'launch', 'spawn', 'process'
        ]
        
        
        # Combine name and description into one string (lowercase for case-insensitive search)
        text = f"{tool_name.lower()} {tool_description.lower()}"
        
        # Check if any dangerous keywords appear in the tool name or description
        for keyword in dangerous_keywords:
            if keyword in text:
                # Found a dangerous keyword! Add it to our issues list
                issues.append({
                    'type': 'dangerous_tool',
                    'severity': 'MEDIUM',
                    'keyword': keyword,  # Which keyword we found (e.g., "execute")
                    'tool_name': tool_name,
                    'tool_description': tool_description,
                    'input_schema': tool_schema,
                    'rationale': f"Tool has '{keyword}' in name/description - sketchy!"
                })
        
        # Check for missing input validation
        # We're checking the STRUCTURE of the inputSchema (not looping through keywords)
        # 
        # A good tool should have an inputSchema that defines what parameters it accepts.
        # Example of GOOD schema:
        #   {
        #     "properties": {
        #       "command": {"type": "string"},
        #       "timeout": {"type": "integer"}
        #     }
        #   }
        #
        # If the schema is missing or empty, the tool might accept ANY input (bad!)
        
        # Case 1: Schema exists but has no properties (empty schema)
        # Example: {"properties": {}}  ← empty!
        if 'properties' in tool_schema:
            if len(tool_schema.get('properties', {})) == 0:
                # Schema exists but is empty - tool accepts any input!
                issues.append({
                    'type': 'no_input_validation',
                    'severity': 'LOW',
                    'tool_name': tool_name,
                    'tool_description': tool_description,
                    'rationale': 'Tool has empty input schema - accepts anything!'
                })
    
        # Case 2: No schema at all (even worse!)
        # Example: tool_schema = {}  ← completely missing!
        elif not tool_schema:
            issues.append({
                'type': 'missing_input_schema',
                'severity': 'MEDIUM',
                'tool_name': tool_name,
                'tool_description': tool_description,
                'rationale': 'Tool has no input schema - could accept malicious input'
            })
        
        return issues








    # ============================================================================
    # MAIN RUN FUNCTION - This is what gets called
    # ============================================================================

    async def run(
        self,
        adapter,
        scope: Optional[Any] = None,
        profile: Optional[Any] = None
    ) -> DetectionResult:
    
        """
        Main function - analyzes tools for security issues.
        
        Flow: Get tools → Analyze each one → Report findings
        Returns a DetectionResult with all the issues we found.
        
        ========================================================================
        HOW IT WORKS - EXPLAINED:
        ========================================================================
        
        1. SIGNALS: Framework uses these to build attack chains and generate reports
           - Each security issue creates one Signal object
           - Example: Found "execute_command" → creates 1 signal
           - Framework's correlator reads signals from ALL detectors to build attack chains
           - Signals appear in reports as "findings"
        
        2. EVIDENCE: Raw data we collected (for reports and debugging)
           - This is what we actually found - tools, counts, summaries
           - Example: {'dangerous_tools': [{'name': 'execute_command'}], 'tools_analyzed': 5}
           - Reports display this so users can see exactly what we found
        
        3. SIGNAL_MAPPING: Converts our internal risk types → framework signal types
           - Framework has standard signal types (REFLECTION, SCHEMA_OVERPERMISSIVE, etc.)
           - We map our risks to those standard types
           - Example: risk_type='dangerous_tool' → SignalType.SCHEMA_OVERPERMISSIVE
           - (because dangerous tools violate "least privilege" principle)
        
        ========================================================================
        """
        # ========================================================================
        # SETUP: Initialize data structures
        # ========================================================================
        
        # Signals: Framework uses these to build attack chains and generate reports
        # Each security issue creates one Signal object
        # Example: Found "execute_command" → creates 1 signal
        # Framework's correlator reads signals from ALL detectors to build attack chains
        signals: List[Signal] = []
        
        # Evidence: Raw data we collected (for reports and debugging)
        # This is what we actually found - tools, counts, summaries
        # Example: {'dangerous_tools': [{'name': 'execute_command'}], 'tools_analyzed': 5}
        # Reports display this so users can see exactly what we found
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,                    # How many tools total
            'dangerous_tools': [],                   # List of dangerous tools we found
            'tools_without_validation': [],          # Tools missing input validation
            'risk_summary': {}                       # Count of each risk type (e.g., {'dangerous_tool': 2})
        }
        start_time = datetime.now(timezone.utc)

        # Signal Mapping: Converts our internal risk types → framework signal types
        # Framework has standard signal types (REFLECTION, SCHEMA_OVERPERMISSIVE, etc.)
        # We map our risks to those standard types
        # Example: risk_type='dangerous_tool' → SignalType.SCHEMA_OVERPERMISSIVE
        # (because dangerous tools violate "least privilege" principle)
        signal_mapping = {
            'dangerous_tool': SignalType.SCHEMA_OVERPERMISSIVE,           # Tool has dangerous capabilities
            'no_input_validation': SignalType.SCHEMA_OVERPERMISSIVE,      # Tool accepts any input
            'missing_input_schema': SignalType.SCHEMA_OVERPERMISSIVE      # Tool has no schema defined
        }

        try:
            # Get all tools from the server
            print("  [PASSIVE] Getting list of all tools...")
            tools = await adapter.list_tools()
            evidence['tools_analyzed'] = len(tools)
            print(f"  [PASSIVE] Found {len(tools)} tools")

            # Analyze each tool for security issues
            print("  [PASSIVE] Analyzing tools for security issues...")
            for tool in tools:
                tool_name = tool.get('name', 'Unknown')
                risks = self._analyze_tool_for_risks(tool)

                # For each risk found, we do 3 things:
                # 1. Track it in evidence (for reports) - so users can see what we found
                # 2. Count it (for summary statistics) - e.g., "Found 2 dangerous tools"
                # 3. Create a signal (for framework correlation) - so framework can build attack chains
                for risk in risks:
                    risk_type = risk['type']  # e.g., 'dangerous_tool', 'no_input_validation'
                    
                    # --- Track in evidence (for reports) ---
                    # Reports display this so users can see what we found
                    if risk_type == 'dangerous_tool':
                        evidence['dangerous_tools'].append({
                            'name': tool_name,
                            'keyword': risk['keyword'],          # Which keyword we found (e.g., "execute")
                            'description': risk['tool_description']
                        })
                        print(f"  [!] Found dangerous tool: {tool_name} (keyword: {risk['keyword']})")
                    elif risk_type in ['no_input_validation', 'missing_input_schema']:
                        evidence['tools_without_validation'].append({'name': tool_name, 'type': risk_type})
                        print(f"  [!] Tool missing input validation: {tool_name}")

                    # --- Count it (for summary statistics) ---
                    # Example: If we find 2 dangerous tools, risk_summary['dangerous_tool'] = 2
                    evidence['risk_summary'][risk_type] = evidence['risk_summary'].get(risk_type, 0) + 1
                    
                    # --- Create signal (for framework correlation) ---
                    # Signals are what the framework uses to:
                    # - Build attack chains (combine signals from multiple detectors)
                    # - Generate reports (signals appear in report findings)
                    # - Correlate findings (if multiple detectors find similar issues)
                    signals.append(Signal(
                        type=signal_mapping.get(risk_type, SignalType.REFLECTION),  # Map our risk → standard signal type
                        value=True,  # Boolean: True = issue found, False = no issue
                        context={  # Extra info about the finding (appears in reports)
                            'tool_name': tool_name,
                            'risk_type': risk_type,
                            'severity': risk['severity'],           # e.g., "MEDIUM", "LOW"
                            'rationale': risk['rationale'],        # Why we flagged it (e.g., "Tool has 'execute' in name")
                            'tool_description': risk.get('tool_description', ''),
                            'keyword': risk.get('keyword', None)    # Which keyword matched (e.g., "execute")
                        }
                    ))

            # Build result
            return DetectionResult(
                detector_id=self.metadata.id,
                detector_name=self.metadata.name,
                detector_version=self.metadata.version,
                status=DetectionStatus.PRESENT if signals else DetectionStatus.ABSENT,
                confidence=0.90 if evidence['tools_analyzed'] > 0 else 0.0,
                signals=signals,
                proof_of_concepts=[],
                evidence=evidence,
                standards=self.metadata.standards,
                timestamp=start_time
            )

        except Exception as e:
            print(f"  [ERROR] Detector failed: {e}")
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
