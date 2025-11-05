"""
Tool Behavior Monitor (Rug Pull Detector)

Detects: CWE-494 (Download of Code Without Integrity Check), OWASP LLM03 (Training Data Poisoning)

Detects tools that change their behavior dynamically after initial approval,
enabling "rug pull" attacks where safe tools become malicious. Works on any MCP server.

Methodology:
Phase 1 - Passive Detection:
- Lists all tools and captures initial descriptions
- Calls each tool with benign test inputs
- Re-lists tools and compares descriptions
- Detects description changes, new hidden instructions
- Identifies stateful tools that modify themselves

Phase 2 - Active PoC Generation:
- Demonstrates description changes
- Shows before/after comparison
- Captures evidence of dynamic behavior modification

Detection method: ACTIVE - repeated enumeration and comparison
Standards: CWE-494, OWASP LLM03, CVSS 7.8 HIGH
"""

import asyncio
import re
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
import hashlib
import json

from ..base import Detector
from ...core.models import (
    ModuleMetadata,
    DetectionResult,
    DetectionStatus,
    ProofOfConcept,
    Signal,
    SignalType,
    StandardsMapping,
    CVSSVector,
)


class ToolBehaviorMonitor(Detector):
    """
    Detects dynamic tool behavior changes (rug pull attacks).

    General-purpose detector for ANY MCP server.
    """

    # Number of tool calls to test for behavior changes
    TEST_ITERATIONS = 3

    # Benign test parameters for common tool types
    SAFE_TEST_PARAMS = {
        'default': {},
        'text_param': {'text': 'test', 'query': 'test', 'input': 'test'},
        'numeric_param': {'count': 1, 'limit': 1, 'page': 1, 'offset': 0},
        'boolean_param': {'enabled': False, 'active': False, 'verbose': False},
    }

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-RUG-001",
            name="Tool Behavior Monitor (Rug Pull Detector)",
            description=(
                "Detects tools that change their behavior or descriptions dynamically "
                "after initial approval, enabling rug pull attacks. Works on any MCP server."
            ),
            version="1.0.0",
            prerequisites={"tools": True},
            timeout_s=60,  # Longer timeout due to repeated calls
            severity_default="HIGH",
            standards=StandardsMapping(
                cwe="CWE-494",  # Download of Code Without Integrity Check
                owasp_llm="LLM03",  # Training Data Poisoning
                owasp_api="API8:2023",  # Security Misconfiguration
                asvs=["V14.2"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    base_score=7.8,
                    severity="HIGH",
                ),
            ),
        )

    async def run(
        self,
        adapter: Any,
        scope: Optional[Any] = None,
        profile: Optional[Any] = None,
    ) -> DetectionResult:
        """
        Execute rug pull detection.

        Strategy:
        1. Enumerate tools and capture initial state
        2. Call each tool multiple times with benign inputs
        3. Re-enumerate tools after each call
        4. Detect description/behavior changes
        5. Flag tools with dynamic modifications
        """
        mode = (scope or {}).get("mode", "balanced") if scope else "balanced"
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,
            'tools_called': 0,
            'changed_tools': [],
            'response_changes': [],
            'call_failures': [],
            'mode': mode,
        }
        start_time = datetime.now(timezone.utc)

        try:
            # Step 1: Initial enumeration
            initial_tools = await adapter.list_tools()
            evidence['tools_analyzed'] = len(initial_tools)

            # Create baseline snapshot
            baseline = self._create_tool_snapshot(initial_tools)
            baseline_responses: Dict[str, str] = {}
            recorded_response_tools: Set[str] = set()

            iteration_plan = {
                "safe": self.TEST_ITERATIONS,
                "balanced": self.TEST_ITERATIONS + 1,
                "aggressive": self.TEST_ITERATIONS + 2,
            }
            total_iterations = iteration_plan.get(mode, self.TEST_ITERATIONS + 1)

            # Step 2: Test each tool multiple times
            for iteration in range(total_iterations):
                for tool in initial_tools:
                    tool_name = tool.get('name', 'unknown')

                    try:
                        # Generate safe test parameters
                        test_params = self._generate_test_params(tool)

                        # Call tool with benign params (catch any errors)
                        try:
                            response = await adapter.call_tool(tool_name, test_params)
                            evidence['tools_called'] += 1
                        except Exception as call_error:
                            # Tool call failed, but that's okay - continue monitoring
                            evidence['call_failures'].append({
                                'tool': tool_name,
                                'iteration': iteration,
                                'error': str(call_error)[:100]
                            })

                            continue

                        response_text = self._response_to_text(response)
                        if tool_name not in baseline_responses:
                            baseline_responses[tool_name] = response_text
                        elif response_text != baseline_responses[tool_name] and tool_name not in recorded_response_tools:
                            recorded_response_tools.add(tool_name)
                            signals.append(Signal(
                                type=SignalType.SCHEMA_OVERPERMISSIVE,
                                value=True,
                                context={
                                    'tool_name': tool_name,
                                    'iteration': iteration + 1,
                                    'change_type': 'response_modified'
                                }
                            ))
                            evidence['response_changes'].append({
                                'tool_name': tool_name,
                                'iteration': iteration + 1,
                                'baseline_response': baseline_responses[tool_name][:200],
                                'modified_response': response_text[:200]
                            })
                            baseline_responses[tool_name] = response_text

                        # Re-enumerate tools to check for definition changes
                        current_tools = await adapter.list_tools()
                        current_snapshot = self._create_tool_snapshot(current_tools)

                        # Compare snapshots
                        changes = self._detect_changes(baseline, current_snapshot, tool_name)

                        if changes:
                            # Tool description/schema changed!
                            signals.append(Signal(
                                type=SignalType.SCHEMA_OVERPERMISSIVE,
                                value=True,
                                context={
                                    'tool_name': tool_name,
                                    'iteration': iteration + 1,
                                    'change_type': changes['type'],
                                    'description_changed': changes.get('description_changed', False),
                                    'schema_changed': changes.get('schema_changed', False),
                                }
                            ))

                            evidence['changed_tools'].append({
                                'tool_name': tool_name,
                                'iteration': iteration + 1,
                                'changes': changes,
                                'baseline_hash': baseline.get(tool_name, {}).get('hash'),
                                'current_hash': current_snapshot.get(tool_name, {}).get('hash')
                            })

                            # Update baseline to new state for subsequent comparisons
                            if tool_name in current_snapshot:
                                baseline[tool_name] = current_snapshot[tool_name]

                    except Exception as e:
                        # Error during testing this tool - skip it
                        continue

                if mode != "safe":
                    await asyncio.sleep(0.1 if mode == "balanced" else 0.25)

            # Step 3: Generate PoCs
            pocs = self._generate_pocs(
                evidence.get('changed_tools', []),
                evidence.get('response_changes', []),
            )

            # Determine status
            total_changes = len(evidence['changed_tools']) + len(evidence['response_changes'])
            if not signals:
                status = DetectionStatus.ABSENT
                confidence = 0.85
            else:
                status = DetectionStatus.PRESENT
                # High confidence if multiple changes detected
                confidence = min(0.95, 0.75 + (0.05 * max(1, total_changes)))

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
                remediation=(
                    "Implement immutable tool definitions: (1) Lock tool descriptions "
                    "after registration, (2) Use version control for tool changes, "
                    "(3) Require re-approval for any modifications, (4) Implement "
                    "integrity checks (hashing) to detect unauthorized changes, "
                    "(5) Log all tool definition updates with audit trail."
                ) if signals else None,
                timestamp=start_time,
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
                timestamp=start_time,
            )

    def _response_to_text(self, response: Any) -> str:
        """Normalize tool response to comparable text."""
        if isinstance(response, dict):
            content = response.get("content")
            if isinstance(content, list):
                fragments: List[str] = []
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text")
                        if text:
                            fragments.append(str(text))
                if fragments:
                    return "\n".join(fragments)
            return str(response)
        return str(response)

    def _create_tool_snapshot(self, tools: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Create a snapshot of all tools for comparison.

        Returns dict mapping tool_name to {hash, description, schema}
        """
        snapshot = {}

        for tool in tools:
            tool_name = tool.get('name', 'unknown')
            description = tool.get('description', '')
            schema = tool.get('inputSchema', {})

            # Create hash of tool definition
            tool_def = json.dumps({
                'description': description,
                'schema': schema
            }, sort_keys=True)
            tool_hash = hashlib.sha256(tool_def.encode()).hexdigest()[:16]

            snapshot[tool_name] = {
                'hash': tool_hash,
                'description': description,
                'schema': schema,
                'full_definition': tool
            }

        return snapshot

    def _detect_changes(
        self,
        baseline: Dict[str, Dict[str, Any]],
        current: Dict[str, Dict[str, Any]],
        tool_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Detect changes in a specific tool between snapshots.

        Returns dict describing changes, or None if no changes.
        """
        if tool_name not in baseline or tool_name not in current:
            return None

        baseline_tool = baseline[tool_name]
        current_tool = current[tool_name]

        # Check if hash changed
        if baseline_tool['hash'] == current_tool['hash']:
            return None

        # Hash changed - identify what changed
        changes = {
            'type': 'modification',
            'description_changed': False,
            'schema_changed': False,
            'details': []
        }

        # Check description
        if baseline_tool['description'] != current_tool['description']:
            changes['description_changed'] = True
            changes['details'].append({
                'field': 'description',
                'before': baseline_tool['description'][:200],
                'after': current_tool['description'][:200]
            })

        # Check schema
        if baseline_tool['schema'] != current_tool['schema']:
            changes['schema_changed'] = True
            changes['details'].append({
                'field': 'schema',
                'before': str(baseline_tool['schema'])[:200],
                'after': str(current_tool['schema'])[:200]
            })

        return changes if changes['details'] else None

    def _generate_test_params(self, tool: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate safe test parameters for a tool based on its schema.

        Returns minimal, benign parameters.
        """
        input_schema = tool.get('inputSchema', {})
        if not input_schema or 'properties' not in input_schema:
            return {}

        properties = input_schema.get('properties', {})
        required = input_schema.get('required', [])
        params = {}

        # Only provide required parameters with safe defaults
        for param_name in required:
            if param_name not in properties:
                continue

            param_info = properties[param_name]
            param_type = param_info.get('type', 'string')

            # Generate safe value based on type
            if param_type == 'string':
                # Check if enum exists
                if 'enum' in param_info and param_info['enum']:
                    params[param_name] = param_info['enum'][0]
                else:
                    params[param_name] = 'test'
            elif param_type == 'number' or param_type == 'integer':
                params[param_name] = 1
            elif param_type == 'boolean':
                params[param_name] = False
            elif param_type == 'array':
                params[param_name] = []
            elif param_type == 'object':
                params[param_name] = {}

        return params

    def _generate_pocs(
        self,
        changed_tools: List[Dict[str, Any]],
        response_changes: List[Dict[str, Any]],
    ) -> List[ProofOfConcept]:
        """Generate PoCs demonstrating tool behavior changes"""
        pocs = []

        for change_info in changed_tools[:3]:  # Top 3
            tool_name = change_info['tool_name']
            iteration = change_info['iteration']
            changes = change_info['changes']
            baseline_hash = change_info.get('baseline_hash', 'N/A')
            current_hash = change_info.get('current_hash', 'N/A')

            # Build change description
            change_types = []
            if changes.get('description_changed'):
                change_types.append("description modified")
            if changes.get('schema_changed'):
                change_types.append("schema modified")

            pocs.append(ProofOfConcept(
                target=tool_name,
                attack_type="rug_pull",
                payload={
                    "tool_name": tool_name,
                    "iteration": iteration,
                    "detection_method": "repeated_enumeration"
                },
                response={
                    "changes_detected": change_types,
                    "baseline_hash": baseline_hash,
                    "modified_hash": current_hash,
                    "change_details": changes.get('details', [])
                },
                success=True,
                impact_demonstrated=(
                    f"Tool '{tool_name}' changed its definition after {iteration} call(s). "
                    f"Changes: {', '.join(change_types)}. "
                    f"Hash changed from {baseline_hash} to {current_hash}. "
                    f"This indicates dynamic behavior modification (rug pull attack)."
                )
            ))

        for response_info in response_changes[:3]:
            tool_name = response_info['tool_name']
            pocs.append(ProofOfConcept(
                target=tool_name,
                attack_type="rug_pull_response",
                payload={
                    "tool_name": tool_name,
                    "iteration": response_info.get('iteration'),
                },
                response={
                    "baseline_response": response_info.get('baseline_response'),
                    "modified_response": response_info.get('modified_response'),
                },
                success=True,
                impact_demonstrated=(
                    f"Tool '{tool_name}' returned different content for identical inputs after "
                    f"{response_info.get('iteration')} invocation(s), indicating dynamic behaviour."
                )
            ))

        return pocs
