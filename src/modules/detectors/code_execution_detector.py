"""
Code Execution Detector

Detects: CWE-94 (Code Injection), OWASP LLM07 (Insecure Plugin Design)

Detects tools that execute arbitrary code without proper sandboxing or validation.
Works on any MCP server.

Methodology:
Phase 1 - Passive Detection:
- Identifies tools with code execution capabilities
- Analyzes tool schemas for dangerous parameters (code, script, eval)
- Checks for absence of sandboxing indicators
- Flags interpreters without restrictions (python, javascript, shell)

Phase 2 - Active PoC Generation (Conservative):
- Tests with benign code (arithmetic, simple output)
- Detects successful execution
- Shows lack of sandboxing/validation

Detection method: PASSIVE analysis + LIMITED ACTIVE testing with safe payloads
Standards: CWE-94, OWASP LLM07, CVSS 9.8 CRITICAL
"""

import re
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
    CVSSVector,
)


class CodeExecutionDetector(Detector):
    """
    Detects unsafe code execution capabilities.

    General-purpose detector for ANY MCP server.
    """

    # Keywords indicating code execution
    CODE_EXEC_KEYWORDS = [
        r'\bexec\b', r'\beval\b', r'\brun\b', r'\bexecute\b',
        r'\bpython\b', r'\bjavascript\b', r'\bjs\b', r'\bnode\b',
        r'\bshell\b', r'\bbash\b', r'\bcmd\b', r'\bcommand\b',
        r'\bscript\b', r'\bcode\b', r'\binterpreter\b',
        r'\brepl\b', r'\bcalculate\b'
    ]

    # Safe test payloads (benign operations only)
    SAFE_TEST_PAYLOADS = {
        'python': '1 + 1',
        'javascript': '1 + 1',
        'math': '2 * 3',
        'generic': 'print("test")'
    }
    CANARY_PAYLOAD = '__import__("os").name'

    # Dangerous parameter names
    DANGEROUS_PARAMS = {'code', 'script', 'command', 'cmd', 'eval', 'expression', 'program'}

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-CEX-001",
            name="Code Execution Detector",
            description=(
                "Detects tools that execute arbitrary code without proper sandboxing. "
                "Works on any MCP server."
            ),
            version="1.0.0",
            prerequisites={"tools": True},
            timeout_s=45,
            severity_default="CRITICAL",
            standards=StandardsMapping(
                cwe="CWE-94",  # Code Injection
                owasp_llm="LLM07",  # Insecure Plugin Design
                owasp_api="API8:2023",  # Security Misconfiguration
                asvs=["V5.2", "V5.3"],
                capec=["CAPEC-242"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    base_score=9.8,
                    severity="CRITICAL",
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
        Execute code execution detection.

        Strategy:
        1. Identify code execution tools
        2. Analyze for dangerous parameters
        3. Test with safe payloads (arithmetic only)
        4. Flag tools without sandboxing
        """
        mode = (scope or {}).get("mode", "balanced") if scope else "balanced"
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,
            'code_exec_tools': [],
            'tested_tools': [],
            'mode': mode,
        }
        start_time = datetime.now(timezone.utc)

        try:
            tools = await adapter.list_tools()
            evidence['tools_analyzed'] = len(tools)

            for tool in tools:
                tool_name = tool.get('name', '')
                description = tool.get('description', '').lower()
                schema = tool.get('inputSchema', {})

                # Check if tool has code execution capability
                combined = f"{tool_name} {description}".lower()

                is_code_exec = any(
                    re.search(keyword, combined, re.IGNORECASE)
                    for keyword in self.CODE_EXEC_KEYWORDS
                )

                if is_code_exec:
                    # Analyze schema
                    dangerous_params = self._find_dangerous_params(schema)

                    # Check for sandboxing indicators
                    has_sandbox = any(
                        word in description for word in
                        ['sandbox', 'isolated', 'restricted', 'safe', 'limited']
                    )

                    risk_score = 0.8 if not has_sandbox else 0.5
                    if dangerous_params:
                        risk_score = min(1.0, risk_score + 0.2)

                    if risk_score >= 0.7:
                        signals.append(Signal(
                            type=SignalType.SCHEMA_OVERPERMISSIVE,
                            value=True,
                            context={
                                'tool_name': tool_name,
                                'risk_score': risk_score,
                                'dangerous_params': dangerous_params,
                                'has_sandbox': has_sandbox
                            }
                        ))

                        evidence['code_exec_tools'].append({
                            'tool_name': tool_name,
                            'risk_score': risk_score,
                            'dangerous_params': dangerous_params,
                            'has_sandbox': has_sandbox
                        })

                        # Attempt safe testing
                        test_result = await self._test_code_execution(
                            adapter, tool_name, schema, mode
                        )
                        if test_result:
                            evidence['tested_tools'].append(test_result)

            # Generate PoCs
            pocs = self._generate_pocs(
                evidence.get('code_exec_tools', []),
                evidence.get('tested_tools', []),
            )

            # Determine status
            if evidence['tested_tools']:
                status = DetectionStatus.PRESENT
                confidence = 0.97
            elif signals:
                status = DetectionStatus.PRESENT
                confidence = 0.9
            else:
                status = DetectionStatus.ABSENT
                confidence = 0.85

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
                    "Secure code execution: (1) Implement strict sandboxing (containers, VMs), "
                    "(2) Whitelist allowed operations/modules, (3) Set resource limits "
                    "(CPU, memory, time), (4) Disable dangerous functions (file I/O, network, exec), "
                    "(5) Validate and sanitize all code inputs, (6) Log all executions for audit."
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

    def _find_dangerous_params(self, schema: Dict[str, Any]) -> List[str]:
        """Find dangerous parameters in tool schema"""
        dangerous = []
        properties = schema.get('properties', {})

        for param_name in properties.keys():
            if param_name.lower() in self.DANGEROUS_PARAMS:
                dangerous.append(param_name)

        return dangerous

    def _build_arguments(
        self,
        schema: Dict[str, Any],
        target_param: str,
        value: str,
    ) -> Dict[str, Any]:
        """Build argument map with safe defaults."""
        properties = schema.get('properties', {})
        required = schema.get('required', []) or []
        args: Dict[str, Any] = {}

        for name in properties.keys():
            if name == target_param:
                args[name] = value
                continue

            if name in required:
                info = properties.get(name, {})
                if 'enum' in info and info['enum']:
                    args[name] = info['enum'][0]
                else:
                    param_type = info.get('type', 'string')
                    if param_type in ('integer', 'number'):
                        args[name] = 0
                    elif param_type == 'boolean':
                        args[name] = False
                    elif param_type == 'array':
                        args[name] = []
                    elif param_type == 'object':
                        args[name] = {}
                    else:
                        args[name] = info.get('default', 'print(\"test\")')

        if target_param not in args:
            args[target_param] = value

        return args

    def _response_to_text(self, response: Any) -> str:
        """Collapse tool response to string for evaluation."""
        if isinstance(response, dict):
            content = response.get("content")
            if isinstance(content, list):
                fragments = []
                for item in content:
                    if isinstance(item, dict) and item.get("text"):
                        fragments.append(str(item["text"]))
                if fragments:
                    return "\n".join(fragments)
            return str(response)
        return str(response)

    async def _test_code_execution(
        self,
        adapter: Any,
        tool_name: str,
        schema: Dict[str, Any],
        mode: str,
    ) -> Optional[Dict[str, Any]]:
        """Test code execution with safe payloads and canary instructions."""
        try:
            dangerous_params = self._find_dangerous_params(schema)
            if not dangerous_params:
                return None

            param_name = dangerous_params[0]
            arguments = self._build_arguments(schema, param_name, self.SAFE_TEST_PAYLOADS['python'])
            if not arguments:
                return None

            baseline_response = await adapter.call_tool(tool_name, arguments)
            baseline_text = self._response_to_text(baseline_response).lower()
            if not any(indicator in baseline_text for indicator in ['2', 'result', 'output', 'success']):
                return None

            result: Dict[str, Any] = {
                'tool_name': tool_name,
                'parameter': param_name,
                'baseline_payload': arguments[param_name],
                'baseline_response': baseline_text[:200],
            }

            if mode == "safe":
                return result

            arguments[param_name] = self.CANARY_PAYLOAD
            try:
                canary_response = await adapter.call_tool(tool_name, arguments)
            except Exception:
                return result

            canary_text = self._response_to_text(canary_response).lower()
            if any(marker in canary_text for marker in ['posix', 'nt', 'linux', 'win32']):
                result.update({
                    'canary_payload': self.CANARY_PAYLOAD,
                    'canary_response': canary_text[:200],
                    'canary_success': True,
                })

            return result

        except Exception:
            return None

    def _generate_pocs(
        self,
        code_exec_tools: List[Dict[str, Any]],
        tested_tools: List[Dict[str, Any]],
    ) -> List[ProofOfConcept]:
        """Generate PoCs for code execution"""
        pocs = []

        for item in tested_tools[:3]:
            tool_name = item['tool_name']
            pocs.append(ProofOfConcept(
                target=tool_name,
                attack_type="code_execution_active",
                payload={
                    "parameter": item.get('parameter'),
                    "baseline_payload": item.get('baseline_payload'),
                    "canary_payload": item.get('canary_payload'),
                },
                response={
                    "baseline_response": item.get('baseline_response'),
                    "canary_response": item.get('canary_response'),
                    "canary_success": item.get('canary_success', False),
                },
                success=True,
                impact_demonstrated=(
                    f"Tool '{tool_name}' executed supplied code snippet and returned interpreter output. "
                    f"Canary success: {item.get('canary_success', False)}."
                )
            ))

        for tool in code_exec_tools[:3]:
            tool_name = tool['tool_name']
            risk_score = tool['risk_score']
            dangerous_params = tool['dangerous_params']
            has_sandbox = tool['has_sandbox']

            pocs.append(ProofOfConcept(
                target=tool_name,
                attack_type="code_execution",
                payload={
                    "tool_name": tool_name,
                    "dangerous_params": dangerous_params,
                    "test_code": "1 + 1"
                },
                response={
                    "risk_score": risk_score,
                    "has_sandboxing": has_sandbox,
                    "impact": "Arbitrary code execution without restrictions"
                },
                success=True,
                impact_demonstrated=(
                    f"Tool '{tool_name}' executes arbitrary code via parameter(s): "
                    f"{', '.join(dangerous_params)}. "
                    f"{'No sandboxing detected' if not has_sandbox else 'Limited sandboxing'}. "
                    f"Risk score: {risk_score:.0%}. Attacker can execute malicious code, "
                    f"access files, exfiltrate data, or compromise the system."
                )
            ))

        return pocs
