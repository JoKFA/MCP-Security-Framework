"""
Command Injection Detector

Detects: CWE-78 (OS Command Injection), OWASP API8 (Security Misconfiguration)

Detects tools that execute system commands with unsanitized user input,
enabling command injection attacks. Works on any MCP server.

Methodology:
Phase 1 - Passive Detection:
- Identifies tools that execute system commands
- Analyzes for command parameters without validation
- Checks tool descriptions for network/system utilities
- Flags tools with shell/exec capabilities

Phase 2 - Active PoC Generation (Conservative):
- Tests with benign command injection attempts (echo, simple queries)
- Detects lack of input sanitization
- Shows exploitation potential

Detection method: PASSIVE analysis + LIMITED ACTIVE testing with safe payloads
Standards: CWE-78, OWASP API8, CVSS 9.8 CRITICAL
"""

import re
from typing import List, Dict, Any, Optional, Tuple
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


class CommandInjectionDetector(Detector):
    """
    Detects command injection vulnerabilities.

    General-purpose detector for ANY MCP server.
    """

    # Keywords indicating system command execution
    COMMAND_EXEC_KEYWORDS = [
        r'\bping\b', r'\btraceroute\b', r'\bnslookup\b', r'\bdig\b',
        r'\bwhois\b', r'\bcurl\b', r'\bwget\b', r'\bnetstat\b',
        r'\bnetwork\b', r'\bdiagnostic\b', r'\bsystem\b', r'\bshell\b',
        r'\bcommand\b', r'\bcmd\b', r'\bexec\b', r'\bprocess\b'
    ]

    # Tools commonly vulnerable to injection
    VULNERABLE_TOOL_PATTERNS = [
        'ping', 'traceroute', 'nslookup', 'dig', 'whois',
        'network', 'diagnostic', 'dns', 'lookup'
    ]

    # Dangerous parameter names
    INJECTION_PARAMS = {
        'host', 'hostname', 'target', 'address', 'ip',
        'domain', 'url', 'command', 'cmd', 'query',
        'args', 'arguments', 'options', 'flags'
    }

    CANARY_TOKEN = "MCPSF_CMD_POC"
    TEST_BASE_INPUT = "127.0.0.1"
    INJECTION_TEMPLATES = [
        "{base}",
        "{base}; echo {marker}",
        "{base} && echo {marker}",
        "{base} | echo {marker}",
        "`echo {marker}`",
    ]

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-CI-001",
            name="Command Injection Detector",
            description=(
                "Detects OS command injection vulnerabilities in tools that execute "
                "system commands. Works on any MCP server."
            ),
            version="1.0.0",
            prerequisites={"tools": True},
            timeout_s=60,
            severity_default="CRITICAL",
            standards=StandardsMapping(
                cwe="CWE-78",  # OS Command Injection
                owasp_llm="LLM07",  # Insecure Plugin Design
                owasp_api="API8:2023",  # Security Misconfiguration
                asvs=["V5.2", "V5.3"],
                capec=["CAPEC-88"],
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
        Execute command injection detection.

        Strategy:
        1. Identify command execution tools
        2. Analyze for injection-prone parameters
        3. Test with safe injection payloads (echo only)
        4. Flag tools vulnerable to injection
        """
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,
            'command_tools': [],
            'vulnerable_tools': [],
            'mode': (scope or {}).get("mode", "balanced") if scope else "balanced",
        }
        start_time = datetime.now(timezone.utc)
        confirmed: List[Dict[str, Any]] = []

        mode = evidence['mode']
        passive_thresholds = {
            "safe": 0.8,
            "balanced": 0.65,
            "aggressive": 0.5,
        }
        passive_threshold = passive_thresholds.get(mode, 0.65)
        exploit_enabled = mode != "safe"

        try:
            tools = await adapter.list_tools()
            evidence['tools_analyzed'] = len(tools)

            for tool in tools:
                tool_name = tool.get('name', '')
                description = tool.get('description', '').lower()
                schema = tool.get('inputSchema', {})

                combined = f"{tool_name} {description}".lower()
                is_command_tool = any(
                    re.search(keyword, combined, re.IGNORECASE)
                    for keyword in self.COMMAND_EXEC_KEYWORDS
                )

                if not is_command_tool:
                    continue

                injection_params = self._find_injection_params(schema)
                risk_score, reasons, has_validation = self._score_command_tool(
                    combined,
                    schema,
                    injection_params,
                )
                flagged = risk_score >= passive_threshold

                tool_record = {
                    'tool_name': tool_name,
                    'risk_score': risk_score,
                    'injection_params': injection_params,
                    'has_validation': has_validation,
                    'flagged': flagged,
                    'risk_reasons': reasons,
                }
                evidence['command_tools'].append(tool_record)

                signal_emitted = False
                if flagged:
                    signals.append(Signal(
                        type=SignalType.SCHEMA_OVERPERMISSIVE,
                        value=True,
                        context={
                            'tool_name': tool_name,
                            'risk_score': round(risk_score, 2),
                            'injection_params': injection_params,
                            'has_validation': has_validation,
                            'mode': mode,
                        }
                    ))
                    signal_emitted = True

                test_result = None
                if exploit_enabled and injection_params:
                    test_result = await self._test_command_injection(
                        adapter,
                        tool_name,
                        schema,
                        injection_params,
                    )
                    if test_result:
                        test_result['risk_score'] = risk_score
                        evidence['vulnerable_tools'].append(test_result)
                        confirmed.append(test_result)
                        if not signal_emitted:
                            signals.append(Signal(
                                type=SignalType.SCHEMA_OVERPERMISSIVE,
                                value=True,
                                context={
                                    'tool_name': tool_name,
                                    'risk_score': round(max(risk_score, 0.7), 2),
                                    'injection_params': injection_params,
                                    'has_validation': has_validation,
                                    'mode': mode,
                                    'exploit': 'canary_succeeded'
                                }
                            ))
                            signal_emitted = True
                        tool_record['flagged'] = True


            pocs = self._generate_pocs(
                evidence.get('vulnerable_tools', []),
                evidence.get('command_tools', []),
            )

            flagged_tools = [t for t in evidence['command_tools'] if t.get('flagged')]
            if confirmed:
                status = DetectionStatus.PRESENT
                confidence = 0.98
            elif flagged_tools:
                status = DetectionStatus.PRESENT
                max_risk = max(tool['risk_score'] for tool in flagged_tools)
                confidence = min(0.95, 0.6 + (max_risk * 0.35))
            elif evidence['command_tools']:
                status = DetectionStatus.ABSENT
                confidence = 0.7
            else:
                status = DetectionStatus.ABSENT
                confidence = 0.9

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
                    "Prevent command injection: (1) Never pass user input directly to system commands, "
                    "(2) Use parameterized APIs instead of shell execution, (3) Whitelist allowed inputs, "
                    "(4) Sanitize input (remove ;|&`$() characters), (5) Use least privilege for execution, "
                    "(6) Avoid shell interpreters (use exec() family directly)."
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

    def _find_injection_params(self, schema: Dict[str, Any]) -> List[str]:
        """Find parameters vulnerable to injection"""
        vulnerable = []
        properties = schema.get('properties', {})

        for param_name, param_info in properties.items():
            param_name_lower = param_name.lower()

            # Check if parameter is injection-prone
            if param_name_lower in self.INJECTION_PARAMS:
                vulnerable.append(param_name)

        return vulnerable

    async def _test_command_injection(
        self,
        adapter: Any,
        tool_name: str,
        schema: Dict[str, Any],
        injection_params: List[str],
    ) -> Optional[Dict[str, Any]]:
        """Test for command injection with safe payloads."""
        if not injection_params:
            return None

        param_name = injection_params[0]
        baseline_text: Optional[str] = None

        for template in self.INJECTION_TEMPLATES:
            payload = template.format(base=self.TEST_BASE_INPUT, marker=self.CANARY_TOKEN)
            arguments = self._build_arguments(schema, param_name, payload)

            try:
                response = await adapter.call_tool(tool_name, arguments)
            except Exception:
                continue

            text = self._response_to_text(response)

            if baseline_text is None:
                baseline_text = text
                continue

            if self.CANARY_TOKEN in text:
                return {
                    'tool_name': tool_name,
                    'vulnerable_param': param_name,
                    'payload': payload,
                    'response_excerpt': text[:400],
                    'marker_found': True,
                }

        return None

    def _generate_pocs(
        self,
        confirmed: List[Dict[str, Any]],
        command_tools: List[Dict[str, Any]],
    ) -> List[ProofOfConcept]:
        """Generate PoCs for command injection."""
        pocs: List[ProofOfConcept] = []

        for item in confirmed[:3]:
            tool_name = item['tool_name']
            excerpt = item.get('response_excerpt', '')
            pocs.append(ProofOfConcept(
                target=tool_name,
                attack_type="command_injection",
                payload={
                    "tool_name": tool_name,
                    "payload": item.get('payload'),
                    "parameter": item.get('vulnerable_param'),
                },
                response={
                    "marker_detected": item.get('marker_found', False),
                    "response_excerpt": excerpt,
                },
                success=True,
                impact_demonstrated=(
                    f"Safe payload echoed canary token via tool '{tool_name}', "
                    f"confirming command injection through parameter '{item.get('vulnerable_param')}'."
                )
            ))

        if not pocs:
            for tool in command_tools:
                if not tool.get('flagged'):
                    continue
                injection_params = tool.get('injection_params', [])
                reasons = tool.get('risk_reasons', [])
                pocs.append(ProofOfConcept(
                    target=tool['tool_name'],
                    attack_type="command_injection_passive",
                    payload={
                        "tool_name": tool['tool_name'],
                        "vulnerable_params": injection_params,
                        "risk_reasons": reasons,
                    },
                    response={
                        "risk_score": tool.get('risk_score'),
                        "has_validation": tool.get('has_validation'),
                    },
                    success=False,
                    impact_demonstrated=(
                        f"Tool '{tool['tool_name']}' exposes unrestricted command parameters "
                        f"({', '.join(injection_params)}) with indicators: {', '.join(reasons[:4])}."
                    )
                ))
                if len(pocs) >= 3:
                    break

        return pocs

    def _score_command_tool(
        self,
        descriptor: str,
        schema: Dict[str, Any],
        injection_params: List[str],
    ) -> Tuple[float, List[str], bool]:
        """Score likelihood that a tool enables command injection."""
        reasons: List[str] = []
        score = 0.0
        has_validation = False

        if any(re.search(pattern, descriptor, re.IGNORECASE) for pattern in self.VULNERABLE_TOOL_PATTERNS):
            score += 0.25
            reasons.append("Tool name references network/system commands")

        if 'shell' in descriptor or 'subprocess' in descriptor:
            score += 0.2
            reasons.append("Tool references shell execution")

        properties = schema.get('properties', {})
        validation_keywords = ['validate', 'sanitize', 'whitelist', 'allowlist', 'regex', 'pattern']

        if any(keyword in descriptor for keyword in validation_keywords):
            has_validation = True

        unrestricted_found = 0
        for param in injection_params:
            score += 0.2
            reasons.append(f"Parameter '{param}' maps user input into command execution")

            param_info = properties.get(param, {})
            if self._param_is_unrestricted(param_info):
                score += 0.25
                reasons.append(f"Parameter '{param}' lacks input restrictions")
                unrestricted_found += 1
            else:
                has_validation = True

        if not injection_params:
            score += 0.1

        if unrestricted_found > 0:
            score = max(score, 0.7)
            reasons.append("Injection parameter(s) accept unrestricted free-form text")

        if not has_validation:
            score += 0.15
            reasons.append("No validation indicators detected")
        else:
            score = max(0.0, score - 0.1)

        return min(score, 1.0), reasons, has_validation

    def _param_is_unrestricted(self, param_info: Dict[str, Any]) -> bool:
        """Determine if a schema parameter permits unrestricted input."""
        if not param_info:
            return True

        restriction_keys = ('enum', 'const', 'pattern', 'format', 'minimum', 'maximum')
        if any(key in param_info for key in restriction_keys):
            return False

        max_length = param_info.get('maxLength')
        if isinstance(max_length, int) and max_length <= 64:
            return False

        return True

    def _build_arguments(
        self,
        schema: Dict[str, Any],
        target_param: str,
        value: str,
    ) -> Dict[str, Any]:
        """Construct minimal argument set with safe defaults."""
        properties = schema.get('properties', {})
        required = schema.get('required', []) or []

        args: Dict[str, Any] = {}
        for param in required:
            if param == target_param:
                args[param] = value
                continue

            info = properties.get(param, {})
            if 'enum' in info and info['enum']:
                args[param] = info['enum'][0]
                continue

            param_type = info.get('type', 'string')
            if param_type in ('integer', 'number'):
                args[param] = 0
            elif param_type == 'boolean':
                args[param] = False
            elif param_type == 'array':
                args[param] = []
            elif param_type == 'object':
                args[param] = {}
            else:
                args[param] = "test"

        if target_param not in args:
            args[target_param] = value

        return args

    def _response_to_text(self, response: Any) -> str:
        """Collapse tool response into comparable text."""
        if isinstance(response, dict):
            content = response.get("content")
            if isinstance(content, list):
                fragments = []
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text")
                        if text:
                            fragments.append(str(text))
                if fragments:
                    return "\n".join(fragments)
            return str(response)
        return str(response)
