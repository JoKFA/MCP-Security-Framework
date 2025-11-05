"""
Excessive Permissions Detector

Detects: CWE-269 (Improper Privilege Management), OWASP LLM08 (Excessive Agency)

Detects overly permissive tool/resource access patterns that violate the
principle of least privilege. Works on any MCP server.

Methodology:
Phase 1 - Passive Detection:
- Enumerates all tools and their schemas
- Analyzes tool capabilities (filesystem, code execution, network, database, system)
- Identifies unrestricted parameters (path, command, url without validation)
- Flags tools with multiple high-risk capabilities combined
- Detects mismatch between stated purpose and actual capabilities

Phase 2 - Active PoC Generation:
- Demonstrates excessive permission findings
- Shows risk scores and capability combinations
- Highlights unrestricted parameters

Detection method: PASSIVE - capability and schema analysis
Standards: CWE-269, OWASP LLM08, OWASP API6, CVSS 9.1 CRITICAL
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
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


class ExcessivePermissionsDetector(Detector):
    """
    Detects excessive permission scopes in MCP server tools and resources.

    General-purpose detector for ANY MCP server.
    """

    # High-risk capability indicators in tool descriptions/names
    HIGH_RISK_CAPABILITIES = {
        'filesystem_access': {
            'keywords': [
                r'\bfile\b', r'\bfiles\b', r'\bread\b', r'\bwrite\b',
                r'\bdelete\b', r'\bremove\b', r'\bpath\b', r'\bdirectory\b',
                r'\bfolder\b', r'\bopen\b', r'\bsave\b'
            ],
            'risk_score': 0.7,
        },
        'code_execution': {
            'keywords': [
                r'\bexec\b', r'\beval\b', r'\brun\b', r'\bexecute\b',
                r'\bpython\b', r'\bjavascript\b', r'\bshell\b', r'\bcommand\b',
                r'\bscript\b', r'\bcode\b'
            ],
            'risk_score': 0.9,
        },
        'network_access': {
            'keywords': [
                r'\bhttp\b', r'\bhttps\b', r'\burl\b', r'\brequest\b',
                r'\bfetch\b', r'\bapi\b', r'\bwebhook\b', r'\bsocket\b',
                r'\bconnect\b'
            ],
            'risk_score': 0.6,
        },
        'database_access': {
            'keywords': [
                r'\bdatabase\b', r'\bdb\b', r'\bsql\b', r'\bquery\b',
                r'\bselect\b', r'\binsert\b', r'\bupdate\b', r'\bdelete\b'
            ],
            'risk_score': 0.75,
        },
        'system_commands': {
            'keywords': [
                r'\bsystem\b', r'\bos\b', r'\bprocess\b', r'\bpid\b',
                r'\bkill\b', r'\bspawn\b', r'\bsubprocess\b'
            ],
            'risk_score': 0.85,
        },
        'credential_access': {
            'keywords': [
                r'\bpassword\b', r'\btoken\b', r'\bapi[_-]?key\b', r'\bcredential\b',
                r'\bsecret\b', r'\bauth\b', r'\blogin\b'
            ],
            'risk_score': 0.8,
        },
    }

    # Indicators of restrictive/safe design
    SAFE_INDICATORS = [
        r'\bpublic\b', r'\bread[_-]only\b', r'\bview\b', r'\bdisplay\b',
        r'\bshow\b', r'\blist\b', r'\bsearch\b', r'\bquery\b',
        r'\bget\b', r'\bfetch\b', r'\bretrieve\b'
    ]

    # Parameters that suggest unrestricted access
    UNRESTRICTED_PARAMS = {
        'path', 'file_path', 'filepath', 'filename', 'file',
        'directory', 'dir', 'folder',
        'url', 'uri', 'endpoint',
        'command', 'cmd', 'script', 'code', 'query'
    }

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-EP-001",
            name="Excessive Permissions Detector",
            description=(
                "Detects overly permissive tool/resource access patterns that violate "
                "the principle of least privilege. Works on any MCP server."
            ),
            version="1.0.0",
            prerequisites={"tools": True},
            timeout_s=45,
            severity_default="HIGH",
            standards=StandardsMapping(
                cwe="CWE-269",  # Improper Privilege Management
                owasp_llm="LLM08",  # Excessive Agency
                owasp_api="API6:2023",  # Unrestricted Resource Access
                asvs=["V4.1", "V4.2"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    base_score=9.1,
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
        Execute excessive permissions detection.

        Strategy:
        1. Enumerate all tools
        2. Analyze each tool for high-risk capabilities
        3. Check for mismatches between stated purpose and capabilities
        4. Flag tools with unrestricted parameters
        5. Detect tools with multiple high-risk capabilities
        """
        mode = (scope or {}).get("mode", "balanced") if scope else "balanced"
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,
            'overpermissive_tools': [],
            'high_risk_tools': [],
            'capability_distribution': {},
            'confirmed_tools': [],
            'mode': mode,
        }
        start_time = datetime.now(timezone.utc)

        passive_thresholds = {
            "safe": 0.75,
            "balanced": 0.6,
            "aggressive": 0.5,
        }
        passive_threshold = passive_thresholds.get(mode, 0.6)
        exploit_enabled = mode != "safe"

        try:
            # Enumerate tools
            tools = await adapter.list_tools()
            evidence['tools_analyzed'] = len(tools)

            for tool in tools:
                tool_name = tool.get('name', 'unknown')
                description = tool.get('description', '')
                input_schema = tool.get('inputSchema', {})

                # Analyze tool for excessive permissions
                analysis = self._analyze_tool_permissions(
                    tool_name, description, input_schema
                )

                flagged = analysis['is_overpermissive'] or analysis['risk_score'] >= passive_threshold
                if flagged and not analysis['is_overpermissive']:
                    analysis['is_overpermissive'] = True
                    if not analysis['reason']:
                        analysis['reason'] = f"Risk score {analysis['risk_score']:.0%} exceeds {int(passive_threshold*100)}% threshold"

                if analysis['is_overpermissive']:
                    # Create signal for overpermissive tool
                    signals.append(Signal(
                        type=SignalType.SCHEMA_OVERPERMISSIVE,
                        value=True,
                        context={
                            'tool_name': tool_name,
                            'risk_score': analysis['risk_score'],
                            'capabilities': analysis['capabilities'],
                            'unrestricted_params': analysis['unrestricted_params'],
                            'reason': analysis['reason']
                        }
                    ))

                    evidence['overpermissive_tools'].append({
                        'tool_name': tool_name,
                        'risk_score': analysis['risk_score'],
                        'capabilities': analysis['capabilities'],
                        'unrestricted_params': analysis['unrestricted_params'],
                        'reason': analysis['reason']
                    })

                    if exploit_enabled:
                        poc = await self._attempt_active_poc(adapter, tool, analysis)
                        if poc:
                            evidence['confirmed_tools'].append(poc)

                    # Track capability distribution
                    for cap in analysis['capabilities']:
                        evidence['capability_distribution'][cap] = \
                            evidence['capability_distribution'].get(cap, 0) + 1

                # Track high-risk tools separately
                if analysis['risk_score'] >= 0.7:
                    evidence['high_risk_tools'].append({
                        'tool_name': tool_name,
                        'risk_score': analysis['risk_score'],
                        'capabilities': analysis['capabilities']
                    })

            pocs = self._generate_pocs(
                evidence.get('overpermissive_tools', []),
                evidence.get('confirmed_tools', []),
            )

            confirmed = evidence.get('confirmed_tools', [])
            if confirmed:
                status = DetectionStatus.PRESENT
                confidence = 0.97
            elif signals:
                status = DetectionStatus.PRESENT
                max_risk = max(
                    (tool['risk_score'] for tool in evidence['overpermissive_tools']),
                    default=0.5
                )
                confidence = max(0.65, min(0.9, max_risk))
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
                    "Apply principle of least privilege: (1) Restrict tool parameters to "
                    "specific allowed values/paths, (2) Implement path validation and "
                    "sanitization, (3) Split multi-capability tools into focused tools, "
                    "(4) Add explicit access control checks, (5) Document and justify "
                    "any high-risk capabilities."
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

    async def _attempt_active_poc(
        self,
        adapter: Any,
        tool: Dict[str, Any],
        analysis: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Attempt safe proof-of-concept calls for flagged tools."""
        tool_name = tool.get('name', 'unknown')
        schema = tool.get('inputSchema', {})
        capabilities = analysis.get('capabilities', [])

        if 'filesystem_access' in capabilities:
            result = await self._filesystem_poc(adapter, tool_name, schema)
            if result:
                return result

        if 'system_commands' in capabilities or 'network_access' in capabilities:
            result = await self._remote_access_poc(adapter, tool_name, schema)
            if result:
                return result

        return None

    async def _filesystem_poc(
        self,
        adapter: Any,
        tool_name: str,
        schema: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Attempt to read a harmless system file to confirm unrestricted access."""
        path_param = self._find_param(schema, {'path', 'file', 'filepath', 'filename'})
        if not path_param:
            return None

        action_param = self._find_param(schema, {'action', 'mode', 'operation'})
        preferred = {}
        if action_param:
            preferred[action_param] = self._choose_enum(schema, action_param, "read")

        candidate_paths = [
            "/etc/hosts",
            "/etc/passwd",
            "/var/log/system.log",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]

        for candidate in candidate_paths:
            preferred[path_param] = candidate
            arguments = self._build_argument_map(schema, preferred)
            if not arguments:
                continue

            try:
                response = await adapter.call_tool(tool_name, arguments)
            except Exception:
                continue

            text = self._extract_text(response)
            if text and "Error" not in text and "not allowed" not in text.lower():
                return {
                    'tool_name': tool_name,
                    'attack_type': 'filesystem_access',
                    'payload': arguments,
                    'response': {
                        'preview': text[:400],
                        'path': candidate,
                    },
                    'impact': (
                        f"Tool '{tool_name}' granted file access to '{candidate}' "
                        "without additional authorization."
                    ),
                }

        return None

    async def _remote_access_poc(
        self,
        adapter: Any,
        tool_name: str,
        schema: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Attempt to invoke remote access functionality with placeholder credentials."""
        system_param = self._find_param(schema, {'system', 'target', 'destination'})
        command_param = self._find_param(schema, {'command', 'action', 'operation'})
        if not system_param or not command_param:
            return None

        auth_param = self._find_param(schema, {'token', 'auth', 'apikey', 'key'})
        preferred = {
            system_param: "admin-console",
            command_param: "status",
        }
        if auth_param:
            preferred[auth_param] = "MCPSF_TEST_TOKEN"

        arguments = self._build_argument_map(schema, preferred)
        if not arguments:
            return None

        try:
            response = await adapter.call_tool(tool_name, arguments)
        except Exception:
            return None

        text = self._extract_text(response)
        if text and ("Admin command" in text or "executed" in text.lower()):
            return {
                'tool_name': tool_name,
                'attack_type': 'remote_access',
                'payload': arguments,
                'response': {
                    'preview': text[:300],
                },
                'impact': (
                    f"Tool '{tool_name}' executed admin command with placeholder token, "
                    "confirming insufficient access controls."
                ),
            }

        return None

    def _analyze_tool_permissions(
        self,
        tool_name: str,
        description: str,
        input_schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze a tool for excessive permissions.

        Returns dict with:
        - is_overpermissive: bool
        - risk_score: float (0-1)
        - capabilities: list of detected high-risk capabilities
        - unrestricted_params: list of unrestricted parameters
        - reason: str explaining why it's flagged
        """
        result = {
            'is_overpermissive': False,
            'risk_score': 0.0,
            'capabilities': [],
            'unrestricted_params': [],
            'reason': ''
        }

        combined_text = f"{tool_name} {description}".lower()

        # 1. Detect capabilities
        capabilities_detected = {}
        for cap_name, cap_info in self.HIGH_RISK_CAPABILITIES.items():
            for keyword_pattern in cap_info['keywords']:
                if re.search(keyword_pattern, combined_text, re.IGNORECASE):
                    capabilities_detected[cap_name] = cap_info['risk_score']
                    break

        result['capabilities'] = list(capabilities_detected.keys())

        # 2. Check for unrestricted parameters
        if input_schema and 'properties' in input_schema:
            properties = input_schema['properties']
            required_params = input_schema.get('required', [])

            for param_name in properties.keys():
                param_name_lower = param_name.lower()
                param_info = properties[param_name]

                # Check if parameter suggests unrestricted access
                if any(unsafe in param_name_lower for unsafe in self.UNRESTRICTED_PARAMS):
                    # Check if there are restrictions (enum, pattern, etc.)
                    has_restrictions = any(key in param_info for key in ['enum', 'pattern', 'const'])

                    if not has_restrictions:
                        result['unrestricted_params'].append({
                            'name': param_name,
                            'type': param_info.get('type', 'unknown'),
                            'required': param_name in required_params
                        })

        # 3. Calculate risk score
        if capabilities_detected:
            # Base risk = highest capability risk
            base_risk = max(capabilities_detected.values())

            # Increase risk for multiple capabilities
            if len(capabilities_detected) > 1:
                base_risk = min(1.0, base_risk + 0.1 * (len(capabilities_detected) - 1))

            # Increase risk for unrestricted parameters
            if result['unrestricted_params']:
                base_risk = min(1.0, base_risk + 0.1 * len(result['unrestricted_params']))

            # Decrease risk if safe indicators present
            safe_count = sum(
                1 for pattern in self.SAFE_INDICATORS
                if re.search(pattern, combined_text, re.IGNORECASE)
            )
            if safe_count > 0:
                base_risk = max(0.0, base_risk - 0.05 * safe_count)

            result['risk_score'] = round(base_risk, 2)

        # 4. Determine if overpermissive
        reasons = []

        # Flag if multiple high-risk capabilities
        if len(capabilities_detected) >= 2:
            result['is_overpermissive'] = True
            reasons.append(f"{len(capabilities_detected)} high-risk capabilities combined")

        # Flag if high-risk capability with unrestricted params
        if capabilities_detected and result['unrestricted_params']:
            result['is_overpermissive'] = True
            reasons.append(f"Unrestricted parameters ({len(result['unrestricted_params'])}) with high-risk capabilities")

        # Flag if very high base risk
        if result['risk_score'] >= 0.75:
            result['is_overpermissive'] = True
            if not reasons:
                reasons.append(f"High risk score ({result['risk_score']:.0%})")

        result['reason'] = '; '.join(reasons) if reasons else 'N/A'

        return result

    def _find_param(self, schema: Dict[str, Any], candidates: Set[str]) -> Optional[str]:
        """Locate a parameter by name heuristic."""
        properties = schema.get('properties', {})
        for name in properties.keys():
            if name.lower() in candidates:
                return name
        for name in properties.keys():
            for candidate in candidates:
                if candidate in name.lower():
                    return name
        return None

    def _choose_enum(self, schema: Dict[str, Any], param: str, fallback: str) -> str:
        """Pick preferred enum value when available."""
        properties = schema.get('properties', {})
        options = properties.get(param, {}).get('enum')
        if isinstance(options, list) and options:
            for option in options:
                if str(option).lower().startswith(fallback):
                    return option
            return options[0]
        return fallback

    def _build_argument_map(
        self,
        schema: Dict[str, Any],
        overrides: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build argument set honoring required fields and overrides."""
        properties = schema.get('properties', {})
        required = schema.get('required', []) or []
        args: Dict[str, Any] = {}

        for name in properties.keys():
            if name in overrides:
                args[name] = overrides[name]
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
                        args[name] = info.get('default', 'test')

        for name, value in overrides.items():
            args[name] = value

        return args

    def _extract_text(self, response: Any) -> str:
        """Normalize adapter responses to plain text."""
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

    def _generate_pocs(
        self,
        overpermissive_tools: List[Dict[str, Any]],
        confirmed_tools: List[Dict[str, Any]],
    ) -> List[ProofOfConcept]:
        """Generate PoCs demonstrating excessive permissions"""
        pocs = []

        confirmed_names = set()
        for item in confirmed_tools[:3]:
            pocs.append(ProofOfConcept(
                target=item['tool_name'],
                attack_type=item.get('attack_type', 'excessive_permissions'),
                payload=item.get('payload', {}),
                response=item.get('response', {}),
                success=True,
                impact_demonstrated=item.get(
                    'impact',
                    f"Active test confirmed excessive permissions for tool '{item['tool_name']}'."
                )
            ))
            confirmed_names.add(item['tool_name'])

        # Sort by risk score
        sorted_tools = sorted(
            overpermissive_tools,
            key=lambda x: x['risk_score'],
            reverse=True
        )

        for tool in sorted_tools:
            if tool['tool_name'] in confirmed_names:
                continue
            if len(pocs) >= 3:
                break
            tool_name = tool['tool_name']
            risk_score = tool['risk_score']
            capabilities = tool['capabilities']
            unrestricted_params = tool['unrestricted_params']
            reason = tool['reason']

            # Build impact description
            impacts = []
            if 'code_execution' in capabilities:
                impacts.append("arbitrary code execution")
            if 'system_commands' in capabilities:
                impacts.append("system command execution")
            if 'filesystem_access' in capabilities:
                impacts.append("unrestricted file system access")
            if 'database_access' in capabilities:
                impacts.append("database manipulation")
            if 'network_access' in capabilities:
                impacts.append("external network access")

            impact_str = ", ".join(impacts) if impacts else "elevated privileges"

            pocs.append(ProofOfConcept(
                target=tool_name,
                attack_type="excessive_permissions",
                payload={
                    "tool_name": tool_name,
                    "detection_method": "capability_analysis"
                },
                response={
                    "risk_score": risk_score,
                    "capabilities": capabilities,
                    "unrestricted_params": [p['name'] for p in unrestricted_params],
                    "reason": reason
                },
                success=True,
                impact_demonstrated=(
                    f"Tool '{tool_name}' has excessive permissions (risk: {risk_score:.0%}). "
                    f"Capabilities: {', '.join(capabilities)}. "
                    f"Unrestricted params: {len(unrestricted_params)}. "
                    f"Potential for: {impact_str}."
                )
            ))

        return pocs
