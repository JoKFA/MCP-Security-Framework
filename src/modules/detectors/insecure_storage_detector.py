"""
Insecure Token Storage Detector

Detects: CWE-522 (Insufficiently Protected Credentials), OWASP API2 (Broken Authentication)

Detects insecure storage and exposure of authentication tokens, API keys,
and credentials in tool responses. Works on any MCP server.

Methodology:
Phase 1 - Passive Detection:
- Identifies authentication-related tools (email, API, cloud, database)
- Calls tools with minimal inputs
- Scans responses for exposed tokens, keys, credentials
- Detects cleartext storage indicators in error messages

Phase 2 - Active PoC Generation:
- Demonstrates token extraction
- Shows exposed credential samples (redacted)
- Highlights security impact

Detection method: ACTIVE - calls tools and analyzes responses for secrets
Standards: CWE-522, OWASP API2, CVSS 8.6 HIGH
"""

import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from uuid import uuid4

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


class InsecureStorageDetector(Detector):
    """
    Detects insecure token/credential storage.

    General-purpose detector for ANY MCP server.
    """

    # Secret patterns (reuse from credential_exposure for consistency)
    SECRET_PATTERNS = {
        'api_keys': [
            r'(?i)(api[_-]?key|apikey)[\s:=]+([^\s\n]+)',
            r'sk-[a-zA-Z0-9]{20,}',
            r'ak_[a-zA-Z0-9]{20,}'
        ],
        'tokens': [
            r'(?i)(token|access[_-]?token|auth[_-]?token)[\s:=]+([^\s\n]+)',
            r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',  # JWT
        ],
        'passwords': [
            r'(?i)(password|passwd|pwd)[\s:=]+([^\s\n]+)',
        ],
        'oauth': [
            r'(?i)(client[_-]?secret|client[_-]?id)[\s:=]+([^\s\n]+)',
            r'(?i)(refresh[_-]?token)[\s:=]+([^\s\n]+)',
        ],
        'cloud_keys': [
            r'(?i)(aws[_-]?access[_-]?key|aws[_-]?secret)[\s:=]+([^\s\n]+)',
            r'AKIA[0-9A-Z]{16}',  # AWS access key
        ],
    }

    # Tool keywords suggesting authentication handling
    AUTH_TOOL_KEYWORDS = [
        'auth', 'login', 'token', 'credential', 'api',
        'email', 'smtp', 'imap', 'oauth', 'sso',
        'database', 'db', 'cloud', 'aws', 's3',
        'key', 'secret', 'password'
    ]

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-IS-001",
            name="Insecure Token Storage Detector",
            description=(
                "Detects insecure storage and exposure of authentication tokens, "
                "API keys, and credentials. Works on any MCP server."
            ),
            version="1.0.0",
            prerequisites={"tools": True},
            timeout_s=60,
            severity_default="HIGH",
            standards=StandardsMapping(
                cwe="CWE-522",  # Insufficiently Protected Credentials
                owasp_llm="LLM01",  # Prompt Injection (credentials in prompts)
                owasp_api="API2:2023",  # Broken Authentication
                asvs=["V2.1", "V2.7"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    base_score=8.6,
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
        Execute insecure storage detection.

        Strategy:
        1. Identify authentication-related tools
        2. Call tools with minimal inputs
        3. Scan responses for exposed secrets
        4. Flag tools that leak credentials
        """
        mode = (scope or {}).get("mode", "balanced") if scope else "balanced"
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,
            'tools_tested': 0,
            'insecure_tools': [],
            'weak_validation_tools': [],
            'mode': mode,
        }
        start_time = datetime.now(timezone.utc)

        try:
            tools = await adapter.list_tools()
            evidence['tools_analyzed'] = len(tools)

            for tool in tools:
                tool_name = tool.get('name', '')
                description = tool.get('description', '').lower()

                # Check if tool likely handles authentication
                is_auth_related = any(
                    keyword in description or keyword in tool_name.lower()
                    for keyword in self.AUTH_TOOL_KEYWORDS
                )

                if is_auth_related or len(tools) <= 10:  # Test all if small server
                    try:
                        # Generate safe test parameters
                        params = self._generate_safe_params(tool)

                        # Call tool
                        response = await adapter.call_tool(tool_name, params)
                        evidence['tools_tested'] += 1

                        # Scan response for secrets
                        response_text = str(response)
                        secrets_found = self._scan_for_secrets(response_text)

                        if secrets_found:
                            signals.append(Signal(
                                type=SignalType.SENSITIVE_EXPOSURE,
                                value=True,
                                context={
                                    'tool_name': tool_name,
                                    'secret_types': list(secrets_found.keys()),
                                    'total_secrets': sum(len(v) for v in secrets_found.values())
                                }
                            ))

                            evidence['insecure_tools'].append({
                                'tool_name': tool_name,
                                'secrets': secrets_found
                            })

                        weak_validation = await self._test_token_validation(
                            adapter,
                            tool,
                            params,
                            mode,
                        )
                        if weak_validation:
                            signals.append(Signal(
                                type=SignalType.AUTH_MISMATCH,
                                value=True,
                                context={
                                    'tool_name': tool_name,
                                    'issue': 'weak_token_validation',
                                }
                            ))
                            evidence['weak_validation_tools'].append(weak_validation)

                    except Exception:
                        pass  # Tool call failed, continue

            # Generate PoCs
            pocs = self._generate_pocs(
                evidence.get('insecure_tools', []),
                evidence.get('weak_validation_tools', []),
            )

            # Determine status
            if evidence['insecure_tools'] or evidence['weak_validation_tools']:
                status = DetectionStatus.PRESENT
                confidence = 0.9 if evidence['insecure_tools'] else 0.82
            elif signals:
                status = DetectionStatus.PRESENT
                confidence = 0.8
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
                    "Secure credential storage: (1) Never return raw tokens/keys in responses, "
                    "(2) Use secure credential storage (environment variables, key vaults), "
                    "(3) Implement token redaction in tool outputs, (4) Use short-lived tokens, "
                    "(5) Rotate credentials regularly, (6) Log credential access for auditing."
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

    def _scan_for_secrets(self, text: str) -> Dict[str, List[str]]:
        """Scan text for exposed secrets"""
        secrets = {}

        for secret_type, patterns in self.SECRET_PATTERNS.items():
            found = []
            for pattern in patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    if isinstance(match, tuple):
                        secret_value = match[1] if len(match) > 1 else match[0]
                    else:
                        secret_value = match

                    if secret_value and len(secret_value) > 3:
                        found.append(secret_value)

            if found:
                secrets[secret_type] = list(set(found))

        return secrets

    def _generate_safe_params(self, tool: Dict[str, Any]) -> Dict[str, Any]:
        """Generate minimal safe parameters"""
        schema = tool.get('inputSchema', {})
        properties = schema.get('properties', {})
        required = schema.get('required', [])

        params = {}
        for param in required[:2]:
            if param in properties:
                param_type = properties[param].get('type', 'string')
                if param_type == 'string':
                    params[param] = 'test'
                elif param_type in ['number', 'integer']:
                    params[param] = 1
                elif param_type == 'boolean':
                    params[param] = False

        return params

    async def _test_token_validation(
        self,
        adapter: Any,
        tool: Dict[str, Any],
        base_params: Dict[str, Any],
        mode: str,
    ) -> Optional[Dict[str, Any]]:
        """Test whether token verification logic accepts arbitrary values."""
        if mode == "safe":
            return None

        tool_name = tool.get('name', '')
        lower_name = tool_name.lower()

        if "verify" not in lower_name and "token" not in lower_name:
            return None

        schema = tool.get('inputSchema', {})
        token_param = self._find_token_param(schema)
        if not token_param:
            return None

        overrides = dict(base_params)
        overrides[token_param] = uuid4().hex

        arguments = self._build_arguments(schema, overrides)
        if not arguments:
            return None

        try:
            response = await adapter.call_tool(tool_name, arguments)
        except Exception:
            return None

        text = str(response).lower()
        positive_indicators = ["appears to be valid", "token is valid", "accepted"]
        negative_indicators = ["invalid", "error", "denied"]

        if any(indicator in text for indicator in positive_indicators) and not any(
            neg in text for neg in negative_indicators
        ):
            return {
                'tool_name': tool_name,
                'payload': arguments,
                'response_preview': str(response)[:200],
            }

        return None

    def _find_token_param(self, schema: Dict[str, Any]) -> Optional[str]:
        """Locate parameter likely representing a token."""
        properties = schema.get('properties', {})
        for name in properties.keys():
            if 'token' in name.lower():
                return name
        return None

    def _build_arguments(
        self,
        schema: Dict[str, Any],
        overrides: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Construct arguments using overrides and schema defaults."""
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

    def _generate_pocs(
        self,
        insecure_tools: List[Dict[str, Any]],
        weak_validation_tools: List[Dict[str, Any]],
    ) -> List[ProofOfConcept]:
        """Generate PoCs for token exposure"""
        pocs = []

        for item in insecure_tools[:3]:
            tool_name = item['tool_name']
            secrets = item['secrets']

            # Redact secrets for display
            redacted_samples = {}
            for secret_type, values in secrets.items():
                samples = []
                for val in values[:2]:
                    if len(val) > 12:
                        redacted = f"{val[:6]}...{val[-4:]}"
                    else:
                        redacted = f"{val[:4]}{'*' * (len(val) - 4)}"
                    samples.append(redacted)
                redacted_samples[secret_type] = samples

            total_secrets = sum(len(v) for v in secrets.values())

            pocs.append(ProofOfConcept(
                target=tool_name,
                attack_type="insecure_storage",
                payload={"tool": tool_name, "method": "call_tool"},
                response={
                    "secret_types": list(secrets.keys()),
                    "total_secrets": total_secrets,
                    "samples": redacted_samples
                },
                success=True,
                impact_demonstrated=(
                    f"Tool '{tool_name}' exposes {total_secrets} secret(s) in responses. "
                    f"Types: {', '.join(secrets.keys())}. Samples: {self._format_samples(redacted_samples)}. "
                    f"Credentials are stored/transmitted insecurely, enabling theft."
                )
            ))

        for item in weak_validation_tools[:2]:
            tool_name = item['tool_name']
            pocs.append(ProofOfConcept(
                target=tool_name,
                attack_type="weak_token_validation",
                payload=item.get('payload', {}),
                response={
                    "response_preview": item.get('response_preview', '')
                },
                success=True,
                impact_demonstrated=(
                    f"Tool '{tool_name}' accepts arbitrary token values, allowing attackers "
                    f"to forge session or access tokens without possessing legitimate secrets."
                )
            ))

        return pocs

    def _format_samples(self, samples: Dict[str, List[str]]) -> str:
        """Format samples for display"""
        parts = []
        for secret_type, vals in list(samples.items())[:2]:
            if vals:
                parts.append(f"{secret_type}=[{', '.join(vals[:2])}]")
        return "; ".join(parts)
