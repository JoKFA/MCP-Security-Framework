"""
Tool Poisoning Detector

Detects: CWE-74 (Injection), OWASP LLM02 (Insecure Output Handling)

Detects hidden instructions in tool/resource descriptions that attempt to manipulate
LLM behavior. Works on any MCP server using pattern-based detection.

Methodology:
Phase 1 - Passive Detection:
- Lists all tools and resources
- Analyzes descriptions for injection patterns (HTML tags, imperatives, deceptive language)
- Identifies suspicious action+target combinations
- Scores findings based on pattern confidence

Phase 2 - Active PoC Generation:
- Demonstrates detected poisoning patterns
- Shows highest-confidence malicious instructions
- Provides evidence of manipulation attempts

Detection method: PASSIVE - pattern matching on metadata
Standards: CWE-74, OWASP LLM02, OWASP API8, CVSS 8.1 HIGH
"""

import re
from typing import List, Dict, Any, Optional, Set
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


class ToolPoisoningDetector(Detector):
    """
    Detects tool poisoning via hidden instructions in descriptions.

    This detector is designed for GENERAL use against any MCP server.
    It does NOT rely on knowing specific tool names or behaviors.
    """

    # Suspicious instruction patterns (language-agnostic)
    # These patterns indicate attempts to manipulate LLM behavior
    INJECTION_PATTERNS = [
        # HTML-style tags commonly used to hide instructions
        (r'<(?:IMPORTANT|HIDDEN|SECRET|SYSTEM|INSTRUCTION|OVERRIDE)>', 'html_tag_injection', 0.9),
        (r'<!\s*--\s*(?:IMPORTANT|HIDDEN|SECRET|SYSTEM)', 'html_comment_injection', 0.85),

        # Markdown-style hidden sections
        (r'<!--\s*(?:IMPORTANT|HIDDEN|SECRET|SYSTEM)', 'markdown_comment_injection', 0.85),

        # Instruction keywords that suggest manipulation
        (r'(?i)\b(?:you must|you should always|always|never mention|do not (?:tell|mention|reveal|disclose))', 'imperative_instruction', 0.7),
        (r'(?i)\b(?:ignore (?:previous|all|the) (?:instructions|rules|prompts))', 'ignore_instruction', 0.95),
        (r'(?i)\b(?:override|bypass|circumvent) (?:auth|authorization|security|access control)', 'security_bypass', 0.9),

        # Resource access instructions (suspicious in tool descriptions)
        (r'(?i)(?:read|access|retrieve|fetch) (?:the )?(?:resource|file|data) (?:at|from|in)', 'resource_access_instruction', 0.75),
        (r'(?i)include (?:the )?(?:confidential|secret|private|internal|admin|sensitive)', 'sensitive_data_instruction', 0.85),

        # Deceptive instructions
        (r'(?i)(?:do not|don\'t) (?:mention|tell|reveal|disclose|indicate) that you', 'deception_instruction', 0.85),
        (r'(?i)present (?:it|this|the (?:data|information)) as (?:if|though)', 'deception_instruction', 0.8),

        # Authorization override patterns
        (r'(?i)if .{1,50} contains .{1,50}(?:override|bypass|special|magic)', 'conditional_override', 0.8),

        # Base64-encoded content (could be hiding instructions)
        (r'[A-Za-z0-9+/]{40,}={0,2}', 'base64_content', 0.6),

        # Unicode tricks (zero-width characters, RTL overrides)
        (r'[\u200B-\u200D\u202A-\u202E\uFEFF]', 'unicode_trick', 0.75),
    ]

    # Sensitive action keywords
    SENSITIVE_ACTIONS = {
        'read', 'access', 'retrieve', 'fetch', 'get', 'obtain',
        'execute', 'run', 'eval', 'exec', 'system', 'command',
        'bypass', 'override', 'circumvent', 'ignore',
        'delete', 'remove', 'modify', 'update', 'change',
        'send', 'transmit', 'exfiltrate', 'leak'
    }

    # Sensitive target keywords
    SENSITIVE_TARGETS = {
        'credential', 'password', 'secret', 'token', 'key', 'api_key',
        'confidential', 'private', 'internal', 'admin', 'root',
        'database', 'config', 'configuration', 'environment',
        'file', 'directory', 'folder', 'system', 'user'
    }

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-TP-001",
            name="Tool Poisoning Detector",
            description=(
                "Detects hidden instructions in tool/resource descriptions that attempt "
                "to manipulate LLM behavior. Works on any MCP server using pattern matching."
            ),
            version="1.0.0",
            prerequisites={"tools": False, "resources": False},  # Works with either
            timeout_s=45,
            severity_default="HIGH",
            standards=StandardsMapping(
                cwe="CWE-74",  # Injection
                owasp_llm="LLM02",  # Insecure Output Handling
                owasp_api="API8:2023",  # Security Misconfiguration
                asvs=["V5.1", "V12.3"],
                capec=["CAPEC-242"],  # Code Injection
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    base_score=8.1,
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
        Execute tool poisoning detection.

        Strategy:
        1. Enumerate all tools and resources
        2. Analyze descriptions for injection patterns
        3. Score each finding based on pattern confidence
        4. Generate PoCs for high-confidence detections
        """
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,
            'resources_analyzed': 0,
            'poisoned_items': [],
            'pattern_matches': {}
        }
        start_time = datetime.now(timezone.utc)

        try:
            # Analyze tools
            try:
                tools = await adapter.list_tools()
                evidence['tools_analyzed'] = len(tools)

                for tool in tools:
                    tool_name = tool.get('name', 'unknown')
                    description = tool.get('description', '')
                    input_schema = tool.get('inputSchema', {})

                    # Analyze tool description
                    findings = self._analyze_text(description, tool_name, 'tool')

                    # Also check parameter descriptions in schema
                    if input_schema and 'properties' in input_schema:
                        for param_name, param_info in input_schema['properties'].items():
                            if 'description' in param_info:
                                param_findings = self._analyze_text(
                                    param_info['description'],
                                    f"{tool_name}.{param_name}",
                                    'tool_parameter'
                                )
                                findings.extend(param_findings)

                    if findings:
                        # Create signal for poisoned tool
                        total_score = sum(f['confidence'] for f in findings)
                        max_confidence = max(f['confidence'] for f in findings)

                        signals.append(Signal(
                            type=SignalType.SCHEMA_OVERPERMISSIVE,
                            value=True,
                            context={
                                'item_type': 'tool',
                                'item_name': tool_name,
                                'pattern_count': len(findings),
                                'max_confidence': max_confidence,
                                'total_score': total_score,
                                'patterns_detected': [f['pattern_type'] for f in findings]
                            }
                        ))

                        evidence['poisoned_items'].append({
                            'type': 'tool',
                            'name': tool_name,
                            'findings': findings,
                            'confidence': max_confidence
                        })

                        # Track pattern statistics
                        for finding in findings:
                            pattern_type = finding['pattern_type']
                            evidence['pattern_matches'][pattern_type] = \
                                evidence['pattern_matches'].get(pattern_type, 0) + 1

            except Exception as e:
                evidence['tool_analysis_error'] = str(e)

            # Analyze resources
            try:
                resources = await adapter.list_resources()
                evidence['resources_analyzed'] = len(resources)

                for resource in resources:
                    resource_uri = resource.get('uri', 'unknown')
                    name = resource.get('name', '')
                    description = resource.get('description', '')

                    # Analyze combined text
                    text = f"{name} {description}"
                    findings = self._analyze_text(text, resource_uri, 'resource')

                    if findings:
                        total_score = sum(f['confidence'] for f in findings)
                        max_confidence = max(f['confidence'] for f in findings)

                        signals.append(Signal(
                            type=SignalType.SCHEMA_OVERPERMISSIVE,
                            value=True,
                            context={
                                'item_type': 'resource',
                                'item_name': resource_uri,
                                'pattern_count': len(findings),
                                'max_confidence': max_confidence,
                                'total_score': total_score,
                                'patterns_detected': [f['pattern_type'] for f in findings]
                            }
                        ))

                        evidence['poisoned_items'].append({
                            'type': 'resource',
                            'name': resource_uri,
                            'findings': findings,
                            'confidence': max_confidence
                        })

                        for finding in findings:
                            pattern_type = finding['pattern_type']
                            evidence['pattern_matches'][pattern_type] = \
                                evidence['pattern_matches'].get(pattern_type, 0) + 1

            except Exception as e:
                evidence['resource_analysis_error'] = str(e)

            # Generate PoCs for high-confidence findings
            pocs = self._generate_pocs(evidence.get('poisoned_items', []))

            # Determine status and confidence
            if not signals:
                status = DetectionStatus.ABSENT
                confidence = 0.9
            else:
                status = DetectionStatus.PRESENT
                # Confidence based on highest-scoring finding
                max_item_confidence = max(
                    (item['confidence'] for item in evidence['poisoned_items']),
                    default=0.5
                )
                confidence = max_item_confidence

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
                    "Remove hidden instructions from tool/resource descriptions. "
                    "Use clear, neutral language that describes functionality without "
                    "attempting to manipulate LLM behavior. Implement automated scanning "
                    "for suspicious patterns in all metadata."
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

    def _analyze_text(
        self,
        text: str,
        item_name: str,
        item_type: str
    ) -> List[Dict[str, Any]]:
        """
        Analyze text for injection patterns.

        Returns list of findings with pattern type and confidence.
        """
        findings = []

        if not text or not text.strip():
            return findings

        # Check each injection pattern
        for pattern, pattern_type, base_confidence in self.INJECTION_PATTERNS:
            matches = re.findall(pattern, text, re.DOTALL | re.MULTILINE)
            if matches:
                # Adjust confidence based on context
                confidence = self._calculate_confidence(
                    text, pattern_type, base_confidence, matches
                )

                findings.append({
                    'pattern_type': pattern_type,
                    'confidence': confidence,
                    'match_count': len(matches),
                    'sample_match': str(matches[0])[:100] if matches else None
                })

        # Check for suspicious action+target combinations
        text_lower = text.lower()
        suspicious_combos = self._find_suspicious_combinations(text_lower)
        if suspicious_combos:
            findings.append({
                'pattern_type': 'suspicious_action_target',
                'confidence': 0.7,
                'match_count': len(suspicious_combos),
                'combinations': suspicious_combos[:5]  # Limit to 5 examples
            })

        return findings

    def _calculate_confidence(
        self,
        text: str,
        pattern_type: str,
        base_confidence: float,
        matches: List[Any]
    ) -> float:
        """
        Calculate adjusted confidence score based on context.

        Factors that increase confidence:
        - Multiple matches
        - Presence of sensitive keywords
        - Deceptive language
        """
        confidence = base_confidence

        # Multiple matches increase confidence
        if len(matches) > 1:
            confidence = min(1.0, confidence + 0.05 * (len(matches) - 1))

        # Presence of sensitive actions/targets increases confidence
        text_lower = text.lower()
        sensitive_count = sum(
            1 for word in self.SENSITIVE_ACTIONS | self.SENSITIVE_TARGETS
            if word in text_lower
        )
        if sensitive_count >= 3:
            confidence = min(1.0, confidence + 0.1)

        # Deceptive patterns are high confidence
        if any(phrase in text_lower for phrase in [
            'do not mention', 'do not tell', 'do not reveal',
            'present it as', 'present this as', 'make it appear'
        ]):
            confidence = min(1.0, confidence + 0.1)

        return round(confidence, 2)

    def _find_suspicious_combinations(self, text_lower: str) -> List[str]:
        """
        Find suspicious action+target combinations.

        Example: "access confidential" or "execute system"
        """
        combinations = []
        words = re.findall(r'\b\w+\b', text_lower)

        for i in range(len(words) - 1):
            action = words[i]
            target = words[i + 1]

            if action in self.SENSITIVE_ACTIONS and target in self.SENSITIVE_TARGETS:
                combinations.append(f"{action} {target}")

        return list(set(combinations))  # Deduplicate

    def _generate_pocs(self, poisoned_items: List[Dict[str, Any]]) -> List[ProofOfConcept]:
        """Generate PoCs demonstrating the poisoning"""
        pocs = []

        # Generate PoCs for top 3 highest-confidence findings
        sorted_items = sorted(
            poisoned_items,
            key=lambda x: x['confidence'],
            reverse=True
        )

        for item in sorted_items[:3]:
            item_type = item['type']
            item_name = item['name']
            findings = item['findings']

            # Summarize pattern types
            pattern_types = [f['pattern_type'] for f in findings]
            pattern_summary = ', '.join(set(pattern_types))

            # Get most confident finding
            top_finding = max(findings, key=lambda x: x['confidence'])

            pocs.append(ProofOfConcept(
                target=item_name,
                attack_type="tool_poisoning",
                payload={
                    "item_type": item_type,
                    "item_name": item_name,
                    "detection_method": "pattern_matching"
                },
                response={
                    "patterns_detected": pattern_types,
                    "highest_confidence_pattern": top_finding['pattern_type'],
                    "confidence": top_finding['confidence'],
                    "sample_evidence": top_finding.get('sample_match', 'N/A')
                },
                success=True,
                impact_demonstrated=(
                    f"Detected poisoned {item_type} '{item_name}' with {len(findings)} "
                    f"suspicious patterns ({pattern_summary}). "
                    f"Highest confidence: {top_finding['pattern_type']} "
                    f"({top_finding['confidence']:.0%})"
                )
            ))

        return pocs
