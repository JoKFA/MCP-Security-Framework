"""
Tool Shadowing Detector

Detects: CWE-706 (Use of Incorrectly-Resolved Name), OWASP LLM07 (Insecure Plugin Design)

Detects tool name conflicts and shadowing attacks where malicious tools
override or impersonate legitimate tools. Works on any MCP server.

Methodology:
Phase 1 - Passive Detection:
- Lists all available tools
- Identifies duplicate tool names
- Detects suspicious name patterns (similar names, typosquatting)
- Flags tools with generic/common names that could shadow legitimate tools
- Analyzes tool descriptions for impersonation indicators

Phase 2 - Active PoC Generation:
- Demonstrates tool name conflicts
- Shows shadowing/impersonation evidence
- Highlights security implications

Detection method: PASSIVE - tool enumeration and name analysis
Standards: CWE-706, OWASP LLM07, CVSS 7.5 HIGH
"""

import re
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timezone
from difflib import SequenceMatcher

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


class ToolShadowingDetector(Detector):
    """
    Detects tool shadowing and name conflict attacks.

    General-purpose detector for ANY MCP server.
    """

    # Common legitimate tool names (likely to be shadowed)
    COMMON_TOOL_NAMES = {
        'calculator', 'calc', 'compute',
        'search', 'find', 'query',
        'read_file', 'write_file', 'file',
        'get', 'post', 'fetch', 'request',
        'send', 'email', 'message',
        'execute', 'run', 'eval',
        'database', 'db', 'sql',
        'weather', 'time', 'date',
    }

    # Similarity threshold for typosquatting detection
    SIMILARITY_THRESHOLD = 0.85

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-TS-001",
            name="Tool Shadowing Detector",
            description=(
                "Detects tool name conflicts and shadowing attacks where malicious tools "
                "override or impersonate legitimate tools. Works on any MCP server."
            ),
            version="1.0.0",
            prerequisites={"tools": True},
            timeout_s=30,
            severity_default="HIGH",
            standards=StandardsMapping(
                cwe="CWE-706",  # Use of Incorrectly-Resolved Name
                owasp_llm="LLM07",  # Insecure Plugin Design
                owasp_api="API8:2023",  # Security Misconfiguration
                asvs=["V14.4"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    base_score=7.5,
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
        Execute tool shadowing detection.

        Strategy:
        1. Enumerate all tools
        2. Detect exact duplicate names
        3. Detect similar names (typosquatting)
        4. Flag generic/common names
        5. Analyze for impersonation patterns
        """
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            'tools_analyzed': 0,
            'duplicates': [],
            'similar_names': [],
            'generic_names': [],
            'impersonation_attempts': []
        }
        start_time = datetime.now(timezone.utc)

        try:
            # Enumerate tools
            tools = await adapter.list_tools()
            evidence['tools_analyzed'] = len(tools)

            # Build tool name index
            tool_names = [tool.get('name', '').lower() for tool in tools]
            tool_map = {tool.get('name', '').lower(): tool for tool in tools}

            # 1. Detect exact duplicates
            duplicates = self._find_duplicates(tool_names)
            if duplicates:
                for name, count in duplicates.items():
                    signals.append(Signal(
                        type=SignalType.SCHEMA_OVERPERMISSIVE,
                        value=True,
                        context={
                            'issue_type': 'duplicate_name',
                            'tool_name': name,
                            'count': count
                        }
                    ))
                    evidence['duplicates'].append({'name': name, 'count': count})

            # 2. Detect similar names (typosquatting)
            similar_pairs = self._find_similar_names(tool_names)
            if similar_pairs:
                for name1, name2, similarity in similar_pairs:
                    signals.append(Signal(
                        type=SignalType.SCHEMA_OVERPERMISSIVE,
                        value=True,
                        context={
                            'issue_type': 'similar_names',
                            'tool_name_1': name1,
                            'tool_name_2': name2,
                            'similarity': similarity
                        }
                    ))
                    evidence['similar_names'].append({
                        'name1': name1,
                        'name2': name2,
                        'similarity': similarity
                    })

            # 3. Record generic/common names (informational only)
            generic = self._find_generic_names(tool_names)
            if generic:
                for name in generic:
                    evidence['generic_names'].append(name)

            # 4. Detect impersonation patterns
            impersonations = self._detect_impersonation(tools)
            if impersonations:
                for imp in impersonations:
                    signals.append(Signal(
                        type=SignalType.SCHEMA_OVERPERMISSIVE,
                        value=True,
                        context={
                            'issue_type': 'impersonation',
                            'tool_name': imp['tool_name'],
                            'pattern': imp['pattern']
                        }
                    ))
                    evidence['impersonation_attempts'].append(imp)

            # Generate PoCs
            pocs = self._generate_pocs(evidence)

            # Determine status
            if not signals:
                status = DetectionStatus.ABSENT
                confidence = 0.9
            else:
                status = DetectionStatus.PRESENT
                # Higher confidence for duplicates, lower for similar names
                if duplicates:
                    confidence = 0.95
                elif similar_pairs:
                    confidence = 0.8
                else:
                    confidence = 0.7

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
                    "Prevent tool shadowing: (1) Enforce unique tool names across all "
                    "connected MCP servers, (2) Use namespacing (e.g., server_name.tool_name), "
                    "(3) Implement tool identity verification, (4) Warn users when multiple "
                    "tools have similar names, (5) Maintain a whitelist of trusted tool sources."
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

    def _find_duplicates(self, tool_names: List[str]) -> Dict[str, int]:
        """Find exact duplicate tool names"""
        duplicates = {}
        name_counts = {}

        for name in tool_names:
            if name:
                name_counts[name] = name_counts.get(name, 0) + 1

        for name, count in name_counts.items():
            if count > 1:
                duplicates[name] = count

        return duplicates

    def _find_similar_names(
        self,
        tool_names: List[str]
    ) -> List[tuple[str, str, float]]:
        """
        Find suspiciously similar tool names (typosquatting).

        Returns list of (name1, name2, similarity_score)
        """
        similar_pairs = []
        checked_pairs = set()

        for i, name1 in enumerate(tool_names):
            if not name1 or len(name1) < 3:
                continue

            for name2 in tool_names[i+1:]:
                if not name2 or len(name2) < 3:
                    continue

                # Skip if already checked
                pair_key = tuple(sorted([name1, name2]))
                if pair_key in checked_pairs:
                    continue
                checked_pairs.add(pair_key)

                # Calculate similarity
                similarity = SequenceMatcher(None, name1, name2).ratio()

                if similarity >= self.SIMILARITY_THRESHOLD and name1 != name2:
                    similar_pairs.append((name1, name2, round(similarity, 2)))

        return similar_pairs

    def _find_generic_names(self, tool_names: List[str]) -> List[str]:
        """Find tools with generic/common names"""
        generic = []

        for name in set(tool_names):
            if name.lower() in self.COMMON_TOOL_NAMES:
                generic.append(name)

        return generic

    def _detect_impersonation(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect tools attempting to impersonate legitimate services.

        Looks for brand names, service names in descriptions.
        """
        impersonations = []

        # Common service/brand patterns to watch for
        impersonation_patterns = [
            (r'\b(?:google|gmail|goog|g-suite)\b', 'google_impersonation'),
            (r'\b(?:microsoft|ms|office365|azure)\b', 'microsoft_impersonation'),
            (r'\b(?:amazon|aws|s3)\b', 'amazon_impersonation'),
            (r'\b(?:slack|slackbot)\b', 'slack_impersonation'),
            (r'\b(?:github|git)\b', 'github_impersonation'),
            (r'\b(?:openai|chatgpt|gpt)\b', 'openai_impersonation'),
        ]

        for tool in tools:
            tool_name = tool.get('name', '').lower()
            description = tool.get('description', '').lower()
            combined = f"{tool_name} {description}"

            for pattern, imp_type in impersonation_patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    impersonations.append({
                        'tool_name': tool.get('name'),
                        'pattern': imp_type,
                        'matched_text': re.findall(pattern, combined, re.IGNORECASE)[:3]
                    })
                    break  # One finding per tool is enough

        return impersonations

    def _generate_pocs(self, evidence: Dict[str, Any]) -> List[ProofOfConcept]:
        """Generate PoCs demonstrating shadowing/conflicts"""
        pocs = []

        # PoC for duplicates
        for dup in evidence.get('duplicates', [])[:2]:
            pocs.append(ProofOfConcept(
                target=dup['name'],
                attack_type="tool_shadowing",
                payload={
                    "issue_type": "duplicate_name",
                    "tool_name": dup['name']
                },
                response={
                    "duplicate_count": dup['count'],
                    "impact": "Ambiguous tool resolution - LLM may call wrong implementation"
                },
                success=True,
                impact_demonstrated=(
                    f"Tool name '{dup['name']}' appears {dup['count']} times. "
                    f"This creates ambiguity - the LLM cannot determine which "
                    f"implementation to call, enabling shadowing attacks."
                )
            ))

        # PoC for similar names
        for sim in evidence.get('similar_names', [])[:2]:
            pocs.append(ProofOfConcept(
                target=f"{sim['name1']} vs {sim['name2']}",
                attack_type="typosquatting",
                payload={
                    "issue_type": "similar_names",
                    "tool_name_1": sim['name1'],
                    "tool_name_2": sim['name2']
                },
                response={
                    "similarity": sim['similarity'],
                    "impact": "User/LLM confusion - may call wrong tool"
                },
                success=True,
                impact_demonstrated=(
                    f"Tools '{sim['name1']}' and '{sim['name2']}' are {sim['similarity']:.0%} similar. "
                    f"This enables typosquatting attacks where users/LLMs accidentally "
                    f"call the malicious lookalike instead of the legitimate tool."
                )
            ))

        # PoC for impersonation
        for imp in evidence.get('impersonation_attempts', [])[:1]:
            pocs.append(ProofOfConcept(
                target=imp['tool_name'],
                attack_type="impersonation",
                payload={
                    "issue_type": "impersonation",
                    "tool_name": imp['tool_name']
                },
                response={
                    "pattern": imp['pattern'],
                    "matched_terms": imp.get('matched_text', [])
                },
                success=True,
                impact_demonstrated=(
                    f"Tool '{imp['tool_name']}' appears to impersonate a legitimate "
                    f"service ({imp['pattern']}). This could mislead users into "
                    f"trusting a malicious tool."
                )
            ))

        return pocs
