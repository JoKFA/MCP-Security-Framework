"""
Privilege Abuse Detector (Top 25 #19)

Detects tools whose declared privileges exceed their stated purpose.

Focus areas:
- Identifies unexpected capability combinations (filesystem + command, etc.)
- Highlights simple utilities that expose high-impact actions
- Complements excessive_permissions by emphasising *mismatch* instead of breadth

Standards: CWE-250, OWASP API4, CVSS 6.5 MEDIUM
"""

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional
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


class PrivilegeAbuseDetector(Detector):
    """Detects tools with permissions that violate least-privilege expectations."""

    MODE_THRESHOLDS = {
        "safe": 0.65,
        "balanced": 0.55,
        "aggressive": 0.45,
    }

    CAPABILITY_WEIGHTS = {
        "filesystem_read": 0.25,
        "filesystem_write": 0.35,
        "filesystem_delete": 0.4,
        "network": 0.25,
        "database": 0.3,
        "command_execution": 0.45,
        "admin": 0.3,
        "credential": 0.35,
    }

    CAPABILITY_PATTERNS: Dict[str, List[re.Pattern]] = {
        "filesystem_read": [
            re.compile(r"\bread\b.*\bfile\b"),
            re.compile(r"\bopen\b.*\bfile\b"),
            re.compile(r"\bdownload\b"),
            re.compile(r"\blist\b.*\bdirector(?:y|ies)\b"),
        ],
        "filesystem_write": [
            re.compile(r"\bwrite\b.*\bfile\b"),
            re.compile(r"\bsave\b"),
            re.compile(r"\bcreate\b.*\bfile\b"),
            re.compile(r"\bupdate\b.*\bfile\b"),
            re.compile(r"\bupload\b"),
        ],
        "filesystem_delete": [
            re.compile(r"\bdelete\b"),
            re.compile(r"\bremove\b"),
            re.compile(r"\bwipe\b"),
            re.compile(r"\btruncate\b"),
        ],
        "network": [
            re.compile(r"\bhttp\b"),
            re.compile(r"\bhttps\b"),
            re.compile(r"\burl\b"),
            re.compile(r"\bapi\b"),
            re.compile(r"\brequest\b"),
            re.compile(r"\bweb\b"),
            re.compile(r"\bfetch\b"),
        ],
        "database": [
            re.compile(r"\bdatabase\b"),
            re.compile(r"\bquery\b"),
            re.compile(r"\bsql\b"),
            re.compile(r"\bdb\b"),
            re.compile(r"\btable\b"),
        ],
        "command_execution": [
            re.compile(r"\bexecute\b"),
            re.compile(r"\bcommand\b"),
            re.compile(r"\bshell\b"),
            re.compile(r"\brun\b"),
            re.compile(r"\bsystem\b"),
            re.compile(r"\bprocess\b"),
            re.compile(r"\bscript\b"),
        ],
        "admin": [
            re.compile(r"\badmin\b"),
            re.compile(r"\bmanage\b"),
            re.compile(r"\bconfig\b"),
            re.compile(r"\bsetting\b"),
            re.compile(r"\bpolicy\b"),
        ],
        "credential": [
            re.compile(r"\bpassword\b"),
            re.compile(r"\btoken\b"),
            re.compile(r"\bsecret\b"),
            re.compile(r"\bapi[_-]?key\b"),
            re.compile(r"\bcredential\b"),
        ],
    }

    SCHEMA_HINTS = {
        "filesystem_read": {"path", "file", "filename", "directory", "folder"},
        "filesystem_write": {"path", "file", "content", "data"},
        "filesystem_delete": {"delete", "remove"},
        "network": {"url", "uri", "endpoint", "host", "hostname"},
        "database": {"sql", "query", "statement"},
        "command_execution": {"command", "cmd", "script", "args", "arguments"},
        "credential": {"password", "token", "secret", "api_key"},
        "admin": {"role", "privilege", "permission"},
    }

    PURPOSE_PROFILES = [
        {
            "id": "calculator",
            "label": "Calculator / math utility",
            "patterns": [
                re.compile(r"\bcalc"),
                re.compile(r"\bmath\b"),
                re.compile(r"\barithmetic\b"),
                re.compile(r"\bcalculator\b"),
            ],
            "allowed": set(),
        },
        {
            "id": "read_only",
            "label": "Read-only information retrieval",
            "patterns": [
                re.compile(r"\bread\b"),
                re.compile(r"\bget\b"),
                re.compile(r"\bfetch\b"),
                re.compile(r"\blist\b"),
                re.compile(r"\bview\b"),
                re.compile(r"\bshow\b"),
            ],
            "allowed": {"filesystem_read", "network"},
        },
        {
            "id": "weather",
            "label": "Weather / forecast service",
            "patterns": [re.compile(r"\bweather\b"), re.compile(r"\bforecast\b")],
            "allowed": {"network"},
        },
        {
            "id": "file_management",
            "label": "File manager / document handling",
            "patterns": [
                re.compile(r"\bfile[_-]?manager\b"),
                re.compile(r"\bfile\b.*\bmanager\b"),
                re.compile(r"\bdocument\b"),
            ],
            "allowed": {"filesystem_read", "filesystem_write"},
        },
        {
            "id": "search",
            "label": "Search / lookup utility",
            "patterns": [
                re.compile(r"\bsearch\b"),
                re.compile(r"\blookup\b"),
                re.compile(r"\bquery\b"),
            ],
            "allowed": {"network", "database"},
        },
    ]

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-PA-001",
            name="Privilege Abuse Detector",
            description=(
                "Detects tools whose capabilities exceed their intended purpose, "
                "violating the principle of least privilege."
            ),
            version="1.1.0",
            prerequisites={"tools": True},
            timeout_s=30,
            severity_default="MEDIUM",
            standards=StandardsMapping(
                cwe="CWE-250",
                owasp_api="API4",
                asvs=["V4.1"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
                    base_score=6.5,
                    severity="MEDIUM",
                ),
            ),
        )

    @staticmethod
    def _normalise_text(name: str, description: str) -> str:
        combined = f"{name} {description}"
        combined = combined.replace("_", " ").replace("-", " ")
        return combined.lower()

    def _infer_capabilities(self, tool: Dict[str, Any]) -> Dict[str, List[str]]:
        """Infer capabilities hinted by the tool's metadata and schema."""
        name = tool.get("name", "")
        description = tool.get("description", "")
        text = self._normalise_text(name, description)
        capabilities: Dict[str, set] = defaultdict(set)

        for capability, patterns in self.CAPABILITY_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(text):
                    capabilities[capability].add(f"text:{pattern.pattern}")

        schema = tool.get("inputSchema") or {}
        properties = schema.get("properties") or {}
        for prop_name, prop_schema in properties.items():
            pname = str(prop_name).lower()
            for capability, hints in self.SCHEMA_HINTS.items():
                if pname in hints:
                    capabilities[capability].add(f"schema:{pname}")
            description_text = str(prop_schema.get("description", "")).lower()
            for capability, patterns in self.CAPABILITY_PATTERNS.items():
                for pattern in patterns:
                    if pattern.search(description_text):
                        capabilities[capability].add(f"schema_desc:{pattern.pattern}")

        return {cap: sorted(reasons) for cap, reasons in capabilities.items()}

    def _classify_purpose(self, tool: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        text = self._normalise_text(tool.get("name", ""), tool.get("description", ""))
        for profile in self.PURPOSE_PROFILES:
            if any(pattern.search(text) for pattern in profile["patterns"]):
                return profile
        return None

    def _evaluate_tool(
        self,
        tool: Dict[str, Any],
        capabilities: Dict[str, List[str]],
    ) -> Optional[Dict[str, Any]]:
        """Return mismatch details if the tool violates least-privilege expectations."""
        if not capabilities:
            return None

        tool_name = tool.get("name", "Unknown")
        purpose_profile = self._classify_purpose(tool)
        unexpected: List[str] = []
        reasons: List[str] = []

        if purpose_profile:
            allowed = purpose_profile["allowed"]
            for capability in capabilities:
                if capability not in allowed:
                    unexpected.append(capability)
                    reasons.append(
                        f"{capability.replace('_', ' ')} not expected for {purpose_profile['label']}"
                    )
        else:
            text = self._normalise_text(tool.get("name", ""), tool.get("description", ""))
            if re.search(r"\bread\b|\bget\b|\blist\b|\bview\b", text):
                for capability in ("filesystem_write", "filesystem_delete", "command_execution"):
                    if capability in capabilities:
                        unexpected.append(capability)
                        reasons.append(
                            f"Read-oriented tool exposes {capability.replace('_', ' ')} capability"
                        )

        high_risk_combo = "filesystem_write" in capabilities and "filesystem_delete" in capabilities
        if high_risk_combo:
            reasons.append("Tool can both write and delete files, implying wide filesystem control")
            if "filesystem_write" not in unexpected or "filesystem_delete" not in unexpected:
                unexpected.extend(
                    cap for cap in ("filesystem_write", "filesystem_delete") if cap not in unexpected
                )

        if "command_execution" in capabilities and purpose_profile and purpose_profile["id"] != "file_management":
            unexpected.append("command_execution")
            reasons.append("Command execution available despite non-administrative purpose")

        unexpected = sorted(set(unexpected))
        if not unexpected:
            return None

        score = sum(self.CAPABILITY_WEIGHTS.get(cap, 0.2) for cap in unexpected)
        if high_risk_combo:
            score += 0.15
        if purpose_profile and purpose_profile["id"] == "calculator":
            score += 0.15
        score = min(score, 0.99)

        return {
            "tool_name": tool_name,
            "purpose": purpose_profile["id"] if purpose_profile else None,
            "purpose_label": purpose_profile["label"] if purpose_profile else None,
            "detected_capabilities": capabilities,
            "unexpected_capabilities": unexpected,
            "reasons": reasons,
            "score": score,
        }

    def _build_signal_context(self, analysis: Dict[str, Any], mode: str) -> Dict[str, Any]:
        return {
            "tool_name": analysis["tool_name"],
            "unexpected_capabilities": analysis["unexpected_capabilities"],
            "purpose": analysis["purpose"],
            "mode": mode,
            "score": round(analysis["score"], 2),
        }

    def _build_poc(self, analysis: Dict[str, Any]) -> ProofOfConcept:
        return ProofOfConcept(
            target=analysis["tool_name"],
            attack_type="privilege_mismatch_detection",
            payload={
                "detected_capabilities": analysis["unexpected_capabilities"],
                "purpose": analysis["purpose"],
            },
            response={
                "reasons": analysis["reasons"],
                "detected_capabilities": analysis["detected_capabilities"],
            },
            success=True,
            impact_demonstrated=(
                f"Tool '{analysis['tool_name']}' exposes {', '.join(analysis['unexpected_capabilities'])} "
                "capabilities despite its declared purpose, enabling privilege abuse."
            ),
        )

    async def run(
        self,
        adapter: Any,
        scope: Optional[Any] = None,
        profile: Optional[Any] = None,  # noqa: ARG002 - reserved for future profile-sensitive logic
    ) -> DetectionResult:
        """
        Analyse the tool catalogue for privilege mismatches.

        Flow: enumerate tools → infer capabilities → compare with purpose → emit mismatches.
        """
        mode = (scope or {}).get("mode", "balanced") if scope else "balanced"
        threshold = self.MODE_THRESHOLDS.get(mode, self.MODE_THRESHOLDS["balanced"])

        signals: List[Signal] = []
        mismatches: List[Dict[str, Any]] = []
        evidence: Dict[str, Any] = {
            "mode": mode,
            "threshold": threshold,
            "tools_analyzed": 0,
            "analysis": [],
        }
        start_time = datetime.now(timezone.utc)

        try:
            tools = await adapter.list_tools()
            evidence["tools_analyzed"] = len(tools)

            for tool in tools:
                capabilities = self._infer_capabilities(tool)
                summary = {
                    "tool_name": tool.get("name", "Unknown"),
                    "detected_capabilities": sorted(capabilities.keys()),
                    "score": 0.0,
                    "flagged": False,
                }

                analysis = self._evaluate_tool(tool, capabilities)
                if analysis:
                    summary["score"] = round(analysis["score"], 2)
                    summary["flagged"] = analysis["score"] >= threshold
                    summary["unexpected_capabilities"] = analysis["unexpected_capabilities"]
                    summary["purpose"] = analysis["purpose"]

                    if analysis["score"] >= threshold:
                        mismatches.append(analysis)
                        signals.append(
                            Signal(
                                type=SignalType.SCHEMA_OVERPERMISSIVE,
                                value=True,
                                context=self._build_signal_context(analysis, mode),
                            )
                        )

                evidence["analysis"].append(summary)

            if mismatches:
                mismatches.sort(key=lambda item: item["score"], reverse=True)
                confidence = min(0.95, 0.6 + mismatches[0]["score"] * 0.4)
                pocs = [self._build_poc(item) for item in mismatches[:3]]
                evidence["flagged_tools"] = [
                    {
                        "tool_name": item["tool_name"],
                        "unexpected_capabilities": item["unexpected_capabilities"],
                        "score": round(item["score"], 2),
                        "purpose": item["purpose"],
                    }
                    for item in mismatches
                ]
                status = DetectionStatus.PRESENT
            else:
                confidence = 0.8
                pocs = []
                status = DetectionStatus.ABSENT

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
                timestamp=start_time,
            )

        except Exception as exc:  # pylint: disable=broad-except
            return DetectionResult(
                detector_id=self.metadata.id,
                detector_name=self.metadata.name,
                detector_version=self.metadata.version,
                status=DetectionStatus.UNKNOWN,
                confidence=0.0,
                signals=[],
                evidence={"error": str(exc)},
                standards=self.metadata.standards,
                timestamp=start_time,
            )
