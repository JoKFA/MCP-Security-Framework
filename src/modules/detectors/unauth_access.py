"""
Unauthenticated Access Detector (Top 25 #5)

Detects if MCP servers are accessible without authentication.

How it works:
- Enumerates tools/resources using the default adapter context
- Flags servers that expose tool/resource listings without auth
- Emits partial findings when only a subset is exposed

Standards: CWE-284, OWASP API1, CVSS 10.0 CRITICAL
"""

from typing import Any, Dict, List, Optional, Tuple
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


class UnauthenticatedAccessDetector(Detector):
    """Detects if an MCP server allows unauthenticated access."""

    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="MCP-2024-UA-001",
            name="Unauthenticated Access Detector",
            description=(
                "Detects MCP servers that are accessible without authentication (Top 25 #5)"
            ),
            version="1.1.0",
            prerequisites={"tools": True},
            timeout_s=30,
            severity_default="CRITICAL",
            standards=StandardsMapping(
                cwe="CWE-284",
                owasp_api="API1",
                asvs=["V1.1"],
                cvss=CVSSVector(
                    version="3.1",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=10.0,
                    severity="CRITICAL",
                ),
            ),
        )

    @staticmethod
    def _is_auth_error(error: Optional[str]) -> bool:
        """Best-effort detection of authentication failures from adapter errors."""
        if not error:
            return False
        lowered = error.lower()
        return any(keyword in lowered for keyword in ("unauth", "forbidden", "401", "403", "auth"))

    @staticmethod
    async def _attempt_listing(action) -> Tuple[bool, List[Any], Optional[str]]:
        """Execute an adapter listing call and capture success, results, and error."""
        try:
            result = await action()
            if result is None:
                result = []
            return True, list(result), None
        except Exception as exc:  # pylint: disable=broad-except
            return False, [], str(exc)

    @staticmethod
    def _sample_names(items: List[Dict[str, Any]], key: str = "name", limit: int = 5) -> List[str]:
        """Extract a small sample of item identifiers for evidence reporting."""
        names: List[str] = []
        for item in items:
            value = item.get(key)
            if isinstance(value, str):
                names.append(value)
            if len(names) >= limit:
                break
        return names

    async def run(
        self,
        adapter: Any,
        scope: Optional[Any] = None,
        profile: Optional[Any] = None,
    ) -> DetectionResult:
        """
        Check whether the target server requires authentication.

        Flow: enumerate → assess exposure → emit signals/PoCs.
        """
        mode = (scope or {}).get("mode", "balanced") if scope else "balanced"
        signals: List[Signal] = []
        evidence: Dict[str, Any] = {
            "mode": mode,
            "tools_accessible": False,
            "resources_accessible": False,
            "resources_supported": True,
            "auth_required": False,
            "errors": {},
        }
        start_time = datetime.now(timezone.utc)
        pocs: List[ProofOfConcept] = []

        resources_supported = True
        if profile and getattr(profile, "capabilities", None):
            resources_supported = bool(getattr(profile.capabilities, "resources", True))
        evidence["resources_supported"] = resources_supported

        try:
            tools_accessible, tools, tools_error = await self._attempt_listing(adapter.list_tools)
            evidence["tools_accessible"] = tools_accessible
            if tools_error:
                evidence["errors"]["tools"] = tools_error

            resources: List[Dict[str, Any]] = []
            resources_accessible = False
            resources_error: Optional[str] = None

            if resources_supported:
                resources_accessible, resources, resources_error = await self._attempt_listing(
                    adapter.list_resources
                )
                evidence["resources_accessible"] = resources_accessible
                if resources_error:
                    evidence["errors"]["resources"] = resources_error
            else:
                evidence["resources_accessible"] = False

            if tools_accessible:
                evidence["tool_samples"] = self._sample_names(tools)
                evidence["tool_count"] = len(tools)

            if resources_accessible:
                evidence["resource_samples"] = self._sample_names(resources, key="uri")
                evidence["resource_count"] = len(resources)

            unauth_tools = tools_accessible
            unauth_resources = resources_accessible and resources_supported

            if unauth_tools and (unauth_resources or not resources_supported):
                status = DetectionStatus.PRESENT
                confidence = 0.95 if unauth_resources else 0.9

                signals.append(
                    Signal(
                        type=SignalType.AUTH_MISMATCH,
                        value=True,
                        context={
                            "tools_accessible": unauth_tools,
                            "resources_accessible": resources_accessible,
                            "resources_supported": resources_supported,
                            "vulnerability": "unauthenticated_access",
                            "severity": "CRITICAL" if unauth_resources else "HIGH",
                        },
                    )
                )

                pocs.append(
                    ProofOfConcept(
                        target="MCP Server",
                        attack_type="unauthenticated_access_test",
                        payload={
                            "operations": ["list_tools"]
                            + (["list_resources"] if resources_supported else []),
                            "authenticated": False,
                        },
                        response={
                            "tools_count": len(tools),
                            "resources_count": len(resources) if resources_supported else None,
                            "tool_samples": evidence.get("tool_samples", []),
                            "resource_samples": evidence.get("resource_samples", []),
                            "vulnerable": True,
                        },
                        success=True,
                        impact_demonstrated=(
                            "Server exposes both tools and resources without authentication, allowing"
                            " reconnaissance by unauthenticated clients."
                            if resources_supported
                            else "Server exposes tool enumeration without authentication."
                        ),
                    )
                )

            elif unauth_tools or unauth_resources:
                status = DetectionStatus.PRESENT
                confidence = 0.7

                signals.append(
                    Signal(
                        type=SignalType.AUTH_MISMATCH,
                        value=True,
                        context={
                            "tools_accessible": unauth_tools,
                            "resources_accessible": resources_accessible,
                            "resources_supported": resources_supported,
                            "vulnerability": "partial_unauthenticated_access",
                        },
                    )
                )
            else:
                auth_indicators: List[bool] = []
                if not tools_accessible:
                    auth_indicators.append(self._is_auth_error(tools_error))
                if resources_supported and not resources_accessible:
                    auth_indicators.append(self._is_auth_error(resources_error))

                if auth_indicators and all(auth_indicators):
                    status = DetectionStatus.ABSENT
                    confidence = 0.85
                    evidence["auth_required"] = True
                else:
                    status = DetectionStatus.UNKNOWN
                    confidence = 0.3

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

