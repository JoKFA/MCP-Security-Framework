"""
SARIF reporter for MCP Security Framework.

Generates SARIF 2.1.0 format reports for integration with security tooling.
Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
from typing import Any, Dict, List
from datetime import datetime

from .base import Reporter
from ..models import AssessmentResult, DetectionResult, Signal, ProofOfConcept


class SARIFReporter(Reporter):
    """
    Generates SARIF 2.1.0 compliant reports.

    SARIF (Static Analysis Results Interchange Format) is an industry-standard
    format for security tool output, supported by GitHub, Azure DevOps, and others.

    Features:
    - Full detector metadata as rules
    - Signals as results with locations
    - PoCs as code flows
    - Standards mappings (CWE, CVSS)
    - Tool fingerprinting
    """

    @property
    def format_name(self) -> str:
        return "sarif"

    @property
    def file_extension(self) -> str:
        return "sarif"

    def generate(self, assessment: AssessmentResult) -> str:
        """
        Generate SARIF 2.1.0 report from assessment result.

        Args:
            assessment: The assessment result

        Returns:
            SARIF JSON string
        """
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [self._create_run(assessment)]
        }

        return json.dumps(sarif, indent=2, default=str)

    def _create_run(self, assessment: AssessmentResult) -> Dict[str, Any]:
        """Create a SARIF run object."""
        return {
            "tool": self._create_tool(assessment),
            "invocations": [self._create_invocation(assessment)],
            "results": self._create_results(assessment),
            "artifacts": self._create_artifacts(assessment),
            "properties": {
                "assessment_id": assessment.assessment_id,
                "target_server": assessment.profile.server_name,
                "target_version": assessment.profile.server_version,
                "transport": assessment.profile.transport,
                "exposure": assessment.profile.exposure,
            }
        }

    def _create_tool(self, assessment: AssessmentResult) -> Dict[str, Any]:
        """Create SARIF tool object."""
        # Build rules from all detectors
        rules = []
        for result in assessment.results:
            rule = self._create_rule(result)
            rules.append(rule)

        return {
            "driver": {
                "name": "MCP Security Framework",
                "version": assessment.framework_version,
                "informationUri": "https://github.com/yourusername/mcp-security-framework",
                "organization": "MCP Security Project",
                "semanticVersion": assessment.framework_version,
                "rules": rules
            }
        }

    def _create_rule(self, result: DetectionResult) -> Dict[str, Any]:
        """Create a SARIF rule from a detector result."""
        rule = {
            "id": result.detector_id,
            "name": result.detector_name,
            "shortDescription": {
                "text": result.detector_name
            },
            "fullDescription": {
                "text": result.evidence.get('description', f"{result.detector_name} detector")
            },
            "help": {
                "text": result.remediation or "No remediation guidance available."
            },
            "properties": {
                "confidence": result.confidence,
                "precision": "high" if result.confidence >= 0.9 else "medium" if result.confidence >= 0.7 else "low",
            }
        }

        # Add security severity
        if result.standards.cvss:
            cvss = result.standards.cvss
            rule["properties"]["security-severity"] = str(cvss.base_score)

            # Map CVSS severity to SARIF level
            severity_map = {
                "CRITICAL": "error",
                "HIGH": "error",
                "MEDIUM": "warning",
                "LOW": "note",
                "NONE": "none"
            }
            rule["defaultConfiguration"] = {
                "level": severity_map.get(cvss.severity, "warning")
            }

        # Add standards tags
        tags = []
        if result.standards.cwe:
            tags.append(f"external/cwe/{result.standards.cwe}")
        if result.standards.owasp_llm:
            tags.append(f"external/owasp-llm/{result.standards.owasp_llm}")
        if result.standards.owasp_api:
            tags.append(f"external/owasp-api/{result.standards.owasp_api}")

        if tags:
            rule["properties"]["tags"] = tags

        return rule

    def _create_invocation(self, assessment: AssessmentResult) -> Dict[str, Any]:
        """Create SARIF invocation object."""
        return {
            "executionSuccessful": True,
            "startTimeUtc": assessment.started_at.isoformat(),
            "endTimeUtc": assessment.completed_at.isoformat(),
            "workingDirectory": {
                "uri": "file:///"
            },
            "properties": {
                "scope": assessment.scope
            }
        }

    def _create_results(self, assessment: AssessmentResult) -> List[Dict[str, Any]]:
        """Create SARIF results from detector findings."""
        results = []

        for detector_result in assessment.results:
            # Only report PRESENT findings
            if detector_result.status.value != "PRESENT":
                continue

            # Create a result for each signal
            for signal in detector_result.signals:
                signal_type = signal.type if isinstance(signal.type, str) else signal.type.value
                sarif_result = {
                    "ruleId": detector_result.detector_id,
                    "message": {
                        "text": self._format_signal_message(signal, detector_result)
                    },
                    "level": self._get_sarif_level(detector_result),
                    "properties": {
                        "signal_type": signal_type,
                        "confidence": detector_result.confidence,
                    }
                }

                # Add location if available
                if signal.context.get('resource_uri') or signal.context.get('tool_name'):
                    sarif_result["locations"] = [self._create_location(signal)]

                # Add code flows from PoCs
                if detector_result.proof_of_concepts:
                    sarif_result["codeFlows"] = self._create_code_flows(detector_result.proof_of_concepts)

                # Add related locations (affected resources)
                if detector_result.affected_resources:
                    sarif_result["relatedLocations"] = [
                        self._create_related_location(uri)
                        for uri in detector_result.affected_resources[:5]
                    ]

                results.append(sarif_result)

        return results

    def _format_signal_message(self, signal: Signal, result: DetectionResult) -> str:
        """Format signal into SARIF message."""
        rationale = signal.context.get('rationale', '')
        if rationale:
            return rationale

        # Fallback message
        signal_type = signal.type if isinstance(signal.type, str) else signal.type.value
        return f"{result.detector_name}: {signal_type} detected"

    def _get_sarif_level(self, result: DetectionResult) -> str:
        """Map severity to SARIF level."""
        if result.standards.cvss:
            severity = result.standards.cvss.severity
            level_map = {
                "CRITICAL": "error",
                "HIGH": "error",
                "MEDIUM": "warning",
                "LOW": "note",
            }
            return level_map.get(severity, "warning")
        return "warning"

    def _create_location(self, signal: Signal) -> Dict[str, Any]:
        """Create SARIF location from signal context."""
        uri = signal.context.get('resource_uri') or signal.context.get('tool_name', 'unknown')

        return {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": uri
                },
                "region": {
                    "startLine": 1,
                    "snippet": {
                        "text": str(signal.context)
                    }
                }
            }
        }

    def _create_related_location(self, uri: str) -> Dict[str, Any]:
        """Create SARIF related location."""
        return {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": uri
                }
            },
            "message": {
                "text": f"Affected resource: {uri}"
            }
        }

    def _create_code_flows(self, pocs: List[ProofOfConcept]) -> List[Dict[str, Any]]:
        """Create SARIF code flows from proof of concepts."""
        flows = []

        for poc in pocs[:3]:  # Limit to 3 PoCs
            flow = {
                "message": {
                    "text": poc.impact_demonstrated
                },
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "message": {
                                        "text": f"Attack: {poc.attack_type}"
                                    },
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": poc.target
                                        }
                                    }
                                },
                                "state": {
                                    "payload": poc.payload,
                                    "response": poc.response,
                                    "success": poc.success
                                }
                            }
                        ]
                    }
                ]
            }
            flows.append(flow)

        return flows

    def _create_artifacts(self, assessment: AssessmentResult) -> List[Dict[str, Any]]:
        """Create SARIF artifacts list."""
        artifacts = []

        # Collect all unique URIs from affected resources
        uris = set()
        for result in assessment.results:
            uris.update(result.affected_resources)

        for uri in uris:
            artifacts.append({
                "location": {
                    "uri": uri
                },
                "roles": ["analysisTarget"]
            })

        return artifacts
