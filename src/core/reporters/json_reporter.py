"""
JSON reporter for MCP Security Framework.

Generates machine-readable JSON reports with full details.
"""

import json
from typing import Any, Dict

from .base import Reporter
from ..models import AssessmentResult


class JSONReporter(Reporter):
    """
    Generates comprehensive JSON reports.

    Output includes:
    - Full assessment metadata
    - All detector results with signals and evidence
    - Proof of concepts
    - Standards mappings (CWE, OWASP, CVSS)
    - Threat model and attack chains
    """

    def __init__(self, pretty: bool = True, include_evidence: bool = True):
        """
        Initialize JSON reporter.

        Args:
            pretty: If True, format JSON with indentation
            include_evidence: If True, include full evidence details
        """
        self.pretty = pretty
        self.include_evidence = include_evidence

    @property
    def format_name(self) -> str:
        return "json"

    @property
    def file_extension(self) -> str:
        return "json"

    def generate(self, assessment: AssessmentResult) -> str:
        """
        Generate JSON report from assessment result.

        Args:
            assessment: The assessment result

        Returns:
            JSON string with full assessment data
        """
        # Convert Pydantic model to dict
        data = assessment.model_dump(mode='json')

        # Optionally strip evidence to reduce size
        if not self.include_evidence:
            for result in data.get('results', []):
                if 'evidence' in result:
                    # Keep only summary info
                    evidence = result['evidence']
                    result['evidence'] = {
                        'summary': f"{len(str(evidence))} bytes (redacted)"
                    }

        # Serialize with optional pretty printing
        if self.pretty:
            return json.dumps(data, indent=2, default=str)
        else:
            return json.dumps(data, default=str)

    def generate_summary(self, assessment: AssessmentResult) -> Dict[str, Any]:
        """
        Generate a summary-only JSON object.

        Args:
            assessment: The assessment result

        Returns:
            Dictionary with summary statistics
        """
        summary = {
            'assessment_id': assessment.assessment_id,
            'started_at': assessment.started_at.isoformat(),
            'completed_at': assessment.completed_at.isoformat(),
            'duration_seconds': (assessment.completed_at - assessment.started_at).total_seconds(),
            'target': {
                'server_name': assessment.profile.server_name,
                'server_version': assessment.profile.server_version,
                'transport': assessment.profile.transport,
                'exposure': assessment.profile.exposure,
            },
            'summary': assessment.summary,
            'detectors_run': len(assessment.results),
            'findings': {
                'present': [],
                'absent': [],
                'unknown': [],
                'not_applicable': []
            },
            'threat_model': None
        }

        # Categorize findings
        for result in assessment.results:
            finding = {
                'detector_id': result.detector_id,
                'detector_name': result.detector_name,
                'confidence': result.confidence,
                'signal_count': len(result.signals),
                'poc_count': len(result.proof_of_concepts),
                'affected_resources': result.affected_resources,
            }

            status_key = result.status.value.lower()
            if status_key in summary['findings']:
                summary['findings'][status_key].append(finding)

        # Add threat model if present
        if assessment.threat_model:
            summary['threat_model'] = {
                'overall_risk': assessment.threat_model.overall_risk,
                'risk_level': assessment.threat_model.risk_level,
                'attack_chains': len(assessment.threat_model.chains),
                'mitigations': len(assessment.threat_model.prioritized_mitigations),
            }

        return summary
