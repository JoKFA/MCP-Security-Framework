"""
CLI reporter for MCP Security Framework.

Generates human-readable colored console output.
"""

from typing import List
from datetime import datetime

from .base import Reporter
from ..models import AssessmentResult, DetectionResult, DetectionStatus, ProofOfConcept


class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Status colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

    # Severity colors
    CRITICAL = '\033[95m'  # Magenta
    HIGH = '\033[91m'      # Red
    MEDIUM = '\033[93m'    # Yellow
    LOW = '\033[92m'       # Green


class CLIReporter(Reporter):
    """
    Generates colored CLI output for terminal display.

    Features:
    - Color-coded severity levels
    - Unicode box drawing characters
    - Summary statistics
    - Detailed findings with PoCs
    - Standards compliance information
    """

    def __init__(self, use_colors: bool = True, verbose: bool = False):
        """
        Initialize CLI reporter.

        Args:
            use_colors: If True, use ANSI color codes
            verbose: If True, include full evidence details
        """
        self.use_colors = use_colors
        self.verbose = verbose

    @property
    def format_name(self) -> str:
        return "cli"

    @property
    def file_extension(self) -> str:
        return "txt"

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors enabled."""
        if self.use_colors:
            return f"{color}{text}{Colors.RESET}"
        return text

    def _status_icon(self, status: DetectionStatus) -> str:
        """Get icon for detection status."""
        icons = {
            DetectionStatus.PRESENT: self._color('✗', Colors.RED),
            DetectionStatus.ABSENT: self._color('✓', Colors.GREEN),
            DetectionStatus.UNKNOWN: self._color('?', Colors.YELLOW),
            DetectionStatus.NOT_APPLICABLE: self._color('-', Colors.GRAY),
        }
        return icons.get(status, '?')

    def _severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            'CRITICAL': Colors.CRITICAL,
            'HIGH': Colors.HIGH,
            'MEDIUM': Colors.MEDIUM,
            'LOW': Colors.LOW,
        }
        return colors.get(severity.upper(), Colors.WHITE)

    def generate(self, assessment: AssessmentResult) -> str:
        """
        Generate CLI report from assessment result.

        Args:
            assessment: The assessment result

        Returns:
            Formatted CLI output string
        """
        lines = []

        # Header
        lines.append(self._color('=' * 80, Colors.CYAN))
        lines.append(self._color('  MCP SECURITY ASSESSMENT REPORT', Colors.BOLD + Colors.CYAN))
        lines.append(self._color('=' * 80, Colors.CYAN))
        lines.append('')

        # Target information
        lines.append(self._color('TARGET INFORMATION', Colors.BOLD))
        lines.append(self._color('─' * 80, Colors.GRAY))
        lines.append(f"Server:       {self._color(assessment.profile.server_name, Colors.WHITE)}")
        lines.append(f"Version:      {assessment.profile.server_version}")
        lines.append(f"Transport:    {assessment.profile.transport}")
        lines.append(f"Exposure:     {self._color(assessment.profile.exposure.upper(), Colors.YELLOW)}")
        lines.append(f"Assessment:   {assessment.assessment_id}")

        duration = (assessment.completed_at - assessment.started_at).total_seconds()
        lines.append(f"Duration:     {duration:.2f}s")
        lines.append('')

        # Summary statistics
        lines.append(self._color('SUMMARY', Colors.BOLD))
        lines.append(self._color('─' * 80, Colors.GRAY))

        present = assessment.summary.get('present', 0)
        absent = assessment.summary.get('absent', 0)
        unknown = assessment.summary.get('unknown', 0)
        not_applicable = assessment.summary.get('not_applicable', 0)

        lines.append(f"Detectors Run:      {len(assessment.results)}")
        lines.append(f"  {self._color('✗ Vulnerabilities:', Colors.RED)}  {self._color(str(present), Colors.BOLD + Colors.RED)}")
        lines.append(f"  {self._color('✓ Passed:', Colors.GREEN)}          {absent}")
        lines.append(f"  {self._color('? Unknown:', Colors.YELLOW)}         {unknown}")
        lines.append(f"  {self._color('- Not Applicable:', Colors.GRAY)}   {not_applicable}")
        lines.append('')

        # Findings
        if present > 0:
            lines.append(self._color('VULNERABILITIES DETECTED', Colors.BOLD + Colors.RED))
            lines.append(self._color('─' * 80, Colors.GRAY))
            lines.append('')

            for result in assessment.results:
                if result.status == DetectionStatus.PRESENT:
                    lines.extend(self._format_finding(result))

        # Clean results
        clean_results = [r for r in assessment.results if r.status == DetectionStatus.ABSENT]
        if clean_results and self.verbose:
            lines.append(self._color('PASSED CHECKS', Colors.BOLD + Colors.GREEN))
            lines.append(self._color('─' * 80, Colors.GRAY))
            for result in clean_results:
                lines.append(f"{self._status_icon(result.status)} {result.detector_name}")
            lines.append('')

        # Threat model
        if assessment.threat_model:
            lines.extend(self._format_threat_model(assessment))

        # Footer
        lines.append(self._color('─' * 80, Colors.GRAY))
        lines.append(self._color(f'Report generated: {datetime.now().isoformat()}', Colors.DIM))
        lines.append(self._color(f'Framework version: {assessment.framework_version}', Colors.DIM))
        lines.append(self._color('=' * 80, Colors.CYAN))

        return '\n'.join(lines)

    def _format_finding(self, result: DetectionResult) -> List[str]:
        """Format a single finding with details."""
        lines = []

        # Finding header with severity
        severity = result.standards.cvss.severity if result.standards.cvss else result.evidence.get('severity', 'UNKNOWN')
        severity_colored = self._color(severity, self._severity_color(severity))

        lines.append('')
        lines.append(self._color('=' * 80, Colors.GRAY))
        lines.append(self._color(f'FINDING: {result.detector_name}', Colors.BOLD))
        lines.append(self._color('=' * 80, Colors.GRAY))
        lines.append('')

        # Basic info
        lines.append(f"Detector ID:     {result.detector_id}")
        lines.append(f"Severity:        {severity_colored}")
        lines.append(f"Confidence:      {result.confidence * 100:.0f}%")
        lines.append(f"Status:          {self._status_icon(result.status)} {result.status.value}")
        lines.append('')

        # Standards mapping
        lines.append(self._color('Standards Mapping:', Colors.BOLD))
        if result.standards.cwe:
            lines.append(f"  CWE:           {result.standards.cwe}")
        if result.standards.owasp_llm:
            lines.append(f"  OWASP LLM:     {result.standards.owasp_llm}")
        if result.standards.owasp_api:
            lines.append(f"  OWASP API:     {result.standards.owasp_api}")
        if result.standards.cvss:
            lines.append(f"  CVSS Score:    {result.standards.cvss.base_score}/10")
            lines.append(f"  CVSS Vector:   {result.standards.cvss.vector}")
        lines.append('')

        # Signals detected
        if result.signals:
            lines.append(self._color(f'Signals Detected: {len(result.signals)}', Colors.BOLD))
            for i, signal in enumerate(result.signals, 1):
                signal_type = signal.type if isinstance(signal.type, str) else signal.type.value
                rationale = signal.context.get('rationale', str(signal.value))
                lines.append(f"  {i}. [{signal_type}]")
                lines.append(f"     {rationale}")

                # Show key context items
                if signal.context:
                    for key, val in list(signal.context.items())[:3]:
                        if key not in ['rationale', 'reason'] and val and len(str(val)) < 100:
                            lines.append(f"     {key}: {val}")
            lines.append('')

        # Affected resources
        if result.affected_resources:
            lines.append(self._color('Affected Resources:', Colors.BOLD))
            for resource in result.affected_resources:
                lines.append(f"  - {resource}")
            lines.append('')

        # Evidence summary
        if result.evidence and self.verbose:
            lines.append(self._color('Evidence Summary:', Colors.BOLD))
            for key, val in list(result.evidence.items())[:5]:
                if not isinstance(val, dict) and len(str(val)) < 100:
                    lines.append(f"  {key}: {val}")
            lines.append('')

        # Proof of concepts (DETAILED)
        if result.proof_of_concepts:
            lines.append(self._color(f'PROOF OF CONCEPT: {len(result.proof_of_concepts)} exploit(s) demonstrated', Colors.BOLD + Colors.RED))
            lines.append(self._color('-' * 80, Colors.GRAY))

            for i, poc in enumerate(result.proof_of_concepts, 1):
                lines.append('')
                lines.append(self._color(f'PoC #{i}: {poc.attack_type.upper()}', Colors.BOLD))
                lines.append(f"  Target:        {poc.target}")
                lines.append(f"  Success:       {'YES' if poc.success else 'NO'}")
                lines.append(f"  Timestamp:     {poc.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                lines.append('')
                lines.append(f"  Impact:")
                lines.append(f"    {poc.impact_demonstrated}")
                lines.append('')

                # Show payload
                lines.append(f"  Attack Payload:")
                for key, val in poc.payload.items():
                    lines.append(f"    {key}: {val}")
                lines.append('')

                # Show response with samples
                lines.append(f"  Server Response:")
                if isinstance(poc.response, dict):
                    for key, val in poc.response.items():
                        if key == 'samples' and isinstance(val, dict):
                            lines.append(f"    Leaked Secrets:")
                            for secret_type, samples in val.items():
                                lines.append(f"      {secret_type}:")
                                for sample in samples:
                                    lines.append(f"        - {sample}")
                        else:
                            lines.append(f"    {key}: {val}")
                else:
                    lines.append(f"    {poc.response}")

            lines.append('')
            lines.append(self._color('-' * 80, Colors.GRAY))
            lines.append('')

        # Remediation
        if result.remediation:
            lines.append(self._color('REMEDIATION:', Colors.BOLD + Colors.GREEN))
            # Split by sentence and format as list
            sentences = [s.strip() for s in result.remediation.replace('. ', '.|').split('|') if s.strip()]
            for sentence in sentences:
                lines.append(f"  - {sentence}")
            lines.append('')

        return lines

    def _format_threat_model(self, assessment: AssessmentResult) -> List[str]:
        """Format threat model section."""
        lines = []
        tm = assessment.threat_model

        lines.append(self._color('THREAT MODEL', Colors.BOLD))
        lines.append(self._color('─' * 80, Colors.GRAY))

        risk_color = self._severity_color(tm.risk_level)
        lines.append(f"Overall Risk:   {self._color(f'{tm.overall_risk:.1f}/10', risk_color)} ({tm.risk_level})")
        lines.append(f"Attack Chains:  {len(tm.chains)}")
        lines.append('')

        if tm.chains:
            lines.append(self._color('Attack Chains:', Colors.BOLD))
            for chain in tm.chains:
                lines.append(f"  - {self._color(chain.name, Colors.YELLOW)} [{chain.severity}]")
                lines.append(f"    Impact: {chain.impact}")
                signal_types = [str(s.type) if isinstance(s.type, str) else str(s.type.value) for s in chain.detected_signals]
                lines.append(f"    Signals: {', '.join(signal_types)}")
            lines.append('')

        if tm.prioritized_mitigations:
            lines.append(self._color('Recommended Actions (Prioritized):', Colors.BOLD))
            for action in tm.prioritized_mitigations[:5]:
                lines.append(f"  {action.priority}. {action.action}")
                lines.append(f"     Effort: {action.effort} | Impact: {action.impact}")
            lines.append('')

        return lines
