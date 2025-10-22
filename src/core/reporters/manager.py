"""
Report manager for MCP Security Framework.

Orchestrates multiple report formats and handles file storage.
"""

from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from .base import Reporter
from .json_reporter import JSONReporter
from .cli_reporter import CLIReporter
from .sarif_reporter import SARIFReporter
from ..models import AssessmentResult


class ReportManager:
    """
    Manages report generation and storage.

    Features:
    - Multiple output formats (JSON, CLI, SARIF)
    - Automatic file naming with timestamps
    - Organized folder structure:
      - reports/ - contains only final bundles
      - captures/ - contains audit logs and raw evidence
    - Audit log preservation
    """

    def __init__(self, reports_dir: Optional[Path] = None, captures_dir: Optional[Path] = None):
        """
        Initialize report manager.

        Args:
            reports_dir: Directory for final reports/bundles (default: ./reports)
            captures_dir: Directory for audit logs/raw evidence (default: ./captures)
        """
        self.reports_dir = reports_dir or Path("reports")
        self.captures_dir = captures_dir or Path("captures")

        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.captures_dir.mkdir(parents=True, exist_ok=True)

        # Initialize reporters
        self.reporters: Dict[str, Reporter] = {
            'json': JSONReporter(pretty=True, include_evidence=True),
            'json-summary': JSONReporter(pretty=True, include_evidence=False),
            'cli': CLIReporter(use_colors=True, verbose=False),
            'cli-verbose': CLIReporter(use_colors=True, verbose=True),
            'cli-plain': CLIReporter(use_colors=False, verbose=False),
            'sarif': SARIFReporter(),
        }

    def generate_bundle(
        self,
        assessment: AssessmentResult,
        bundle_name: Optional[str] = None,
        include_formats: Optional[List[str]] = None
    ) -> Path:
        """
        Generate a complete assessment bundle with all reports.

        This is the PRIMARY method for creating reports. It creates:
        - A bundle directory in reports/
        - All report formats inside the bundle
        - Audit log copied from captures/ to bundle
        - Metadata file

        Args:
            assessment: The assessment result
            bundle_name: Optional bundle directory name
            include_formats: Formats to include (default: json, cli, sarif)

        Returns:
            Path to bundle directory
        """
        if include_formats is None:
            include_formats = ['json', 'cli', 'sarif']

        # Create bundle directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        assessment_id = assessment.assessment_id.split('-')[0]

        if bundle_name:
            bundle_dir = self.reports_dir / bundle_name
        else:
            server_safe = assessment.profile.server_name.replace(' ', '_').replace('/', '_')
            bundle_dir = self.reports_dir / f"{server_safe}_{timestamp}"

        bundle_dir.mkdir(parents=True, exist_ok=True)

        # Generate all reports in bundle
        for format_name in include_formats:
            if format_name not in self.reporters:
                continue

            # Use plain text reporter (no colors) for file output
            if format_name == 'cli':
                reporter = CLIReporter(use_colors=False, verbose=False)
            else:
                reporter = self.reporters[format_name]

            content = reporter.generate(assessment)
            filename = f"report.{reporter.file_extension}"
            reporter.save(content, bundle_dir / filename)

        # Copy audit log from captures/ to bundle
        if assessment.audit_log_path:
            source = Path(assessment.audit_log_path)
            if source.exists():
                import shutil
                shutil.copy2(source, bundle_dir / "audit.jsonl")

        # Create metadata file
        metadata = {
            "assessment_id": assessment.assessment_id,
            "target": assessment.profile.server_name,
            "started_at": assessment.started_at.isoformat(),
            "completed_at": assessment.completed_at.isoformat(),
            "framework_version": assessment.framework_version,
            "summary": assessment.summary,
        }

        import json
        (bundle_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2),
            encoding='utf-8'
        )

        return bundle_dir

    def generate_cli_output(self, assessment: AssessmentResult, verbose: bool = False, use_colors: bool = False) -> str:
        """
        Generate CLI output without saving to file (for console display).

        Args:
            assessment: The assessment result
            verbose: If True, include all details
            use_colors: If True, use ANSI colors (may cause issues on Windows)

        Returns:
            Formatted CLI output string
        """
        reporter = CLIReporter(use_colors=use_colors, verbose=verbose)
        return reporter.generate(assessment)

    def print_summary(self, assessment: AssessmentResult) -> None:
        """
        Print a quick summary to console.

        Args:
            assessment: The assessment result
        """
        present = assessment.summary.get('present', 0)
        absent = assessment.summary.get('absent', 0)

        print(f"[OK] Assessment Complete: {assessment.profile.server_name}")
        print(f"   Vulnerabilities: {present}")
        print(f"   Clean checks: {absent}")
        print(f"   Duration: {(assessment.completed_at - assessment.started_at).total_seconds():.2f}s")

        if present > 0:
            print(f"\n   [WARNING] Issues detected - review full report")
