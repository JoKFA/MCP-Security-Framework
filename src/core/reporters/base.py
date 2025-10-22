"""
Base reporter interface for MCP Security Framework.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict
from pathlib import Path

from ..models import AssessmentResult


class Reporter(ABC):
    """
    Abstract base class for report generators.

    All reporters must implement the generate() method.
    """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """
        Get the format name for this reporter.

        Returns:
            Format name (e.g., "json", "sarif", "cli")
        """
        pass

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """
        Get the file extension for this reporter.

        Returns:
            File extension without dot (e.g., "json", "sarif", "txt")
        """
        pass

    @abstractmethod
    def generate(self, assessment: AssessmentResult) -> str:
        """
        Generate a report from an assessment result.

        Args:
            assessment: The assessment result to report

        Returns:
            Report content as string
        """
        pass

    def save(self, content: str, output_path: Path) -> None:
        """
        Save report content to file.

        Args:
            content: Report content to save
            output_path: Path to save the report
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding='utf-8')
