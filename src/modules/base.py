"""
Base module interface for MCP security testing modules
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a security finding"""
    type: str
    severity: Severity
    resource: str
    description: str
    evidence: str
    attack_vector: Optional[str] = None
    attack_chain: Optional[List[str]] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class TestResult:
    """Result of a security test module execution"""
    findings: List[Finding]
    success: bool
    error_message: Optional[str] = None
    execution_time: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None


class BaseSecurityModule(ABC):
    """Base class for all security testing modules"""
    
    def __init__(self):
        self.name = self.get_name()
        self.description = self.get_description()
        self.version = self.get_version()
        self.author = self.get_author()
        self.tags = self.get_tags()
    
    @abstractmethod
    def get_name(self) -> str:
        """Return the module name"""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Return the module description"""
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """Return the module version"""
        pass
    
    @abstractmethod
    def get_author(self) -> str:
        """Return the module author"""
        pass
    
    @abstractmethod
    def get_tags(self) -> List[str]:
        """Return tags for this module (e.g., ['prompt-injection', 'credentials'])"""
        pass
    
    @abstractmethod
    async def run(self, adapter) -> TestResult:
        """
        Execute the security test
        
        Args:
            adapter: McpClientAdapter instance for communicating with MCP server
            
        Returns:
            TestResult with findings and metadata
        """
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get module metadata"""
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'author': self.author,
            'tags': self.tags
        }
    
    def create_finding(self, 
                      finding_type: str,
                      severity: Severity,
                      resource: str,
                      description: str,
                      evidence: str,
                      **kwargs) -> Finding:
        """Helper method to create a finding"""
        return Finding(
            type=finding_type,
            severity=severity,
            resource=resource,
            description=description,
            evidence=evidence,
            **kwargs
        )
