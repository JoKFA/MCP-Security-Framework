"""MCP Security Testing Framework

A security testing framework for Model Context Protocol (MCP) servers.
"""

__version__ = "0.1.0"
__author__ = "MCP Security Team"

from .adapters import McpClientAdapter, HttpSseAdapter

__all__ = ['McpClientAdapter', 'HttpSseAdapter']
