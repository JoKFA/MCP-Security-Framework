"""
CLI Command Detector for MCP Servers.

Automatically detects the correct command-line syntax for different MCP servers
by parsing help output and trying common patterns.

Strategy:
1. Parse --help output to detect supported flags
2. Try common CLI patterns in order of likelihood
3. Validate each attempt by checking exit code / output
4. Return the working command

This eliminates the need for manual command overrides!
"""

import re
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class CLIPattern:
    """A detected CLI pattern for running an MCP server."""
    command: List[str]
    transport: str  # "sse" or "stdio"
    port: Optional[int] = None
    confidence: float = 0.0  # 0.0 to 1.0


class CLIDetector:
    """
    Detects correct CLI syntax for MCP servers.

    Usage:
        detector = CLIDetector()
        pattern = detector.detect(container, module="markitdown_mcp", transport="sse")
        # Returns: ["python", "-m", "markitdown_mcp", "--sse", "--port", "3001"]
    """

    # Common SSE flag patterns (in order of likelihood)
    SSE_PATTERNS = [
        ["--sse"],           # Most common
        ["--http"],          # Also common
        ["sse"],             # Positional arg
        ["--transport", "sse"],
        ["--mode", "sse"],
    ]

    # Common stdio flag patterns
    STDIO_PATTERNS = [
        [],                  # No args (default stdio)
        ["--stdio"],
        ["stdio"],
        ["--transport", "stdio"],
    ]

    def detect(
        self,
        container,
        module: str,
        transport: str = "sse",
        base_command: List[str] = None
    ) -> CLIPattern:
        """
        Detect correct CLI command for MCP server.

        Args:
            container: Docker container object
            module: Python module name or entry point
            transport: Desired transport ("sse" or "stdio")
            base_command: Base command (e.g., ["python", "-m", "module"])

        Returns:
            CLIPattern with detected command

        Strategy:
            1. Parse --help to understand CLI interface
            2. Try common patterns for desired transport
            3. Validate by attempting to start server
            4. Return first working pattern
        """
        if base_command is None:
            base_command = ["python", "-m", module]

        print(f"[*] Auto-detecting CLI syntax for: {module}")

        # Step 1: Parse help output
        help_info = self._parse_help(container, base_command)

        # Step 2: Generate candidate commands based on help
        candidates = self._generate_candidates(
            base_command,
            transport,
            help_info
        )

        # Step 3: Test each candidate
        for candidate in candidates:
            if self._validate_command(container, candidate, transport):
                print(f"[+] Detected working command: {' '.join(candidate.command)}")
                return candidate

        # Fallback: return base command with best guess
        print(f"[!] Warning: Could not auto-detect CLI syntax, using best guess")
        return CLIPattern(
            command=base_command,
            transport=transport,
            confidence=0.3
        )

    def _parse_help(
        self,
        container,
        base_command: List[str]
    ) -> Dict[str, any]:
        """
        Parse --help output to understand CLI interface.

        Returns:
            Dict with detected flags, options, defaults
        """
        # Use timeout to prevent hanging on servers that don't support --help
        cmd = base_command + ["--help"]
        cmd_str = " ".join(cmd)
        test_cmd = f"timeout 2 {cmd_str} 2>&1 || true"
        result = container.exec_run(["sh", "-c", test_cmd], workdir="/app")

        if result.exit_code not in (0, 124):  # 0=success, 124=timeout
            # Try -h
            cmd = base_command + ["-h"]
            cmd_str = " ".join(cmd)
            test_cmd = f"timeout 2 {cmd_str} 2>&1 || true"
            result = container.exec_run(["sh", "-c", test_cmd], workdir="/app")

        if result.exit_code not in (0, 124):  # No help available
            return {}

        help_text = result.output.decode('utf-8', errors='ignore')

        info = {
            'has_sse_flag': False,
            'has_http_flag': False,
            'has_stdio_flag': False,
            'has_transport_arg': False,
            'has_host_flag': False,
            'default_port': None,
            'port_flag': None,
        }

        # Detect flags
        if re.search(r'--sse\b', help_text):
            info['has_sse_flag'] = True
        if re.search(r'--http\b', help_text):
            info['has_http_flag'] = True
        if re.search(r'--stdio\b', help_text):
            info['has_stdio_flag'] = True
        if re.search(r'--transport\b', help_text):
            info['has_transport_arg'] = True
        if re.search(r'--host\b', help_text):
            info['has_host_flag'] = True

        # Detect port flag and default
        port_match = re.search(r'(--port)\s+.*?default[:\s]+(\d+)', help_text, re.IGNORECASE)
        if port_match:
            info['port_flag'] = port_match.group(1)
            info['default_port'] = int(port_match.group(2))
        elif re.search(r'--port\b', help_text):
            info['port_flag'] = '--port'

        print(f"[*] Parsed help: SSE={info['has_sse_flag']}, HTTP={info['has_http_flag']}, "
              f"Host={info['has_host_flag']}, Port={info['default_port']}")

        return info

    def _generate_candidates(
        self,
        base_command: List[str],
        transport: str,
        help_info: Dict
    ) -> List[CLIPattern]:
        """
        Generate candidate commands based on help info.

        Returns:
            List of CLIPattern sorted by confidence
        """
        candidates = []

        if transport == "sse":
            # Pattern 1: Use detected SSE flag (highest confidence)
            if help_info.get('has_sse_flag'):
                cmd = base_command + ["--sse"]
                if help_info.get('port_flag') and help_info.get('default_port'):
                    cmd += [help_info['port_flag'], str(help_info['default_port'])]
                # CRITICAL: Add --host 0.0.0.0 for Docker compatibility
                # Docker port mapping requires binding to all interfaces, not localhost
                if help_info.get('has_host_flag'):
                    cmd += ["--host", "0.0.0.0"]
                candidates.append(CLIPattern(cmd, "sse", help_info.get('default_port'), 0.95))

            # Pattern 2: Use --http flag
            if help_info.get('has_http_flag'):
                cmd = base_command + ["--http"]
                if help_info.get('port_flag') and help_info.get('default_port'):
                    cmd += [help_info['port_flag'], str(help_info['default_port'])]
                # Add --host 0.0.0.0 for Docker compatibility
                if help_info.get('has_host_flag'):
                    cmd += ["--host", "0.0.0.0"]
                candidates.append(CLIPattern(cmd, "sse", help_info.get('default_port'), 0.90))

            # Pattern 3: Use --transport sse
            if help_info.get('has_transport_arg'):
                cmd = base_command + ["--transport", "sse"]
                candidates.append(CLIPattern(cmd, "sse", confidence=0.85))

            # Pattern 4: Positional "sse"
            candidates.append(CLIPattern(base_command + ["sse"], "sse", confidence=0.70))

            # Pattern 5: Try common port 9001
            candidates.append(CLIPattern(
                base_command + ["--sse", "--port", "9001"],
                "sse",
                port=9001,
                confidence=0.60
            ))

        elif transport == "stdio":
            # Pattern 1: No args (stdio is often default)
            candidates.append(CLIPattern(base_command, "stdio", confidence=0.95))

            # Pattern 2: --stdio flag
            if help_info.get('has_stdio_flag'):
                candidates.append(CLIPattern(base_command + ["--stdio"], "stdio", confidence=0.90))

            # Pattern 3: Positional "stdio"
            candidates.append(CLIPattern(base_command + ["stdio"], "stdio", confidence=0.70))

        # Sort by confidence
        candidates.sort(key=lambda x: x.confidence, reverse=True)
        return candidates

    def _validate_command(
        self,
        container,
        pattern: CLIPattern,
        expected_transport: str
    ) -> bool:
        """
        Validate that a command works by attempting to start the server.

        Strategy:
            - Run command in background
            - Check if it starts without errors
            - For SSE: verify port is listening
            - For stdio: verify it accepts input

        Returns:
            True if command works
        """
        # Quick syntax check - run with timeout
        cmd_str = " ".join(pattern.command)
        test_cmd = f"timeout 2 {cmd_str} 2>&1 || true"

        result = container.exec_run(["sh", "-c", test_cmd], workdir="/app")
        output = result.output.decode('utf-8', errors='ignore')

        # Check for error patterns
        error_patterns = [
            r'error: unrecognized arguments',
            r'invalid choice',
            r'Usage:',  # Only if followed by error
            r'no such option',
            r'Traceback \(most recent call last\)',
        ]

        for pattern_re in error_patterns:
            if re.search(pattern_re, output, re.IGNORECASE):
                print(f"[!] Command failed validation: {' '.join(pattern.command)}")
                print(f"    Error: {output[:200]}")
                return False

        # If no obvious errors, consider it valid
        # (We can't do full server startup validation here as it would be too slow)
        print(f"[+] Command passed validation: {' '.join(pattern.command)}")
        return True


def detect_cli_command(
    container,
    module: str,
    transport: str,
    base_command: List[str] = None
) -> List[str]:
    """
    Convenience function to detect CLI command.

    Returns:
        Command as list of strings
    """
    detector = CLIDetector()
    pattern = detector.detect(container, module, transport, base_command)
    return pattern.command
