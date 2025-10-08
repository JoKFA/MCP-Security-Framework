# Contributing to MCP Security Framework

This document provides guidelines for team members contributing to the MCP Security Framework project.

## Table of Contents
- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Module Development](#module-development)

---

## Project Overview

**MCP Security Framework** is a Metasploit-like tool for security testing Model Context Protocol (MCP) servers. The framework connects to MCP servers, executes security tests, captures all interactions, and generates reproducible proof-of-concept reports.

**Key Features:**
- Support for both stdio and SSE (Server-Sent Events) transports
- Automatic traffic capture in NDJSON format
- Modular test architecture
- Professional reporting with evidence
- Works with vulnerable and production MCP servers

**Current Status:** Phase 1 Complete (Connection Layer)

---

## Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────┐
│              Test Runner (Core)                 │
│  - Loads and executes test modules              │
│  - Orchestrates security tests                  │
│  - Manages sessions and timeouts                │
└─────────────────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
┌───────▼────────┐         ┌──────────▼─────────┐
│ stdio_adapter  │         │  http_sse_adapter  │
│ - Process comm │         │  - HTTP/SSE        │
│ - JSON-RPC     │         │  - Streaming       │
└────────────────┘         └────────────────────┘
        │                             │
        └──────────────┬──────────────┘
                       │
              ┌────────▼────────┐
              │  Capture Store  │
              │  - NDJSON logs  │
              │  - Evidence     │
              └─────────────────┘
```

### Core Components

**1. Adapters (`src/adapters/`)**
- `McpClientAdapter` - Primary adapter using official MCP SDK
  - Supports both stdio and SSE transports
  - Handles protocol handshake and session lifecycle
  - Captures all traffic automatically
- `HttpSseAdapter` - Legacy raw HTTP adapter for protocol testing

**2. Test Runner (`src/core/`)** [PLANNED - Phase 2]
- Module loading and execution
- Session management
- Result aggregation
- Error handling

**3. Test Modules (`src/modules/`)** [PLANNED - Phase 3]
- Individual security test implementations
- Vulnerability detection logic
- Evidence collection

**4. Capture System**
- NDJSON format for line-by-line event logging
- Timestamps and metadata for all events
- Forensic evidence for reporting

---

## Development Setup

### Prerequisites
- Python 3.10+
- Node.js/npm (for stdio MCP servers)
- Git

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd mcp-security-framework
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Set up test targets:
```bash
# Clone DV-MCP (Damn Vulnerable MCP)
cd targets/vulnerable
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server.git dv-mcp
cd dv-mcp
pip install -r requirements.txt
```

4. Verify setup:
```bash
# Run adapter integration tests
python tests/integration/test_adapter_connection.py
```

---

## Project Structure

```
mcp-security-framework/
├── src/                    # Source code
│   ├── adapters/          # Protocol adapters
│   ├── core/              # Test runner (future)
│   └── modules/           # Test modules (future)
│
├── examples/              # Usage examples and manual exploits
│   ├── manual_exploit_challenge1_prompt_injection.py
│   ├── test_dv_mcp_challenge1.py
│   ├── test_dv_mcp_challenge2.py
│   └── test_official_time_server.py
│
├── tests/                 # Framework tests
│   ├── unit/             # Unit tests
│   └── integration/      # Integration tests
│       └── test_adapter_connection.py
│
├── targets/              # Test targets (local only, not in git)
│   ├── vulnerable/       # Vulnerable servers (DV-MCP)
│   ├── official/         # Official MCP servers
│   └── custom/           # Custom test servers
│
├── captures/             # Generated evidence (not in git)
├── reports/              # Generated reports (not in git)
│
├── README.md             # User-facing documentation
├── CONTRIBUTING.md       # This file
├── LICENSE              # MIT License
├── requirements.txt     # Python dependencies
└── pyproject.toml       # Package metadata
```

### What Gets Committed to Git

✅ **Include:**
- Source code (`src/`, `examples/`, `tests/`)
- Documentation (`README.md`, `CONTRIBUTING.md`)
- Configuration (`requirements.txt`, `pyproject.toml`, `LICENSE`)
- Directory markers (`.gitkeep` files)

❌ **Exclude (via .gitignore):**
- Generated captures (`captures/*.ndjson`)
- Generated reports (`reports/*.json`)
- Test targets (`targets/`)
- Python cache (`__pycache__/`, `*.pyc`)
- Virtual environments (`venv/`, `.venv/`)

---

## Development Workflow

### Branch Strategy

- `main` - Stable, production-ready code
- `develop` - Integration branch for features
- `feature/*` - Individual feature branches
- `fix/*` - Bug fix branches

### Making Changes

1. **Create a feature branch:**
```bash
git checkout -b feature/your-feature-name
```

2. **Make your changes and test:**
```bash
# Run integration tests
python tests/integration/test_adapter_connection.py

# Test against DV-MCP
python examples/test_dv_mcp_challenge1.py
```

3. **Commit your changes:**
```bash
git add .
git commit -m "Add: your feature description"
```

4. **Push and create PR:**
```bash
git push origin feature/your-feature-name
# Create pull request on GitHub
```

### Commit Message Guidelines

Use conventional commits format:
- `Add: new feature or file`
- `Update: modify existing functionality`
- `Fix: bug fixes`
- `Docs: documentation changes`
- `Test: test additions or modifications`
- `Refactor: code restructuring`

---

## Coding Standards

### Python Style
- Follow PEP 8 style guide
- Use type hints for function signatures
- Maximum line length: 100 characters
- Use descriptive variable names

### Documentation
- Docstrings for all public classes and methods
- Inline comments for complex logic
- Update relevant docs when adding features

### Example Code Style

```python
async def test_vulnerability(adapter: McpClientAdapter) -> TestResult:
    """
    Test for specific vulnerability pattern.

    Args:
        adapter: Connected MCP client adapter

    Returns:
        TestResult object with findings
    """
    findings = []

    # Enumerate resources
    resources = await adapter.list_resources()

    # Check for vulnerable patterns
    for resource in resources:
        if is_vulnerable(resource):
            findings.append(create_finding(resource))

    return TestResult(findings=findings)
```

---

## Testing Guidelines

### Running Tests

**Integration Tests:**
```bash
# Test adapter connections (requires DV-MCP running)
python tests/integration/test_adapter_connection.py
```

**Manual Exploitation Examples:**
```bash
# Start DV-MCP Challenge 1
cd targets/vulnerable/dv-mcp
python challenges/easy/challenge1/server_sse.py

# In another terminal, run exploit
python examples/manual_exploit_challenge1_prompt_injection.py
```

### Writing Tests

**Unit Tests (Future):**
- Test individual functions and classes
- Mock external dependencies
- Fast execution (<1 second each)

**Integration Tests:**
- Test adapter connectivity
- Verify protocol compliance
- Test against real MCP servers

**Example Integration Test:**
```python
async def test_adapter_connection():
    """Test that adapter can connect to MCP server"""
    adapter = McpClientAdapter(transport="sse", url="http://localhost:9001/sse")

    # Test connection
    connection_info = await adapter.connect()
    assert 'server_info' in connection_info

    # Test basic operations
    resources = await adapter.list_resources()
    assert isinstance(resources, list)

    await adapter.disconnect()
```

---

## Module Development

### Creating a New Test Module (Phase 2+)

When Phase 2 is implemented, test modules will follow this structure:

**1. Module Template:**
```python
from src.core.base_module import TestModule, TestResult

class MyVulnerabilityDetector(TestModule):
    """Detects [specific vulnerability] in MCP servers"""

    def get_metadata(self):
        return {
            'name': 'My Vulnerability Detector',
            'severity': 'HIGH',
            'description': 'Detects...',
            'references': ['CVE-XXXX', 'https://...']
        }

    async def run(self, adapter: McpClientAdapter) -> TestResult:
        """Execute the test"""
        findings = []

        # Your detection logic here
        resources = await adapter.list_resources()
        for resource in resources:
            if self._is_vulnerable(resource):
                findings.append(self._create_finding(resource))

        return TestResult(findings=findings)

    def _is_vulnerable(self, resource):
        """Check if resource is vulnerable"""
        # Pattern matching logic
        pass

    def _create_finding(self, resource):
        """Create structured finding"""
        return {
            'type': 'Vulnerability Type',
            'severity': 'HIGH',
            'resource': str(resource['uri']),
            'description': '...',
            'evidence': '...',
            'remediation': '...'
        }
```

**2. Testing Your Module:**
- Test against DV-MCP challenges
- Verify true positive detection
- Check for false positives
- Capture evidence properly

---

## Development Phases

### ✅ Phase 1: Connection Layer (COMPLETE)
- McpClientAdapter implementation
- SSE and stdio transport support
- NDJSON capture system
- Tested with 3 different MCP servers

### 🔄 Phase 2: Test Runner (NEXT)
- Core test runner implementation
- Module loading system
- First automated test module
- Basic reporting

### 📋 Phase 3: Test Modules (PLANNED)
- 10 vulnerability detection modules
- Coverage for all DV-MCP challenges
- Pattern libraries for common vulnerabilities

### 📋 Phase 4: Advanced Features (FUTURE)
- Replay engine
- Professional reporting (HTML/PDF)
- Web dashboard
- CI/CD integration

---

## Getting Help

- **Issues:** Open an issue on GitHub for bugs or feature requests
- **Discussions:** Use GitHub Discussions for questions and ideas
- **Pull Requests:** Submit PRs for code contributions

---

## Resources

- [MCP Documentation](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [DV-MCP Challenges](https://github.com/harishsg993010/damn-vulnerable-MCP-server)

---

*Last updated: 2025-10-08*
