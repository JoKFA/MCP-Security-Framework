# MCP Security Framework (mcpsf)

**A professional security testing framework for Model Context Protocol (MCP) servers**

Automated vulnerability detection, penetration testing, and compliance validation for MCP implementations.

---

## Overview

The MCP Security Framework is a Metasploit-like tool designed to identify security vulnerabilities in MCP servers through automated testing and exploitation. Built with a signal-based detection architecture, the framework provides comprehensive security assessments with professional reporting.

**Current Version:** v0.3.0 (Production Release)

---

## Key Features

- **14 Security Detectors** - Comprehensive vulnerability coverage (Injection, Privilege, Configuration, Behavioral)
- **Multi-Transport Support** - Connect via SSE (HTTP) or stdio transports
- **Production CLI** - Simple `mcpsf assess` command for full security assessments
- **Multi-Format Reports** - JSON, SARIF 2.1.0, and human-readable CLI reports
- **Standards Compliance** - Mapped to CWE, OWASP LLM/API Top 10, CVSS v3.1
- **Real-World Validated** - Tested against 10+ open-source MCP servers and DV-MCP challenges
- **Evidence Capture** - Complete NDJSON audit logs with integrity verification
- **Safety Guardrails** - Scope enforcement, rate limiting, credential redaction

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/JoKFA/MCP-Security-Framework.git
cd MCP-Security-Framework

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

**Assess an MCP server:**

```bash
# SSE transport (HTTP-based servers)
python mcpsf.py assess --transport sse --url http://localhost:9001/sse

# stdio transport (local process)
python mcpsf.py assess --transport stdio --command "npx" --args "@modelcontextprotocol/server-time"
```

**List available detectors:**

```bash
python mcpsf.py list-detectors
```

**Example output:**
```
ID                        Name                                          Severity
-------------------------------------------------------------------------------------
MCP-2024-CEX-001          Code Execution Detector                       CRITICAL
MCP-2024-CI-001           Command Injection Detector                    CRITICAL
MCP-2024-UA-001           Unauthenticated Access Detector               CRITICAL
MCP-2024-CE-001           Credential Exposure Detector                  HIGH
MCP-2024-PI-001           Prompt Injection via Resource Parameters      HIGH
MCP-2024-TP-001           Tool Poisoning Detector                       HIGH
... (14 total detectors)
```

---

## Complete Assessment Example

### Step 1: Run Assessment

```bash
# Assess DV-MCP Challenge 1 (vulnerable test server)
python mcpsf.py assess --transport sse --url http://localhost:9001/sse
```

### Step 2: Review Output

**Terminal output shows real-time progress:**

```
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║           MCP Security Framework (mcpsf) v0.3.0                    ║
║           Professional Security Testing for MCP Servers            ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

[*] Starting Assessment
────────────────────────────────────────────────────────────────────
  Target: http://localhost:9001/sse
  Transport: sse
  Detectors: 14 loaded

[+] Connected to: Challenge 1 - Basic Prompt Injection

[*] Running Detectors...
  [PASS] MCP-2024-CEX-001 - Code Execution Detector
  [PASS] MCP-2024-CI-001 - Command Injection Detector
  [FAIL] MCP-2024-CE-001 - Credential Exposure Detector (2 findings)
  [FAIL] MCP-2024-PI-001 - Prompt Injection via Resource Parameters (1 finding)
  ...

[!] Assessment Complete
  Total Findings: 3 vulnerabilities
  Severity: 2 HIGH, 1 MEDIUM

[+] Reports Generated:
  📄 reports/Challenge_1_-_Basic_Prompt_Injection/report.json
  📄 reports/Challenge_1_-_Basic_Prompt_Injection/report.txt
  📄 reports/Challenge_1_-_Basic_Prompt_Injection/report.sarif
  📝 reports/Challenge_1_-_Basic_Prompt_Injection/audit.jsonl
```

### Step 3: Review Reports

**Generated files in `reports/<ServerName>/` folder:**

| File | Purpose | Audience |
|------|---------|----------|
| `report.json` | Machine-readable findings | Automation, CI/CD |
| `report.sarif` | SARIF 2.1.0 format | GitHub Security, IDE integration |
| `report.txt` | Human-readable summary | Security analysts |
| `audit.jsonl` | Complete traffic capture | Forensics, replay |
| `metadata.json` | Assessment metadata | Archive, tracking |

**Example finding from `report.txt`:**

```
════════════════════════════════════════════════════════════════════
  Finding #1: Credential Exposure via Accessible Resource [HIGH]
════════════════════════════════════════════════════════════════════

Detector: MCP-2024-CE-001 (Credential Exposure Detector)
Confidence: 95%

Description:
  Sensitive credentials (passwords, API keys, database connection strings)
  are exposed through publicly accessible MCP resources without authentication.

Standards:
  • CWE-522: Insufficiently Protected Credentials
  • OWASP LLM01: Prompt Injection
  • CVSS: 8.2 (HIGH)

Proof of Concept:
  1. Connect to MCP server
  2. List available resources
  3. Read resource: internal://credentials
  4. Credentials leaked in response:
     - Admin Password: super_secret_******* (REDACTED)
     - API Key: sk-a1b2c3d4******** (REDACTED)

Remediation:
  - Implement authentication for sensitive resources
  - Use environment variables instead of hardcoded credentials
  - Apply principle of least privilege
```

---

## Security Detectors

### Detector Categories

**Injection Attacks (4 detectors):**
- `MCP-2024-PI-001` - Prompt Injection via Resource Parameters
- `MCP-2024-II-001` - Indirect Prompt Injection
- `MCP-2024-CI-001` - Command Injection
- `MCP-2024-CEX-001` - Code Execution

**Privilege & Access Control (3 detectors):**
- `MCP-2024-UA-001` - Unauthenticated Access
- `MCP-2024-PA-001` - Privilege Abuse
- `MCP-2024-EP-001` - Excessive Permissions

**Configuration & Exposure (4 detectors):**
- `MCP-2024-CE-001` - Credential Exposure
- `MCP-2024-IS-001` - Insecure Token Storage
- `MCP-2024-TP-001` - Tool Poisoning
- `MCP-2024-TS-001` - Tool Shadowing

**Behavioral Analysis (3 detectors):**
- `MCP-2024-RUG-001` - Rug Pull Detection (Tool Behavior Monitor)
- `MCP-2024-TE-001` - Tool Enumeration Analyzer
- `MCP-2024-DUMMY-001` - Test Detector (framework validation)

### Standards Mapping

All detectors map to industry standards:
- **CWE** (Common Weakness Enumeration)
- **OWASP LLM Top 10** (2023)
- **OWASP API Security Top 10**
- **CVSS v3.1** (severity scoring)

---

## Project Structure

```
mcp-security-framework/
├── mcpsf.py                    # Production CLI entry point
├── pyproject.toml              # Package metadata
├── LICENSE                     # MIT License
│
├── src/
│   ├── adapters/
│   │   ├── mcp_client_adapter.py    # Primary adapter (MCP SDK)
│   │   └── http_sse_adapter.py      # Legacy raw HTTP adapter
│   │
│   ├── core/
│   │   ├── models.py           # Pydantic data models
│   │   ├── runner.py           # Test orchestration engine
│   │   ├── safe_adapter.py     # Safety wrapper (scope/rate/redaction)
│   │   ├── policy.py           # Policy enforcement
│   │   └── reporters/          # Report generators
│   │       ├── json_reporter.py
│   │       ├── sarif_reporter.py
│   │       ├── cli_reporter.py
│   │       └── manager.py
│   │
│   └── modules/
│       ├── base.py             # Detector base class
│       ├── registry.py         # Auto-discovery system
│       └── detectors/          # 14 security detectors
│
├── tests/
│   ├── unit/                   # Unit tests (100+ tests)
│   └── integration/            # Integration tests
│
├── targets/                    # Test MCP servers (git-ignored)
├── reports/                    # Generated reports (git-ignored)
├── captures/                   # Audit logs (git-ignored)
└── docs/                       # Documentation
```

---

## Advanced Usage

### Custom Detector Selection

```bash
# Run only specific detectors
python mcpsf.py assess \
  --transport sse \
  --url http://localhost:9001/sse \
  --detectors MCP-2024-PI-001,MCP-2024-CE-001
```

### Custom Output Directory

```bash
# Save reports to custom location
python mcpsf.py assess \
  --transport sse \
  --url http://localhost:9001/sse \
  --output ./my-assessments/
```

### Scope Configuration

Create a `scope.yaml` file to limit testing:

```yaml
# Example scope.yaml
resources:
  allowed_uris:
    - "file://docs/*"
    - "internal://public-*"
  blocked_uris:
    - "internal://credentials"
    - "file:///etc/*"

tools:
  allowed_tools:
    - "get_weather"
    - "search_docs"
  blocked_tools:
    - "execute_command"
    - "delete_file"
```

Apply scope:

```bash
python mcpsf.py assess \
  --transport sse \
  --url http://localhost:9001/sse \
  --scope scope.yaml
```

---

## Programmatic Usage

```python
import asyncio
from src.core.runner import TestRunner

async def run_assessment():
    # Configure target
    config = {
        "transport": "sse",
        "url": "http://localhost:9001/sse"
    }

    # Run assessment
    runner = TestRunner(config)
    result = await runner.run_all_detectors()

    # Access findings
    for finding in result.findings:
        print(f"[{finding.severity}] {finding.title}")
        print(f"Confidence: {finding.confidence}%")
        print(f"CWE: {finding.cwe_id}")

    return result

# Run
asyncio.run(run_assessment())
```

---

## Development Status

### ✅ Phase 1: Connection Layer (COMPLETE)
- McpClientAdapter with official MCP SDK
- SSE and stdio transport support
- NDJSON evidence capture
- Integration tests

### ✅ Phase 2: Security Assessment Framework (COMPLETE)
- Signal-based detection architecture
- Detector base class and auto-discovery
- TestRunner orchestration
- Policy engine (scope, rate limiting, redaction)
- SafeAdapter safety wrapper

### ✅ Phase 3: Detector Suite (COMPLETE)
- 14 production-ready detectors
- Coverage: Injection, Privilege, Configuration, Behavioral
- Standards mapping (CWE, OWASP, CVSS)
- General-purpose design (works on ANY MCP server)

### ✅ Phase 4: Production CLI & Reporting (COMPLETE)
- `mcpsf assess` command
- Multi-format reports (JSON, SARIF, CLI)
- Report bundles with metadata
- Exit codes for CI/CD integration

### ✅ Phase 5: Real-World Validation (COMPLETE)
- **10 DV-MCP challenges tested** (100% detection rate)
- **10+ open-source MCP servers assessed**
- Validated against: fetch, excel, wikipedia, todo-list, time servers

### 📋 Phase 6: Advanced Features (FUTURE)
- NDJSON replay engine
- PoC bundle generation (Python scripts + evidence)
- Interactive CLI mode (like msfconsole)
- Web dashboard
- Plugin system for custom detectors

---

## Real-World Validation

The framework has been validated against:

**DV-MCP (Damn Vulnerable MCP) Challenges:**
- ✅ Challenge 1 - Basic Prompt Injection
- ✅ Challenge 2 - Tool Poisoning
- ✅ Challenge 3 - Excessive Permission Scope
- ✅ Challenge 4 - Rug Pull Attack
- ✅ Challenge 5 - Tool Shadowing
- ✅ Challenge 6 - Indirect Prompt Injection
- ✅ Challenge 7 - Token Theft
- ✅ Challenge 8 - Malicious Code Execution
- ✅ Challenge 9 - Remote Access Control
- ✅ Challenge 10+ - Additional challenges

**Open-Source MCP Servers:**
- fetch-mcp (web scraping)
- excel-mcp (spreadsheet operations)
- wikipedia-mcp (knowledge retrieval)
- todo-list-mcp (task management)
- time-server (official reference)
- command-executor (system operations)
- hubble (data processing)
- starwind-ui (UI generation)

**Detection Rate:** 95%+ confidence on known vulnerabilities

---

## Testing

### Run Unit Tests

```bash
# All unit tests (100+ tests)
pytest tests/unit -v

# Specific test module
pytest tests/unit/test_detectors.py -v
```

### Run Integration Tests

```bash
# Integration tests (requires running MCP server)
pytest tests/integration -v -s
```

### Test Against DV-MCP

```bash
# Start DV-MCP Challenge 1 server
cd targets/vulnerable/dv-mcp
python challenges/easy/challenge1/server_sse.py

# In another terminal, run assessment
python mcpsf.py assess --transport sse --url http://localhost:9001/sse
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Run MCP Security Assessment
        run: |
          python mcpsf.py assess \
            --transport stdio \
            --command "npx" \
            --args "@modelcontextprotocol/server-time" \
            --output ./scan-results

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: scan-results/*/report.sarif
```

---

## Contributing

We welcome contributions! To contribute:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/new-detector`)
3. **Write tests** for new functionality
4. **Ensure all tests pass** (`pytest tests/`)
5. **Submit a pull request**

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## Resources

- **MCP Documentation:** https://modelcontextprotocol.io/
- **MCP Python SDK:** https://github.com/modelcontextprotocol/python-sdk
- **DV-MCP (Test Targets):** https://github.com/harishsg993010/damn-vulnerable-MCP-server
- **OWASP LLM Top 10:** https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **SARIF Specification:** https://sarifweb.azurewebsites.net/

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Project Information

**Repository:** https://github.com/JoKFA/MCP-Security-Framework

**Version:** v0.3.0 (Production Release)

**Branch:** `v0.3/Modules_Runer_Ready`

**Status:** Production-ready, validated against 20+ MCP servers

**Detectors:** 14 (Injection, Privilege, Configuration, Behavioral)

**Report Formats:** JSON, SARIF 2.1.0, CLI/TXT

---

## Acknowledgments

- Model Context Protocol team for the excellent Python SDK
- DV-MCP project for comprehensive test targets
- Security community for vulnerability research and standards
