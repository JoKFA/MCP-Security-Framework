# MCP Security Framework

A Metasploit-like security testing framework for Model Context Protocol (MCP) servers.

## Features

- 🔌 **Multi-Transport Support** - Connect to MCP servers via SSE (HTTP) or stdio
- 🎯 **Automated Testing** - Run security tests and vulnerability scans
- 📝 **Evidence Capture** - Automatic NDJSON logging of all traffic
- 📊 **Professional Reporting** - Detailed findings with attack chains and remediation
- 🧪 **Manual Exploitation** - Craft custom attacks with full control
- ✅ **Production Ready** - Tested against vulnerable and official MCP servers

## Project Structure

```
mcp-security-framework/
├── LICENSE                # MIT License
├── README.md              # This file
├── CONTRIBUTING.md        # Team contribution guidelines
├── pyproject.toml         # Package metadata
├── requirements.txt       # Python dependencies
│
├── src/
│   ├── adapters/          # Protocol adapters (stdio, SSE)
│   │   ├── mcp_client_adapter.py    # Main adapter (MCP SDK)
│   │   └── http_sse_adapter.py      # Raw protocol adapter
│   ├── core/              # Test runner (Phase 2)
│   └── modules/           # Test modules (Phase 3)
│
├── examples/              # Manual exploitation examples
│   ├── manual_exploit_challenge1_prompt_injection.py
│   ├── test_dv_mcp_challenge1.py
│   ├── test_dv_mcp_challenge2.py
│   └── test_official_time_server.py
│
├── tests/                 # Framework tests
│   ├── unit/              # Unit tests (future)
│   └── integration/       # Integration tests
│       └── test_adapter_connection.py
│
├── targets/               # Test targets (local only, not in git)
│   ├── vulnerable/        # Vulnerable servers (DV-MCP)
│   ├── official/          # Official MCP servers
│   └── custom/            # Custom test servers
│
├── captures/              # Evidence logs (generated, not in git)
└── reports/               # Test reports (generated, not in git)
```

## Quick Start

### 1. Clone and Install

```bash
# Clone the repository
git clone https://github.com/JoKFA/MCP-Security-Framework.git
cd MCP-Security-Framework

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Set Up Test Targets

```bash
# Clone DV-MCP (Damn Vulnerable MCP)
cd targets/vulnerable
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server.git dv-mcp
cd dv-mcp
pip install -r requirements.txt
cd ../../..
```

### 3. Run Adapter Integration Tests

**Verify that the framework adapters are working correctly:**

```bash
# Start DV-MCP Challenge 1 server in one terminal
cd targets/vulnerable/dv-mcp
python challenges/easy/challenge1/server_sse.py

# In another terminal, run the adapter tests
python tests/integration/test_adapter_connection.py
```

**Expected output:**
```
======================================================================
  MCP Client Adapter - Integration Tests
======================================================================

[TEST] SSE Transport Connection Test
──────────────────────────────────────────────────────────────────────
  -> Target: http://localhost:9001/sse
  [PASS] Adapter instance created
  [PASS] Connection established
  [PASS] Server initialization successful
  [PASS] Resources listed: 1 resources found
  [PASS] Tools listed: 1 tools found
  [PASS] Resource read successful

[TEST] SSE Test Summary
──────────────────────────────────────────────────────────────────────
  Evidence: Test Results
  ┌──────────────────────────────────────────────────────────────────
  │ Total Tests: 6
  │ Passed: 6
  │ Failed: 0
  │ Success Rate: 100.0%
  └──────────────────────────────────────────────────────────────────
  [PASS] SSE Transport: ALL TESTS PASSED (6/6)

[TEST] STDIO Transport Connection Test
──────────────────────────────────────────────────────────────────────
  [PASS] STDIO Transport: ALL TESTS PASSED (5/5)

======================================================================
  ALL ADAPTER TESTS PASSED
  The MCP Client Adapter is working correctly!
======================================================================
```

### 4. Run Manual Exploitation Example

**Demonstrate a prompt injection attack against DV-MCP Challenge 1:**

```bash
# Make sure DV-MCP Challenge 1 server is running
cd targets/vulnerable/dv-mcp
python challenges/easy/challenge1/server_sse.py

# In another terminal, run the manual exploit
python examples/manual_exploit_challenge1_prompt_injection.py
```

**Expected output:**
```
======================================================================
  MCP Security Framework - Manual Exploitation Test
  Target: DV-MCP Challenge 1 (Prompt Injection)
======================================================================

[*] Phase 1: Reconnaissance
──────────────────────────────────────────────────────────────────────
  [+] Connected to: Challenge 1 - Basic Prompt Injection
  [+] Server capabilities: resources, tools, prompts

[*] Phase 2: Resource Enumeration
──────────────────────────────────────────────────────────────────────
  [+] Found 1 resources
  [!] Suspicious resource: internal://credentials

[*] Phase 4: Prompt Injection Exploitation
──────────────────────────────────────────────────────────────────────
  [!] Crafting prompt injection payload...
  [-] CRITICAL: Sensitive data accessible!

┌─ EVIDENCE: Exposed Credentials ─ [HIGH]
│
│  Admin Username: admin_user
│  Admin Password: super_secret_password123
│  API Key: sk-a1b2c3d4e5f6g7h8i9j0
│  Database Connection String: postgresql://dbuser:dbpass@localhost/production
└────────────────────────────────────────────────────────────────────

[*] Phase 5: Test Summary
──────────────────────────────────────────────────────────────────────
  [-] VULNERABLE: 1 security issue(s) found

Finding #1: Credential Exposure via Prompt Injection [CRITICAL]
  Attack Chain:
    1. Attacker crafts malicious user_id parameter with embedded LLM instructions
    2. Server reflects unsanitized input in response
    3. LLM processes the injected instructions
    4. LLM reads and returns sensitive credential resource
    5. Attacker exfiltrates admin credentials, API keys, and database passwords

  [+] Report saved to: reports/manual_exploit_challenge1_TIMESTAMP.json
  [+] Evidence saved to: captures/manual_exploit_challenge1_TIMESTAMP.ndjson

======================================================================
  TEST RESULT: VULNERABLE - Remediation Required
======================================================================
```

**Generated files:**
- `reports/manual_exploit_challenge1_TIMESTAMP.json` - Structured finding report
- `captures/manual_exploit_challenge1_TIMESTAMP.ndjson` - Complete traffic capture

---

## Programmatic Usage

```python
from src.adapters import McpClientAdapter

# Connect via SSE
adapter = McpClientAdapter(transport="sse", url="http://localhost:9001/sse")
await adapter.connect()

# List tools
tools = await adapter.list_tools()

# Call a tool
result = await adapter.call_tool("get_user_info", {"username": "admin"})

# Read a resource (this exposes credentials in DV-MCP Challenge 1)
resource = await adapter.read_resource("internal://credentials")

# Save evidence
adapter.save_capture("captures/evidence.ndjson")
```

---

## Additional Examples

**Basic adapter usage:**
```bash
python examples/test_dv_mcp_challenge1.py      # Simple SSE connection test
python examples/test_dv_mcp_challenge2.py      # Tool poisoning test
python examples/test_official_time_server.py   # stdio transport test
```

---

## Development Status

### ✅ Phase 1: Connection Layer (COMPLETE)

- ✅ McpClientAdapter implementation using official MCP SDK
- ✅ SSE and stdio transport support
- ✅ NDJSON capture system
- ✅ Integration tests
- ✅ Manual exploitation framework
- ✅ Professional reporting

**Tested against:**
- DV-MCP Challenge 1 (Prompt Injection)
- DV-MCP Challenge 2 (Tool Poisoning)
- Official MCP reference servers (@modelcontextprotocol/server-everything)

### 📋 Phase 2: Test Runner (Next)

- Automated test module loading
- Vulnerability scanner orchestration
- Batch testing capabilities

### 📋 Phase 3: Test Modules (Planned)

10 security test modules covering:
- Credential exposure
- Prompt injection
- Tool poisoning
- Excessive permissions
- Code execution
- And more...

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Coding standards
- Testing guidelines
- Module development guide
- Branch strategy

---

## Resources

- **MCP Documentation:** https://modelcontextprotocol.io/
- **MCP Python SDK:** https://github.com/modelcontextprotocol/python-sdk
- **DV-MCP (Test Targets):** https://github.com/harishsg993010/damn-vulnerable-MCP-server

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Project Status

**Current Version:** v0.1.0 (Phase 1 Complete)

**Repository:** https://github.com/JoKFA/MCP-Security-Framework
