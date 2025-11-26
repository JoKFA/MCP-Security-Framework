# MCP Security Framework (MCPSF) Documentation

**Version:** 0.4.0
**Status:** Production Ready
**Last Updated:** 2025-11-24

---

## 📚 Documentation Overview

This documentation covers the complete MCP Security Framework, from automatic sandboxing to vulnerability detection and reporting.

### Quick Links

| Document | Description | Audience |
|----------|-------------|----------|
| **[Architecture Overview](ARCHITECTURE.md)** | High-level system design and data flow | Everyone |
| **[Wrapper Guide](WRAPPER_GUIDE.md)** | AMSAW v2 automatic sandboxing system | Developers, DevOps |
| **[Detectors Guide](DETECTORS_GUIDE.md)** | Security vulnerability detection engine | Security Engineers |
| **[Reports Guide](REPORTS_GUIDE.md)** | Report formats and CI/CD integration | DevOps, Security Teams |
| **[API Reference](API_REFERENCE.md)** | CLI commands and Python API | Developers |
| **[Web View Guide](../WEB_VIEW_README.md)** | Flask web UI for running assessments and browsing reports | Web UI Users |

---

## 🚀 Quick Start

### Prerequisites

- **Python:** 3.11+ recommended (tested with 3.11/3.12)
- **Node.js:** 18+ for Node-based MCPs (npm available on PATH)
- **Docker:** 24+ with permission to run containers (required for sandboxing)
- **Package managers:** `uv` or `pip`, plus `npm`
- **Git + tar:** Needed for cloning/downloading targets
- **Recommended host:** 4+ vCPU, 8GB RAM, 5GB free disk per assessment
- **Network/proxy:** Allow Git/npm/tarball downloads; behind proxies set `HTTP(S)_PROXY` and `npm config set proxy`/`https-proxy`
- **Offline caching:** Pre-download npm tarballs and Python wheels if running in restricted networks

### Installation

```bash
# Clone repository
git clone https://github.com/yourorg/mcp-security-framework
cd mcp-security-framework

# Install dependencies
pip install -r requirements.txt  # or uv sync

# Verify installation
python mcpsf.py version
```

### Basic Usage

```bash
# Assess a local MCP server
python mcpsf.py assess targets/vulnerable/dv-mcp/challenges/easy/challenge1

# Assess an npm package
python mcpsf.py assess @modelcontextprotocol/server-time

# Assess a GitHub repository
python mcpsf.py assess https://github.com/modelcontextprotocol/servers/tree/main/src/time

# Run specific detectors
python mcpsf.py assess <source> --detectors MCP-2024-PI-001,MCP-2024-TP-001

# Generate reports to custom directory
python mcpsf.py assess <source> -o ./my-reports
```

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Input (Source)                         │
│  npm package | GitHub URL | Local Path | Remote URL             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 1: Discovery Engine (AST Analysis)                       │
│  ├─ Detects language (Python/Node.js)                           │
│  ├─ Finds entry points and transport type                       │
│  ├─ Extracts host/port configuration                            │
│  └─ Returns ServerConfig                                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 2: Container Provisioner                                 │
│  ├─ Provisions Docker container (mcp-runner-python/node)        │
│  ├─ Installs dependencies (uv/npm)                              │
│  ├─ Auto-detects CLI syntax                                     │
│  ├─ Starts MCP server                                           │
│  └─ Crash analysis loop (auto-fixes common errors)              │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 3: Universal Bridge (Transport Normalization)            │
│  ├─ stdio → HTTP (FastAPI bridge)                               │
│  ├─ SSE → HTTP (reverse proxy)                                  │
│  ├─ Smoke test (verify MCP responds)                            │
│  └─ Returns normalized HTTP URL                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 4: Security Assessment (14 Detectors)                    │
│  ├─ TestRunner orchestrates detector execution                  │
│  ├─ SafeAdapter enforces safety guardrails                      │
│  ├─ McpClientAdapter handles MCP protocol                       │
│  └─ Detectors analyze for vulnerabilities                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Phase 5: Report Generation                                     │
│  ├─ JSON (machine-readable)                                     │
│  ├─ SARIF (GitHub Security Tab)                                 │
│  ├─ CLI (human-readable terminal output)                        │
│  └─ Audit log (JSONL for analysis)                              │
└─────────────────────────────────────────────────────────────────┘
```

**Key Innovation:** Phases 1-3 (AMSAW v2) automatically sandbox ANY MCP server from ANY source with zero user configuration.

---

## 🎯 Key Features

### Automatic Sandboxing (AMSAW v2)

- **Zero-config:** Automatically detects and sandboxes MCP servers
- **Multi-source:** npm, GitHub, local directories, remote URLs
- **AST-based:** Deterministic detection (no guessing!)
- **Docker-isolated:** All assessments run in containers
- **Crash-resilient:** Auto-fixes common errors (ffmpeg, host binding, ports)
- **Fast:** <30s setup time (vs 2-3 minutes with old approach)

### Security Detection Engine

- **14 vulnerability detectors** covering OWASP Top 10 for MCP
- **95%+ accuracy** on known vulnerable MCPs
- **Profile-based:** Safe, Balanced, Aggressive modes
- **Rate-limited:** SafeAdapter prevents DoS during testing
- **Redaction:** Automatically redacts sensitive data

### Professional Reporting

- **JSON:** Machine-readable for CI/CD pipelines
- **SARIF:** GitHub Security Tab integration
- **CLI:** Human-readable terminal output
- **Audit logs:** JSONL format for post-analysis

---

## 📊 System Metrics

| Metric | Value |
|--------|-------|
| **Total Lines of Code** | ~4,500 |
| **Setup Time** | 10-20 seconds |
| **Assessment Time** | 30-90 seconds (avg) |
| **Success Rate** | 100% (on working Python MCPs) |
| **Detectors** | 14 |
| **Supported Languages** | Python, Node.js |
| **Supported Transports** | stdio, SSE |

---

## 🔒 Security Model

### Isolation Layers

1. **Docker Containers:** All MCP servers run in isolated containers
2. **Network Isolation:** Containers use bridge networking
3. **Rate Limiting:** SafeAdapter limits requests per second
4. **Scope Enforcement:** Policy engine restricts tool access
5. **Data Redaction:** Sensitive data automatically removed

### Threat Model

**What we protect against:**
- Malicious MCP servers attempting to escape sandbox
- Prompt injection attacks on MCP tools
- Credential exposure in responses
- Tool poisoning and shadowing
- Excessive permission abuse

**What we DON'T protect against:**
- Physical host compromise (requires Docker security)
- Zero-day Docker escapes (keep Docker updated)
- DoS attacks on host machine (use resource limits)

---

## ⚠️ Known Limitations

- **Success rate scope:** The 100% figure applies to the curated set of known-good Python MCPs; real-world targets with custom deps or unusual startup flows may require manual fixes.
- **Language/transport:** Only Python and Node.js MCPs are supported; transports limited to stdio and SSE.
- **Native/system deps:** Auto-fixes cover common cases (e.g., ffmpeg), but bespoke native libraries or GPU tooling may fail to build inside the sandbox without manual intervention.
- **Network constraints:** Fully offline/proxy-restricted environments need pre-fetched npm tarballs/Python wheels and Docker images; otherwise provisioning will fail.
- **Web UI exposure:** The Flask web view ships without auth; do not bind to non-localhost without putting it behind your own reverse proxy/auth.

---

## 📖 Detailed Guides

### For Security Engineers

1. Start with **[Architecture Overview](ARCHITECTURE.md)** to understand system design
2. Read **[Detectors Guide](DETECTORS_GUIDE.md)** to learn how detectors work
3. Review **[Reports Guide](REPORTS_GUIDE.md)** for interpreting results

### For Developers

1. Start with **[API Reference](API_REFERENCE.md)** for CLI/Python usage
2. Read **[Wrapper Guide](WRAPPER_GUIDE.md)** to understand sandboxing
3. See **[Architecture Overview](ARCHITECTURE.md)** for integration points

### For DevOps/CI Engineers

1. Start with **[Reports Guide](REPORTS_GUIDE.md)** for CI/CD integration
2. Read **[API Reference](API_REFERENCE.md)** for automation
3. Review **[Wrapper Guide](WRAPPER_GUIDE.md)** for Docker requirements

---

## 🧪 Testing

### Test Suites

```bash
# Unit tests (fast)
pytest tests/unit/

# Integration tests (medium)
pytest tests/integration/

# End-to-end tests (slow)
python tests/test_challenge1.py
python tests/test_challenge2.py
python tests/test_wikipedia_mcp.py
```

### Known Working MCPs

| MCP | Source | Transport | Status |
|-----|--------|-----------|--------|
| Challenge 1 (Prompt Injection) | Local | SSE | ✅ PASS |
| Challenge 2 (Tool Poisoning) | Local | SSE | ✅ PASS |
| Challenge 3 (Excessive Perms) | Local | SSE | ✅ PASS |
| Wikipedia MCP | npm | SSE | ✅ PASS |
| Markitdown MCP | npm | SSE | ✅ PASS |
| Excel MCP | npm | stdio | ✅ PASS |

---

## 🤝 Contributing

See **[CONTRIBUTING.md](../CONTRIBUTING.md)** for:
- Development setup and tooling
- Coding style and lint/test expectations
- How to run smoke/unit/integration suites
- Release/versioning checklist
- Code review guidelines

---

## 📝 Version History

### v0.4.0 (2025-11-24) - Current

- ✅ AMSAW v2 automatic sandboxing system
- ✅ AST-based discovery engine
- ✅ Universal bridge (stdio/SSE normalization)
- ✅ Proactive host binding detection
- ✅ Native module handling for Node.js
- ✅ Crash analysis loop with auto-fixes
- ✅ 100% success rate on working Python MCPs

### v0.3.0 (2025-11-20)

- Flask web UI for live monitoring
- Enhanced reporting (SARIF support)
- Detector improvements

### v0.2.0 (2025-10-15)

- Initial detection engine (14 detectors)
- SafeAdapter safety guardrails
- JSON/CLI reporting

### v0.1.0 (2025-09-01)

- Initial release
- Basic MCP client integration
- Manual target configuration

---

## 📧 Support

- **Issues:** https://github.com/yourorg/mcp-security-framework/issues
- **Discussions:** https://github.com/yourorg/mcp-security-framework/discussions
- **Documentation:** This directory!

---

## 📄 License

MIT License - See LICENSE file for details

---

**Built with ❤️ for the MCP security community**
