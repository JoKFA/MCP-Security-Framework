# Weekly Project Update

**Project Title:** MCP Security Framework - Automated Vulnerability Assessment Tool for Model Context Protocol Servers
**Week #:** 4
**Date:** October 22, 2025
**Student:** Yaoting, Joshua, Tanish
**Instructor:** Mohammand

---

## 1. Summary

This week our team completed Phase 2 of the MCP Security Framework by implementing two additional security detectors and building a comprehensive multi-format reporting system. The framework can now automatically detect credential exposure and prompt injection vulnerabilities, generate proof-of-concept exploits, and produce professional assessment reports in three different formats (JSON, SARIF 2.1.0, and plain text). I successfully tested the complete system against DV-MCP Challenge 1 and detected both vulnerabilities with high confidence.

---

## 2. Progress

This week the focus was on expanding detector capabilities and building the reporting infrastructure planned in last week's roadmap. Three major components were completed: two new security detectors, a universal proof-of-concept generation system, and a multi-format reporting engine.

### Detector Implementation

**Credential Exposure Detector (MCP-2024-CE-001)**

The credential exposure detector scans MCP server resources for exposed secrets using regex pattern matching. It identifies six types of sensitive data (passwords, API keys, tokens, connection strings, private keys, database URLs) and classifies findings by severity. The detector automatically redacts secrets for safe display, showing only the first 6 and last 4 characters (e.g., "sk-a1b2...i9j0").

| Capability | Implementation |
|------------|----------------|
| Secret Types | 6 categories with dedicated regex patterns |
| Severity Classification | CRITICAL (keys/connections) → HIGH (passwords/API keys) → MEDIUM (tokens) |
| Redaction Strategy | First 6 + last 4 characters visible |
| Standards Mapping | CWE-522, OWASP LLM01, OWASP API2, CVSS 8.2 HIGH |

**Tool Enumeration Analyzer (MCP-2024-TE-001)**

This detector assesses the risk profile of MCP server tools by examining their schemas for dangerous operations (file system access, command execution, network operations). It validates whether tools have proper input constraints and flags overly permissive schemas. A risk scoring system categorizes tools as HIGH, MEDIUM, or LOW risk.

**Universal Proof-of-Concept Generation**

The most significant enhancement was extending PoC generation across all detectors. Previously only one detector generated exploits. The prompt injection detector was refactored to include two PoC methods:
- `_generate_injection_pocs()` - Tests parameterized resource manipulation
- `_generate_access_pocs()` - Demonstrates unauthorized sensitive resource access

All PoCs now include the complete attack payload, server response, and impact demonstration with actual evidence (safely redacted).

### Reporting System Architecture

A complete reporting layer was built with three specialized reporters implementing a common base interface:

**Reporter Components:**

```
src/core/reporters/
├── base.py              - Abstract Reporter interface
├── json_reporter.py     - Machine-readable output
├── sarif_reporter.py    - SARIF 2.1.0 for CI/CD integration
├── cli_reporter.py      - Human-readable structured text
└── manager.py           - Report orchestration and bundling
```

**Key Features:**

| Reporter | Format | Purpose | Size |
|----------|--------|---------|------|
| JSON | `.json` | Machine-readable, full evidence | 9.5KB |
| SARIF | `.sarif` | CI/CD integration, industry standard | 14KB |
| CLI | `.txt` | Human-readable with PoC details | 5.3KB |

The Report Manager produces complete assessment bundles - single directories containing all three report formats plus audit log copy and metadata. This bundle architecture replaced the previous scattered file approach, making assessment results easier to share and archive.

**Technical Challenges Solved:**

1. **ANSI Color Code Handling** - CLI reporter needed dual mode: colored terminal output vs plain text files. Fixed by conditionally instantiating reporter with `use_colors=False` when saving.

2. **Pydantic Enum Serialization** - Signal types serialize as strings in JSON but remain enums in Python. Added type checking: `signal.type if isinstance(signal.type, str) else signal.type.value`

3. **Folder Organization** - Established clear separation: `reports/` for final bundles only, `captures/` for raw audit logs with integrity hashes.

### Testing and Validation

Complete system validated against DV-MCP Challenge 1:

| Metric | Result |
|--------|--------|
| Vulnerabilities Detected | 2/2 (Credential Exposure, Prompt Injection) |
| Detection Confidence | 95% (both detectors) |
| PoCs Generated | 2 successful exploits with actual evidence |
| Assessment Duration | 1.57 seconds |
| Requests Made | 6 (rate limited to 2 QPS) |
| False Positives | 0 |

The framework successfully identified exposed credentials, demonstrated unauthorized access, and produced professional reports in all three formats.

---

## 3. Key Learnings / Issues

### Technical Challenges

**PoC Evidence Quality**

The initial proof-of-concept implementation only showed summary counts ("Retrieved 4 secrets") without actual samples. This made it difficult to verify findings or demonstrate real impact. The solution involved two changes: storing actual secrets in the detector's evidence dictionary, and implementing a redaction function that safely displays partial values. The credential exposure detector now generates PoC responses with redacted samples that prove the vulnerability without exposing complete credentials.

**SARIF Schema Compliance**

Implementing SARIF 2.1.0 support revealed the specification's complexity. The schema has strict requirements for mapping security findings to source code locations, representing attack flows, and categorizing vulnerability types. Key challenges included:

- Converting signal types to SARIF result objects
- Mapping affected resources to code location objects (even though MCP resources aren't traditional source files)
- Representing multi-step PoCs as SARIF code flows
- Handling Pydantic enum serialization (enums convert to strings in JSON output)

The enum handling issue was particularly subtle. Pydantic's `use_enum_values=True` converts enums to strings during serialization, breaking code that expects enum objects. The fix required type checking: `signal.type if isinstance(signal.type, str) else signal.type.value`

### Design Decisions

**Bundle Architecture vs Scattered Files**

The reporting system uses a bundle architecture where each assessment produces a single directory containing all outputs (3 report formats + audit log + metadata). This replaced the initial design of saving files directly to reports/. Benefits include:

- Easier sharing (one directory = complete assessment)
- Better organization (clear assessment boundaries)
- Metadata tracking (assessment ID, duration, framework version per bundle)
- Cleaner folder structure (reports/ contains only bundles)

**Automatic PoC Generation**

All detectors were refactored to automatically generate proof-of-concept exploits when vulnerabilities are found. This wasn't originally planned - the initial design had PoC generation as optional. Making it mandatory ensures every finding can be verified and reproduced. The detector base class now expects PoC methods, and the reporting system displays them prominently in all output formats.

**Folder Separation: captures/ vs reports/**

A clear distinction was established between raw evidence and final reports:
- `captures/` - Raw audit logs from SafeAdapter (may contain sensitive data, integrity-tracked)
- `reports/` - Final assessment bundles only (sanitized, shareable)

This separation makes it easier to manage evidence retention policies and share results safely.

### Development Process Insights

The end-to-end test script (`test_challenge1_with_report.py`) proved invaluable for catching integration issues. Unit tests validated individual components, but the full pipeline test revealed problems like ANSI color codes appearing in saved files and enum serialization mismatches. This reinforced the importance of integration testing for security tools where components interact in complex ways.

For security tools that generate sensitive data, .gitignore configuration becomes critical. The pattern `folder/*` with `!folder/.gitkeep` preserves repository structure while excluding all generated content (audit logs, assessment reports, test targets).

---

## 4. Next Steps

### Immediate Priorities (Next 1-2 Weeks)

**Phase 3: Additional Detectors**

| Priority | Detector | Target Challenge | Complexity |
|----------|----------|------------------|------------|
| 1 | Tool Poisoning Detector | Challenge 2 | Medium (behavioral analysis) |
| 2 | Challenge Coverage Analysis | All 10 challenges | Low (testing only) |
| 3 | Excessive Permissions Tester | Challenge 3 | Medium (schema analysis) |

The Tool Poisoning Detector for Challenge 2 will test for malicious tool behaviors like returning deceptive data or manipulating AI agent actions. This requires behavioral analysis capabilities since poisoning attacks are more subtle than credential exposure. The detector will need to compare expected vs actual tool responses and flag suspicious patterns.

Before building more detectors, the current framework should be tested against all 10 DV-MCP challenges to identify which vulnerabilities the existing detectors can already find. This will help prioritize which detection modules to build next and may reveal that some challenges can be detected by extending existing detectors rather than creating new ones.

### Medium-Term Goals (Next Month)

**Threat Modeling Engine**

The core models include a threat modeling engine design that hasn't been implemented yet. This engine will analyze signals from multiple detectors to identify attack chains - sequences of vulnerabilities that combine for greater impact. For example:

- Credential Exposure + Excessive Permissions → Account Takeover
- Tool Poisoning + Prompt Injection → Agent Manipulation
- Resource Enumeration + Path Traversal → Data Exfiltration

**Command-Line Interface**

Build a proper CLI with argument parsing so users can run assessments with `mcpsf assess` instead of writing Python scripts. Planned features:

- Detector selection (run all, or specify subset)
- Scope configuration (allowed prefixes, rate limits)
- Output format selection (JSON, SARIF, CLI, or all)
- Target specification (SSE URL or stdio command)

### Research and Improvements

**Active Testing for Credential Detector**

The credential exposure detector currently only passively scans resource content. It could be enhanced to actively test whether servers validate credential parameters by sending controlled injection payloads. This would increase detection thoroughness but requires careful design to avoid causing harm to target servers. Research is needed on safe active testing boundaries.

**Detector Development Guide**

Documentation should be expanded with a detector development guide covering:
- Detector interface implementation
- Detection types (passive vs active, pattern-based vs behavioral)
- PoC generation best practices
- Evidence collection and redaction strategies
- Standards mapping (CWE, OWASP, CVSS)

---

## 5. Blockers / Help Needed

### Current Status
No critical blockers. All planned Phase 2 tasks are complete and the framework successfully detects Challenge 1 vulnerabilities.

### Questions for Instructor Feedback

**1. PoC Redaction Strategy**

Current approach: secrets redacted to show first 6 + last 4 characters (e.g., "sk-a1b2...i9j0")

Questions:
- Is this the right balance between proving vulnerability existence and protecting sensitive data?
- Should redaction level be configurable (e.g., more/less characters, full masking option)?
- Are there industry standards for PoC evidence redaction we should follow?

**2. Detector Development Strategy**

Two possible approaches for the remaining 8 detectors:

| Approach | Pros | Cons |
|----------|------|------|
| **Iterative** (one detector → test → next) | Catches issues early, validates design per detector | Slower overall, may miss cross-detector issues |
| **Batch** (all detectors → test together) | Faster implementation, reveals integration issues | Late bug discovery, harder debugging |

Which approach would you recommend for this project?

**3. Development Priorities**

Current decision point: CLI interface vs additional detectors

- **CLI First**: Makes tool more user-friendly and production-ready, but delays vulnerability coverage
- **Detectors First**: Increases vulnerability coverage quickly, but tool remains script-based

Which would be more valuable at this stage of the project?

### Resource Needs

**Diverse Test Targets**

Currently testing only against DV-MCP (intentionally vulnerable). Access to legitimate MCP server implementations would help validate:
- False positive rate in real-world scenarios
- Framework compatibility with production MCP servers
- Detection accuracy across different server implementations

Recommendations for publicly available MCP servers would be appreciated.

---

## 6. Next Meeting

**Proposed Agenda:**
- Demo the complete reporting system with actual assessment results from Challenge 1
- Walk through the proof-of-concept generation architecture and discuss redaction strategy
- Review the detector development roadmap for Phase 3
- Discuss testing approach for the remaining 8 detectors
- Get feedback on CLI interface design and priority
- Review code organization and documentation completeness

---

## 7. Attachments / Links

**GitHub Branch:** https://github.com/JoKFA/MCP-Security-Framework/tree/v0.2/detectors-and-report-system

**Sample Assessment Bundle:** `reports/Challenge1_Basic_Prompt_Injection/`
- report.json (9.5KB) - Full machine-readable report
- report.txt (5.3KB) - Structured plain text report
- report.sarif (14KB) - SARIF 2.1.0 format for CI/CD integration
- audit.jsonl (4.5KB) - Complete audit log with integrity hash
- metadata.json (360B) - Assessment metadata

**Test Execution:**
```bash
# Run the complete assessment
python test_challenge1_with_report.py

# Output:
# Assessment complete!
# - 2 vulnerabilities detected (Credential Exposure, Prompt Injection)
# - 2 PoCs generated with actual evidence
# - Bundle created: reports/Challenge1_Basic_Prompt_Injection/
```

**Detection Results:**
```
Detector: Credential Exposure (MCP-2024-CE-001)
Status: PRESENT
Severity: HIGH (CVSS 8.2)
Confidence: 95%
Secrets Found: 4 (passwords, api_keys, connection_strings)
PoC: Shows redacted samples of leaked credentials

Detector: Prompt Injection (MCP-2024-PI-001)
Status: PRESENT
Severity: HIGH (CVSS 7.5)
Confidence: 95%
Affected Resources: internal://credentials
PoC: Demonstrates unauthorized access with content preview
```

---

## 8. Metrics Summary

**Phase 2 Completion:**
- Core framework: 100% complete
- Detectors implemented: 2 operational (Credential Exposure, Prompt Injection)
- Report formats: 3 complete (JSON, SARIF 2.1.0, CLI)
- Unit tests: 80+ passing
- Integration tests: 1 passing (Challenge 1)
- Documentation: Updated (CLAUDE.md, README.md)

**Code Statistics:**
- New files this week: 19
- Total lines added: 2,674
- Reporting system: ~1,200 lines
- Detector modules: ~800 lines
- Test code: ~400 lines
- Documentation: ~300 lines

**Test Coverage:**
- Vulnerabilities detected: 2/2 in Challenge 1 (100%)
- False positives: 0
- PoC success rate: 2/2 (100%)
- Assessment duration: 1.57 seconds
- Total requests: 6 (rate limited to 2 QPS)

---

## 9. Additional Notes

**Standards Compliance:**

The framework now tracks compliance with multiple security standards:
- CWE: CWE-522 (Credential Exposure), CWE-74 (Injection)
- OWASP LLM Top 10: LLM01 (Prompt Injection)
- OWASP API Security: API2 (Broken Authentication), API8 (Security Misconfiguration)
- CVSS v3.1: All findings scored (7.5-8.2 HIGH range)
- SARIF 2.1.0: Full compliance for CI/CD integration

**Project Structure**

The project structure was reorganized this week to accommodate the new reporting system and clarify folder purposes:

```
src/
├── core/
│   ├── models.py          (Core data models)
│   ├── runner.py          (Test orchestration)
│   └── reporters/         (NEW: Reporting system)
│       ├── base.py        (Abstract reporter interface)
│       ├── json_reporter.py
│       ├── sarif_reporter.py
│       ├── cli_reporter.py
│       └── manager.py     (Bundle orchestration)
├── modules/
│   └── detectors/
│       ├── credential_exposure.py       (NEW)
│       ├── tool_enumeration.py          (NEW)
│       └── prompt_injection_resource_params.py

reports/                   (Assessment bundles only - gitignored)
captures/                  (Audit logs only - gitignored)
targets/                   (External test servers - gitignored)
```

All three output folders are now properly gitignored using the `folder/*` pattern with `.gitkeep` files to preserve directory structure in the repository.

**Git Activity:**
- Branch created: v0.2/detectors-and-report-system
- Commits: 1 (consolidated update)
- Files changed: 19 (2,674 additions, 132 deletions)
- Status: Pushed to GitHub, ready for review

---

**Prepared By:** Yaoting
**Date:** October 22, 2025


