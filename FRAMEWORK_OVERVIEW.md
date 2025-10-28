# MCP Security Framework Overview

**Comprehensive automated security assessment for Model Context Protocol (MCP) servers**

## What Was Built

This framework provides both **passive detection** (analyzing metadata and patterns) and **active confirmation** (testing vulnerabilities by interacting with servers) to identify security weaknesses in MCP implementations.

## Architecture Overview

### Directory Structure

```
src/modules/
├── passive_detectors/       # Fast pattern-based detection
│   ├── credential_exposure.py
│   ├── prompt_injection_resource_params.py
│   ├── tool_enumeration.py
│   ├── unauth_access.py          # NEW
│   └── privilege_abuse.py        # NEW
└── active_detectors/         # Confirmation testing
    ├── prompt_injection_active.py
    └── tool_abuse_active.py
```

### Detection Flow

1. **Load detectors** from `passive_detectors/` folder
2. **Load active detectors** from `active_detectors/` folder  
3. **Run passive detectors first** (fast, metadata analysis)
4. **Run active detectors** (slower, interactive confirmation)
5. **Generate comprehensive reports** with proof-of-concept

## Detectors Explained

### Passive Detectors (Pattern Analysis)

#### 1. Credential Exposure Detector
- **What it does**: Scans resources for API keys, passwords, tokens, database URLs
- **Method**: Pattern matching using regex for credentials
- **Output**: Lists exposed secrets with locations
- **Standards**: CWE-522, OWASP LLM01, CVSS 8.2 HIGH

#### 2. Prompt Injection via Resource Parameters
- **What it does**: Identifies parameterized resources vulnerable to injection
- **Method**: Detects resources with `{param}` patterns that accept user input
- **Output**: Lists parameterized resources and generates PoC payloads
- **Example**: `notes://{user_id}` → Potential injection point

#### 3. Tool Enumeration Analyzer
- **What it does**: Catalogues all available tools and their capabilities
- **Method**: Analyzes tool schemas and descriptions
- **Output**: Full inventory of tools with metadata

#### 4. Unauthenticated Access Detector (NEW - Top 25 #5)
- **What it does**: Checks if server requires authentication
- **Method**: Attempts to list tools and resources without auth
- **Detection**: If both succeed → server has no authentication (CRITICAL)
- **Standards**: CWE-284, CVSS 10.0 CRITICAL
- **Test Results**: ✅ Detects unprotected servers

#### 5. Privilege Abuse Detector (NEW - Top 25 #19)
- **What it does**: Identifies tools with excessive permissions
- **Method**: Analyzes tool capabilities vs. stated purpose
- **Examples**: 
  - File manager with read/write/delete → violates least privilege
  - Calculator with file system access
- **Standards**: CWE-250, CVSS 6.5 MEDIUM
- **Test Results**: ✅ Detects Challenge 3's file_manager abuse

### Active Detectors (Confirmation Testing)

#### 1. Prompt Injection Active Confirmation
- **What it does**: Actually tests if prompt injection works
- **Method**: 
  1. Injects unique canary: `MCPSF_INJECT_[random]`
  2. Reads resource with canary as parameter
  3. Checks if canary appears in response
  4. If YES → vulnerability CONFIRMED
- **Why Active**: Just having parameterized resources doesn't mean they're exploitable
- **Test Results**: ✅ Confirms DV-MCP Challenge 1 vulnerability

#### 2. Tool Abuse Active Confirmation
- **What it does**: Actually calls dangerous tools to confirm they work
- **Method**:
  1. Finds tools with dangerous keywords (execute, delete, etc.)
  2. Calls them with safe test parameters
  3. Observes response
  4. If tool executes → vulnerability CONFIRMED
- **Why Active**: Detecting "dangerous" in description ≠ proof it works
- **Test Results**: ✅ Confirms Challenge 3's file_manager executes

## Key Concepts

### Passive vs Active Detection

**Passive Detection**:
- Fast pattern matching on metadata
- No interaction with server
- Examples: Regex for credentials, checking for `{param}` in URIs
- Confidence: Medium (might be false positives)

**Active Detection**:
- Actually exploits the vulnerability
- Sends canaries/payloads to server
- Confirms by observing response
- Confidence: High (definitive proof)

### Why Both?

1. **Passive first**: Quick screening, catch obvious issues
2. **Active second**: Confirm real vulnerabilities, reduce false positives
3. **Comprehensive**: Covers discovery AND exploitation

### Canaries Explained

A "canary" is a harmless unique marker used to detect reflection:
- **Generated**: `MCPSF_INJECT_3874c4e425542f24` (random hex)
- **Injected**: Into vulnerable parameter (e.g., `notes://MCPSF_INJECT_3874c4e425542f24`)
- **Observed**: If server returns canary in response → vulnerability confirmed
- **Why Safe**: Canary is meaningless, just used for detection, not damage

## Implementation Highlights

### Registry System

```python
# Automatically loads detectors from directories
Loading PASSIVE detectors...
  ✓ MCP-2024-CE-001 (Credential Exposure Detector)
  ✓ MCP-2024-PA-001 (Privilege Abuse Detector)
  ✓ MCP-2024-UA-001 (Unauthenticated Access Detector)
  ✓ MCP-2024-PI-001 (Prompt Injection via Resource Parameters)
  ✓ MCP-2024-TE-001 (Tool Enumeration Analyzer)

Loading ACTIVE detectors...
  ✓ MCP-2024-ACTIVE-PI-001 (Active Prompt Injection Confirmation)
  ✓ MCP-2024-ACTIVE-TA-001 (Active Tool Abuse Confirmation)
```

### Signal Types

Detectors emit typed signals consumed by the correlator:
- `REFLECTION` - Canary found in response
- `ERROR_SIGNATURE` - Stack traces leaked
- `AUTH_MISMATCH` - Authentication failures/bypasses
- `SCHEMA_OVERPERMISSIVE` - Excessive tool permissions
- `SENSITIVE_EXPOSURE` - Credentials in responses

### Standard Compliance

Each detector maps to security standards:
- **CWE**: Common Weakness Enumeration
- **OWASP**: API Security Top 10 / LLM Security
- **ASVS**: Application Security Verification Standard
- **CVSS**: Common Vulnerability Scoring System

## Test Results

### Challenge 1 (Prompt Injection)
✅ **Active Prompt Injection**: PRESENT (confidence 0.98)
- Canary `MCPSF_INJECT_[hex]` successfully injected and reflected

✅ **Unauthenticated Access**: PRESENT (confidence 0.95)
- 1 tool and 1 resource accessible without auth

✅ **Credential Exposure**: PRESENT (confidence 0.95)
- Internal credentials exposed in resource

✅ **Passive Prompt Injection**: PRESENT (confidence 0.95)
- Parameterized `notes://{user_id}` detected

### Challenge 3 (Excessive Permissions)
✅ **Active Tool Abuse**: PRESENT (confidence 0.95)
- `file_manager` tool executed successfully

✅ **Unauthenticated Access**: PRESENT (confidence 0.95)
- Tools accessible without authentication

✅ **Privilege Abuse**: PRESENT (confidence 0.90)
- File manager has read/write/delete permissions (violates least privilege)

## Usage Example

```python
from src.core.runner import TestRunner
from src.core.policy import ScopeConfig

scope = ScopeConfig(
    target="http://localhost:9001/sse",
    transport="sse",
    allowed_prefixes=["notes://", "internal://", "/"],
    blocked_paths=[]
)

runner = TestRunner(scope)
result = await runner.assess()

# Results contain:
# - status (PRESENT/ABSENT/UNKNOWN)
# - confidence score
# - signals (typed observations)
# - proof_of_concepts (actual exploit demonstrations)
# - evidence (raw data)
```

## Security Considerations

### Safe Active Testing

- **Canaries**: Harmless markers for reflection testing
- **Rate Limiting**: Built-in via SafeAdapter
- **Scope Control**: Only tests allowed resources
- **Read-Only**: Active detectors don't modify/damage data

### What Gets Tested

✅ Read operations
✅ Injection with canaries
✅ Tool calls with safe parameters
❌ Write/delete operations
❌ Network egress
❌ Data exfiltration

## Future Enhancements

### Additional Passive Detectors
- SQL Injection detection (Top 25 #21)
- Path Traversal detection (Top 25 #10)
- Tool Name Spoofing detection (Top 25 #12)
- Configuration Poisoning (Top 25 #7)

### Additional Active Detectors
- Command Injection confirmation (Top 25 #2)
- RCE verification (Top 25 #4)
- Token theft confirmation (Top 25 #8)

### Advanced Features
- Multi-vector attack chains
- Correlation of related vulnerabilities
- Exploit chain generation
- Remediation recommendations

## Summary

This framework provides **automated security assessment** for MCP servers with:
- ✅ 7 working detectors (5 passive, 2 active)
- ✅ Full standards compliance (CWE, OWASP, ASVS, CVSS)
- ✅ Comprehensive reporting with PoCs
- ✅ Safe active testing (no damage to target servers)
- ✅ Tested against damn vulnerable MCP server

The combination of passive pattern detection and active confirmation testing provides high-confidence vulnerability identification while maintaining safety during assessment.

