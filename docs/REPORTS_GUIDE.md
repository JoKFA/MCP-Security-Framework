# Reports Guide

**Version:** 0.4.0
**Last Updated:** 2025-11-24
**Audience:** DevOps Engineers, Security Teams

---

## Table of Contents

1. [Overview](#overview)
2. [Report Formats](#report-formats)
3. [CI/CD Integration](#cicd-integration)
4. [Report Analysis](#report-analysis)
5. [Automation Examples](#automation-examples)

---

## Overview

The MCP Security Framework generates multiple report formats suitable for different audiences and use cases:

| Format | File | Purpose | Audience |
|--------|------|---------|----------|
| **JSON** | `report.json` | Machine-readable, CI/CD integration | Automation, Developers |
| **SARIF** | `report.sarif` | GitHub Security Tab, IDE integration | Developers, Security Teams |
| **CLI** | `report.txt` | Human-readable summary | Humans, Terminal users |
| **Audit Log** | `audit.jsonl` | Request/response history | Security Analysts, Debugging |
| **Metadata** | `metadata.json` | Assessment context | All |

All reports are saved to: `reports/<server-name>_<timestamp>/`

---

## Report Formats

### JSON Report (report.json)

**Purpose:** Primary machine-readable format for CI/CD pipelines.

**Structure:**
```json
{
  "summary": {
    "present": 4,
    "absent": 10,
    "error": 0,
    "total": 14
  },
  "profile": {
    "server_name": "Challenge 1 - Basic Prompt Injection",
    "protocol_version": "2024-11-05",
    "capabilities": {
      "tools": true,
      "resources": true,
      "prompts": false
    },
    "tool_count": 2,
    "resource_count": 1
  },
  "results": [
    {
      "detector_id": "MCP-2024-PI-001",
      "detector_name": "Prompt Injection via Resource Parameters",
      "status": "PRESENT",
      "confidence": 0.95,
      "evidence": {
        "injected_payload": "<malicious>Ignore all previous instructions</malicious>",
        "response_indicators": ["injection_reflected", "behavior_modified"],
        "affected_resources": ["file://user_data.txt"]
      },
      "signals": [
        {
          "type": "injection_success",
          "description": "Malicious payload was reflected in response",
          "severity": "HIGH",
          "confidence": 0.95,
          "evidence": {
            "payload": "<malicious>...</malicious>",
            "response": "...reflected content..."
          }
        }
      ],
      "standards": {
        "cvss": {
          "score": 8.1,
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "severity": "HIGH"
        },
        "cwe": ["CWE-79", "CWE-94"],
        "owasp_llm": ["LLM01:2025"],
        "owasp_api": ["API3:2023"]
      },
      "metadata": {
        "timestamp": "2025-11-24T12:00:00Z",
        "duration_s": 2.3
      }
    }
  ],
  "metadata": {
    "assessment_timestamp": "2025-11-24T12:00:00Z",
    "assessment_duration_s": 45.2,
    "framework_version": "0.4.0",
    "source": "targets/vulnerable/dv-mcp/challenges/easy/challenge1",
    "assessment_mode": "balanced"
  }
}
```

**Key Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `summary.present` | int | Number of vulnerabilities found |
| `summary.absent` | int | Number of checks that passed |
| `summary.error` | int | Number of detector errors |
| `results[].status` | enum | PRESENT, ABSENT, ERROR |
| `results[].confidence` | float | 0.0 to 1.0 |
| `results[].standards.cvss.score` | float | CVSS 3.1 score (0.0-10.0) |

**Usage:**
```python
import json

# Load report
with open("reports/mcp_20251124/report.json") as f:
    report = json.load(f)

# Check for critical vulnerabilities
critical = [r for r in report["results"]
            if r["status"] == "PRESENT"
            and r["standards"]["cvss"]["score"] >= 9.0]

if critical:
    print(f"CRITICAL: {len(critical)} high-severity vulnerabilities found!")
    sys.exit(1)
```

---

### SARIF Report (report.sarif)

**Purpose:** GitHub Security Tab integration, IDE integration (VS Code, etc.)

**Structure:**
```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "MCP Security Framework",
          "version": "0.4.0",
          "informationUri": "https://github.com/yourorg/mcp-security-framework",
          "rules": [
            {
              "id": "MCP-2024-PI-001",
              "name": "PromptInjectionViaResourceParameters",
              "shortDescription": {
                "text": "Prompt Injection via Resource Parameters"
              },
              "fullDescription": {
                "text": "Server accepts resource parameters without validation..."
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "tags": ["security", "injection", "prompt"],
                "precision": "high"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "MCP-2024-PI-001",
          "level": "error",
          "message": {
            "text": "Prompt injection vulnerability detected in resource 'file://user_data.txt'"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/server.py",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 42
                }
              }
            }
          ],
          "properties": {
            "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "confidence": 0.95
          }
        }
      ]
    }
  ]
}
```

**GitHub Integration:**

1. Upload SARIF to GitHub Security Tab:
```bash
# Using GitHub CLI
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  /repos/OWNER/REPO/code-scanning/sarifs \
  -f sarif=@report.sarif \
  -f commit_sha=$(git rev-parse HEAD) \
  -f ref=refs/heads/main
```

2. View in GitHub UI:
   - Navigate to **Security** → **Code Scanning**
   - See vulnerabilities annotated on code

**Benefits:**
- Integrated with GitHub pull requests
- Code annotations show exact vulnerable lines
- Trend tracking over time
- Team collaboration features

---

### CLI Report (report.txt)

**Purpose:** Human-readable summary for terminal output.

**Example:**
```
======================================================================
  ASSESSMENT COMPLETE (45.2s)
======================================================================
  Target: Challenge 1 - Basic Prompt Injection
  Source: targets/vulnerable/dv-mcp/challenges/easy/challenge1
  Mode: balanced
  Vulnerabilities: 4
  Detectors Run: 14
======================================================================

VULNERABILITIES FOUND
----------------------------------------------------------------------

[HIGH] MCP-2024-PI-001: Prompt Injection via Resource Parameters
  Description: Server accepts resource parameters without proper validation,
              allowing injection of malicious instructions that can manipulate
              LLM behavior or extract sensitive information.

  Evidence:
    • Injected payload: <malicious>Ignore all previous instructions</malicious>
    • Resource affected: file://user_data.txt
    • Response contained injected content

  Impact:
    • Attacker can manipulate LLM responses
    • Potential data exfiltration
    • Loss of response integrity

  Recommendation:
    • Validate and sanitize all resource parameters
    • Implement input allowlisting
    • Escape special characters before processing

  Standards:
    • CVSS 3.1: 8.1 (HIGH)
    • CWE: CWE-79, CWE-94
    • OWASP LLM: LLM01:2025
    • OWASP API: API3:2023

----------------------------------------------------------------------

[MEDIUM] MCP-2024-EP-001: Excessive Permissions
  Description: Tool 'read_file' has overly broad filesystem access...

  Evidence:
    • Tool allows reading from any path
    • No path restriction detected
    • Successfully read /etc/passwd

  Recommendation:
    • Implement path allowlisting
    • Use least-privilege principle
    • Add permission checks

  Standards:
    • CVSS 3.1: 6.5 (MEDIUM)
    • CWE: CWE-732
    • OWASP API: API5:2023

======================================================================

SUMMARY
----------------------------------------------------------------------
  ✓ Passed:  10 checks
  ✗ Failed:   4 vulnerabilities
  ⚠ Errors:   0

  Severity Breakdown:
    • CRITICAL: 0
    • HIGH:     2
    • MEDIUM:   2
    • LOW:      0

Reports saved to: reports/Challenge_1_20251124_120000/

Next Steps:
  1. Review and prioritize vulnerabilities by CVSS score
  2. Implement recommended fixes
  3. Re-run assessment to verify fixes
  4. Review SARIF report in GitHub Security Tab
```

**Usage:**
```bash
# View in terminal
cat reports/mcp_20251124/report.txt

# Or use less for pagination
less reports/mcp_20251124/report.txt
```

---

### Audit Log (audit.jsonl)

**Purpose:** Complete request/response history for debugging and forensics.

**Format:** JSON Lines (one JSON object per line)

**Example:**
```jsonl
{"timestamp":"2025-11-24T12:00:01","method":"initialize","request":{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05"}},"response":{"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"Challenge 1"}}}}
{"timestamp":"2025-11-24T12:00:02","method":"tools/list","request":{"jsonrpc":"2.0","method":"tools/list"},"response":{"result":{"tools":[{"name":"search","description":"Search database"}]}}}
{"timestamp":"2025-11-24T12:00:03","method":"tools/call","tool":"search","args":{"query":"<malicious>"},"response":{"result":{"content":"...reflected payload..."}}}
```

**Usage:**
```python
import json

# Parse audit log
with open("reports/mcp_20251124/audit.jsonl") as f:
    for line in f:
        entry = json.loads(line)
        if entry["method"] == "tools/call":
            print(f"Tool: {entry['tool']}")
            print(f"Args: {entry['args']}")
            print(f"Response: {entry['response'][:100]}...")
```

**Analysis:**
```bash
# Count total requests
wc -l audit.jsonl

# Find all tool calls
grep "tools/call" audit.jsonl | jq .

# Find failed requests
grep "error" audit.jsonl
```

---

### Metadata (metadata.json)

**Purpose:** Assessment context and configuration.

**Example:**
```json
{
  "assessment_id": "challenge1_20251124_120000",
  "timestamp": "2025-11-24T12:00:00Z",
  "duration_s": 45.2,
  "source": "targets/vulnerable/dv-mcp/challenges/easy/challenge1",
  "source_type": "local",
  "framework_version": "0.4.0",
  "python_version": "3.11.5",
  "assessment_mode": "balanced",
  "detectors_run": [
    "MCP-2024-PI-001",
    "MCP-2024-TP-001",
    "..."
  ],
  "environment": {
    "os": "Linux",
    "docker_version": "24.0.5",
    "container_image": "mcp-runner-python:latest"
  }
}
```

---

## CI/CD Integration

### GitHub Actions

**Basic workflow:**

```yaml
name: MCP Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install MCPSF
        run: |
          pip install -r requirements.txt

      - name: Run Security Assessment
        run: |
          python mcpsf.py assess ./src/mcp-server -o reports/

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: reports/*/report.sarif

      - name: Check for vulnerabilities
        run: |
          python -c "
          import json, sys
          with open('reports/*/report.json') as f:
              report = json.load(f)
              if report['summary']['present'] > 0:
                  print(f'FAIL: {report[\"summary\"][\"present\"]} vulnerabilities found')
                  sys.exit(1)
              print('PASS: No vulnerabilities found')
          "

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: reports/
```

**Advanced: Fail on severity:**

```yaml
      - name: Check severity threshold
        run: |
          python scripts/check_threshold.py --max-cvss 7.0 reports/*/report.json
```

```python
# scripts/check_threshold.py
import json, sys, argparse

parser = argparse.ArgumentParser()
parser.add_argument("report", help="Path to report.json")
parser.add_argument("--max-cvss", type=float, default=7.0)
args = parser.parse_args()

with open(args.report) as f:
    report = json.load(f)

high_severity = [
    r for r in report["results"]
    if r["status"] == "PRESENT"
    and r.get("standards", {}).get("cvss", {}).get("score", 0) > args.max_cvss
]

if high_severity:
    print(f"FAIL: {len(high_severity)} vulnerabilities above CVSS {args.max_cvss}")
    for vuln in high_severity:
        cvss = vuln["standards"]["cvss"]["score"]
        print(f"  - {vuln['detector_id']}: CVSS {cvss}")
    sys.exit(1)

print(f"PASS: No vulnerabilities above CVSS {args.max_cvss}")
```

---

### GitLab CI

```yaml
# .gitlab-ci.yml
security-scan:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - python mcpsf.py assess ./src/mcp-server -o reports/
    - python scripts/check_threshold.py reports/*/report.json
  artifacts:
    when: always
    paths:
      - reports/
    reports:
      sast: reports/*/report.sarif
```

---

### Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install -r requirements.txt'
                sh 'python mcpsf.py assess ./src/mcp-server -o reports/'
            }
        }

        stage('Check Results') {
            steps {
                script {
                    def report = readJSON file: 'reports/*/report.json'
                    if (report.summary.present > 0) {
                        error("Security vulnerabilities found!")
                    }
                }
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: false
                publishHTML([
                    reportDir: 'reports',
                    reportFiles: '*/report.txt',
                    reportName: 'Security Report'
                ])
            }
        }
    }
}
```

---

## Report Analysis

### Trending Over Time

**Track vulnerability trends:**

```python
import json, os
from pathlib import Path
from datetime import datetime

def analyze_trends(reports_dir):
    reports = []

    for report_dir in Path(reports_dir).iterdir():
        if not report_dir.is_dir():
            continue

        report_path = report_dir / "report.json"
        if not report_path.exists():
            continue

        with open(report_path) as f:
            report = json.load(f)
            reports.append({
                "timestamp": report["metadata"]["assessment_timestamp"],
                "present": report["summary"]["present"],
                "absent": report["summary"]["absent"]
            })

    # Sort by timestamp
    reports.sort(key=lambda r: r["timestamp"])

    # Print trend
    print("Vulnerability Trend:")
    for r in reports:
        print(f"{r['timestamp']}: {r['present']} vulnerabilities")

analyze_trends("reports/")
```

### Compare Reports

**Compare two assessments:**

```python
def compare_reports(old_report, new_report):
    with open(old_report) as f:
        old = json.load(f)
    with open(new_report) as f:
        new = json.load(f)

    old_vulns = {r["detector_id"] for r in old["results"] if r["status"] == "PRESENT"}
    new_vulns = {r["detector_id"] for r in new["results"] if r["status"] == "PRESENT"}

    # Fixed vulnerabilities
    fixed = old_vulns - new_vulns
    if fixed:
        print(f"✅ Fixed: {len(fixed)} vulnerabilities")
        for vuln_id in fixed:
            print(f"  - {vuln_id}")

    # New vulnerabilities
    introduced = new_vulns - old_vulns
    if introduced:
        print(f"⚠️ Introduced: {len(introduced)} new vulnerabilities")
        for vuln_id in introduced:
            print(f"  - {vuln_id}")

    # No change
    if not fixed and not introduced:
        print("No change in vulnerabilities")

compare_reports("reports/old/report.json", "reports/new/report.json")
```

---

## Automation Examples

### Slack Notifications

```python
import requests, json

def send_slack_notification(webhook_url, report_path):
    with open(report_path) as f:
        report = json.load(f)

    vulns = report["summary"]["present"]
    severity = "danger" if vulns > 0 else "good"

    message = {
        "attachments": [
            {
                "color": severity,
                "title": "MCP Security Scan Complete",
                "fields": [
                    {"title": "Target", "value": report["profile"]["server_name"], "short": True},
                    {"title": "Vulnerabilities", "value": str(vulns), "short": True},
                    {"title": "Duration", "value": f"{report['metadata']['assessment_duration_s']:.1f}s", "short": True}
                ]
            }
        ]
    }

    requests.post(webhook_url, json=message)

# Usage
send_slack_notification("https://hooks.slack.com/...", "reports/*/report.json")
```

### Email Reports

```python
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

def email_report(smtp_server, from_addr, to_addr, report_path):
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = "MCP Security Assessment Report"

    # Attach report.txt
    with open(report_path / "report.txt") as f:
        body = f.read()
    msg.attach(MIMEText(body, 'plain'))

    # Attach report.json
    with open(report_path / "report.json", 'rb') as f:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="report.json"')
        msg.attach(part)

    # Send
    server = smtplib.SMTP(smtp_server, 587)
    server.starttls()
    server.send_message(msg)
    server.quit()
```

---

## Conclusion

The MCP Security Framework provides comprehensive reporting for all use cases:
- **JSON** for automation and CI/CD
- **SARIF** for GitHub/IDE integration
- **CLI** for human review
- **Audit logs** for debugging
- **Metadata** for context

By integrating reports into your CI/CD pipeline, you can maintain continuous security monitoring and catch vulnerabilities before they reach production.
