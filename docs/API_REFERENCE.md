# API Reference

**Version:** 0.4.0
**Last Updated:** 2025-11-24
**Audience:** Developers, Automation Engineers

---

## Table of Contents

1. [CLI API](#cli-api)
2. [Python API](#python-api)
3. [Web API](#web-api)
4. [Configuration Files](#configuration-files)

---

## CLI API

### mcpsf assess

Assess an MCP server for security vulnerabilities.

**Syntax:**
```bash
python mcpsf.py assess <source> [options]
```

**Arguments:**

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `source` | string | Yes | MCP source (npm/github/local/url) |

**Options:**

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--detectors` | `-d` | string | all | Comma-separated detector IDs |
| `--output` | `-o` | path | `./reports` | Output directory for reports |
| `--mode` | | enum | `balanced` | Assessment mode (safe/balanced/aggressive) |
| `--profile` | | enum | | Alias for --mode |
| `--scope` | `-s` | path | | Path to scope.yaml file |
| `--verbose` | `-v` | flag | false | Enable verbose logging |

**Examples:**

```bash
# Assess npm package
python mcpsf.py assess @modelcontextprotocol/server-time

# Assess local directory
python mcpsf.py assess targets/vulnerable/dv-mcp/challenges/easy/challenge1

# Assess GitHub repository
python mcpsf.py assess https://github.com/modelcontextprotocol/servers/tree/main/src/time

# Run specific detectors
python mcpsf.py assess <source> --detectors MCP-2024-PI-001,MCP-2024-TP-001

# Custom output directory
python mcpsf.py assess <source> -o ./my-reports

# Aggressive mode
python mcpsf.py assess <source> --mode aggressive

# With custom scope
python mcpsf.py assess <source> --scope scope.yaml

# Verbose output
python mcpsf.py assess <source> -v
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Success, no vulnerabilities found |
| 1 | Vulnerabilities found |
| 2 | Assessment error |

**Source Types:**

| Pattern | Type | Example |
|---------|------|---------|
| `@scope/package` | npm (scoped) | `@modelcontextprotocol/server-time` |
| `package-name` | npm (unscoped) | `sqlite-mcp-server` |
| `github.com/*` | GitHub | `https://github.com/user/repo/tree/main/path` |
| `/absolute/path` | Local (absolute) | `/home/user/projects/mcp-server` |
| `./relative/path` | Local (relative) | `./targets/mcp` |
| `http://...` | Remote HTTP | `http://localhost:9001/sse` |
| `https://...` | Remote HTTPS | `https://api.example.com/mcp` |
| `stdio://...` | stdio URL | `stdio://python/-m/module` |

---

### mcpsf list-detectors

List all available security detectors.

**Syntax:**
```bash
python mcpsf.py list-detectors [options]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--verbose` | flag | false | Show detailed information |

**Example:**
```bash
# List all detectors
python mcpsf.py list-detectors

# Detailed information
python mcpsf.py list-detectors --verbose
```

**Output:**
```
Available Detectors (14 total):

MCP-2024-PI-001   Prompt Injection via Resource Parameters        [HIGH]
MCP-2024-TP-001   Tool Poisoning Detector                        [HIGH]
MCP-2024-CE-001   Credential Exposure Detector                   [CRITICAL]
MCP-2024-CI-001   Command Injection Detector                     [CRITICAL]
...
```

---

### mcpsf version

Show framework version information.

**Syntax:**
```bash
python mcpsf.py version
```

**Output:**
```
MCP Security Framework v0.4.0
Python: 3.11.5
Docker: 24.0.5
```

---

## Python API

### AssessmentPipeline

Main entry point for programmatic assessments.

**Import:**
```python
from src.core.pipeline import AssessmentPipeline
```

**Class:**
```python
class AssessmentPipeline:
    def __init__(self, interactive: bool = False):
        """
        Initialize assessment pipeline.

        Args:
            interactive: Allow interactive prompts (e.g., credentials)
        """
```

**Methods:**

#### pipeline.run()

```python
async def run(
    self,
    source: str,
    profile: str = "balanced",
    detectors: Optional[List[str]] = None
) -> AssessmentResult:
    """
    Run complete security assessment.

    Args:
        source: MCP source (npm/github/local/url)
        profile: Assessment mode ("safe", "balanced", "aggressive")
        detectors: List of detector IDs (None = all)

    Returns:
        AssessmentResult with findings

    Raises:
        SourceDetectionError: Cannot determine source type
        ProvisioningError: Container provisioning failed
        BridgeError: Transport normalization failed
        AssessmentError: Security assessment failed
    """
```

**Example:**
```python
import asyncio
from src.core.pipeline import AssessmentPipeline

async def assess_mcp():
    pipeline = AssessmentPipeline(interactive=True)

    result = await pipeline.run(
        source="@modelcontextprotocol/server-time",
        profile="balanced",
        detectors=None  # Run all detectors
    )

    print(f"Vulnerabilities found: {result.summary.present}")

    for detection in result.results:
        if detection.status == "PRESENT":
            print(f"  - {detection.detector_id}: {detection.detector_name}")

    return result

# Run assessment
result = asyncio.run(assess_mcp())
```

---

### SourceDiscovery

Detect and analyze MCP sources.

**Import:**
```python
from src.core.discovery import SourceDiscovery, ServerConfig
```

**Class:**
```python
class SourceDiscovery:
    def discover(self, source: str) -> List[ServerConfig]:
        """
        Discover MCP server(s) from source.

        Args:
            source: npm package, GitHub URL, local path, or remote URL

        Returns:
            List of ServerConfig (can be multiple for monorepos)

        Raises:
            SourceDetectionError: Cannot determine source type
            MCPNotFoundError: No MCP found in source
        """
```

**Example:**
```python
from src.core.discovery import SourceDiscovery

discovery = SourceDiscovery()

# Discover from npm package
configs = discovery.discover("@modelcontextprotocol/server-time")

for config in configs:
    print(f"Found: {config.name}")
    print(f"  Language: {config.language}")
    print(f"  Transport: {config.transport}")
    print(f"  Entry point: {' '.join(config.entry_point)}")
```

---

### ContainerProvisioner

Provision Docker containers for MCP servers.

**Import:**
```python
from src.core.provisioner import ContainerProvisioner
```

**Class:**
```python
class ContainerProvisioner:
    async def provision(self, config: ServerConfig) -> ProvisionedContainer:
        """
        Provision container for MCP server.

        Args:
            config: ServerConfig from discovery

        Returns:
            ProvisionedContainer with running container info

        Raises:
            ProvisioningError: Container provisioning failed
        """
```

**Example:**
```python
from src.core.discovery import SourceDiscovery
from src.core.provisioner import ContainerProvisioner

# Discover MCP
discovery = SourceDiscovery()
config = discovery.discover("@modelcontextprotocol/server-time")[0]

# Provision container
provisioner = ContainerProvisioner()
container = await provisioner.provision(config)

print(f"Container ID: {container.container_id}")
print(f"MCP URL: {container.url}")

# Don't forget cleanup!
await provisioner.cleanup(container)
```

---

### UniversalBridge

Normalize MCP transport to HTTP.

**Import:**
```python
from src.core.bridge import UniversalBridge
```

**Class:**
```python
class UniversalBridge:
    async def start(
        self,
        container: Container,
        config: ServerConfig
    ) -> str:
        """
        Start transport bridge.

        Args:
            container: Docker container
            config: ServerConfig

        Returns:
            Normalized HTTP URL

        Raises:
            BridgeError: Bridge startup failed
        """
```

**Example:**
```python
from src.core.bridge import UniversalBridge

bridge = UniversalBridge()

# Start bridge for container
url = await bridge.start(container, config)

print(f"Bridge URL: {url}")

# Use URL for assessment
# ...

# Cleanup
await bridge.stop()
```

---

### TestRunner

Run security detectors against MCP server.

**Import:**
```python
from src.core.runner import TestRunner
from src.core.policy import ScopeConfig
```

**Class:**
```python
class TestRunner:
    def __init__(self, scope: ScopeConfig):
        """
        Initialize test runner.

        Args:
            scope: Scope configuration
        """

    async def assess(self) -> AssessmentResult:
        """
        Run security assessment.

        Returns:
            AssessmentResult with findings
        """
```

**Example:**
```python
from src.core.runner import TestRunner
from src.core.policy import ScopeConfig, RateLimitConfig, PolicyConfig

# Configure scope
scope = ScopeConfig(
    target="http://localhost:9001/sse",
    mode="balanced",
    rate_limit=RateLimitConfig(qps=10, burst=20),
    policy=PolicyConfig(
        dry_run=False,
        redact_evidence=True,
        max_total_requests=1000
    )
)

# Run assessment
runner = TestRunner(scope)
result = await runner.assess()

print(f"Vulnerabilities: {result.summary.present}")
```

---

### ReportManager

Generate assessment reports.

**Import:**
```python
from src.core.reporters.manager import ReportManager
```

**Class:**
```python
class ReportManager:
    def __init__(self, reports_dir: Path):
        """
        Initialize report manager.

        Args:
            reports_dir: Directory to save reports
        """

    def generate_bundle(
        self,
        result: AssessmentResult,
        bundle_name: Optional[str] = None
    ) -> Path:
        """
        Generate all report formats.

        Args:
            result: AssessmentResult
            bundle_name: Custom bundle name (default: auto-generated)

        Returns:
            Path to bundle directory
        """
```

**Example:**
```python
from pathlib import Path
from src.core.reporters.manager import ReportManager

# Generate reports
report_mgr = ReportManager(reports_dir=Path("./reports"))
bundle_path = report_mgr.generate_bundle(result, bundle_name="my-assessment")

print(f"Reports saved to: {bundle_path}")
print(f"  - {bundle_path / 'report.json'}")
print(f"  - {bundle_path / 'report.sarif'}")
print(f"  - {bundle_path / 'report.txt'}")
```

---

## Web API

The Flask web UI exposes REST API endpoints.

**Base URL:** `http://127.0.0.1:5000`

### POST /api/assess

Start a new assessment.

**Request:**
```json
{
  "target": "@modelcontextprotocol/server-time",
  "mode": "balanced"
}
```

**Response:**
```json
{
  "assessment_id": "20251124_120000",
  "status": "started",
  "message": "Assessment started"
}
```

**cURL:**
```bash
curl -X POST http://127.0.0.1:5000/api/assess \
  -H "Content-Type: application/json" \
  -d '{"target": "@modelcontextprotocol/server-time", "mode": "balanced"}'
```

---

### GET /api/assess/<assessment_id>/status

Check assessment progress.

**Response:**
```json
{
  "status": "running",
  "message": "Running AMSAW v2 pipeline...",
  "progress": 45,
  "logs": [
    "[*] Detected source type: npm",
    "[*] Detected language: Node.js",
    "[*] Transport: SSE"
  ],
  "error": null,
  "report_id": null
}
```

**Status Values:**
- `running` - Assessment in progress
- `completed` - Assessment finished successfully
- `error` - Assessment failed

**cURL:**
```bash
curl http://127.0.0.1:5000/api/assess/20251124_120000/status
```

---

### GET /api/reports

List all available reports.

**Response:**
```json
[
  {
    "id": "server-time_20251124_120000",
    "name": "server time 20251124 120000",
    "metadata": {
      "timestamp": "2025-11-24T12:00:00Z",
      "source": "@modelcontextprotocol/server-time",
      "vulnerabilities": 0
    },
    "path": "server-time_20251124_120000"
  }
]
```

**cURL:**
```bash
curl http://127.0.0.1:5000/api/reports
```

---

### GET /api/report/<report_id>

Get specific report (JSON format).

**Response:**
```json
{
  "summary": {
    "present": 0,
    "absent": 14,
    "error": 0
  },
  "profile": {...},
  "results": [...]
}
```

**cURL:**
```bash
curl http://127.0.0.1:5000/api/report/server-time_20251124_120000
```

---

### GET /api/report/<report_id>/sarif

Get specific report (SARIF format).

**Response:**
```json
{
  "version": "2.1.0",
  "$schema": "...",
  "runs": [...]
}
```

**cURL:**
```bash
curl http://127.0.0.1:5000/api/report/server-time_20251124_120000/sarif
```

---

## Configuration Files

### scope.yaml

Define assessment scope and safety guardrails.

**Location:** Custom (pass via `--scope` flag)

**Structure:**
```yaml
# Target configuration
target: http://localhost:9001/sse
mode: balanced  # safe, balanced, aggressive

# Rate limiting
rate_limit:
  qps: 10          # Queries per second
  burst: 20        # Burst allowance

# Safety policy
policy:
  dry_run: false                  # Set true for testing
  redact_evidence: true           # Redact sensitive data in reports
  max_payload_kb: 256            # Max request size
  max_total_requests: 1000       # Max requests per assessment

# Scope restrictions
allowed_prefixes:
  - "file:///app/data/"           # Only these paths allowed
  - "internal://"
blocked_paths:
  - "/etc/passwd"                 # Explicitly blocked
  - "/root/"
```

**Example:**
```bash
python mcpsf.py assess <source> --scope scope.yaml
```

---

### pyproject.toml

Project dependencies and metadata.

**Location:** `pyproject.toml`

**Structure:**
```toml
[project]
name = "mcp-security-framework"
version = "0.4.0"
description = "Security testing framework for MCP servers"
requires-python = ">=3.11"

dependencies = [
    "mcp>=0.3.0",
    "httpx>=0.25.0",
    "docker>=6.1.0",
    "fastapi>=0.104.0",
    "uvicorn>=0.24.0",
    "pydantic>=2.5.0",
    "pyyaml>=6.0",
    "flask>=3.0.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "mypy>=1.7.0"
]
```

---

## Complete Example

**End-to-end Python usage:**

```python
import asyncio
from pathlib import Path
from src.core.pipeline import AssessmentPipeline
from src.core.reporters.manager import ReportManager

async def main():
    # Initialize pipeline
    pipeline = AssessmentPipeline(interactive=False)

    # Run assessment
    print("Starting assessment...")
    result = await pipeline.run(
        source="@modelcontextprotocol/server-time",
        profile="balanced",
        detectors=None  # Run all
    )

    # Generate reports
    print("Generating reports...")
    report_mgr = ReportManager(reports_dir=Path("./reports"))
    bundle_path = report_mgr.generate_bundle(result)

    # Print summary
    print(f"\nAssessment complete!")
    print(f"  Vulnerabilities: {result.summary.present}")
    print(f"  Checks passed: {result.summary.absent}")
    print(f"  Reports: {bundle_path}")

    # Exit with appropriate code
    return 1 if result.summary.present > 0 else 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
```

**End-to-end CLI usage:**

```bash
#!/bin/bash

# Assess MCP server
python mcpsf.py assess @modelcontextprotocol/server-time \
  --mode balanced \
  --output ./reports \
  --verbose

# Check exit code
if [ $? -eq 0 ]; then
  echo "✅ No vulnerabilities found"
else
  echo "⚠️ Vulnerabilities detected"

  # Upload to GitHub
  gh api /repos/OWNER/REPO/code-scanning/sarifs \
    -f sarif=@reports/*/report.sarif \
    -f commit_sha=$(git rev-parse HEAD)

  # Send notification
  python scripts/notify_slack.py reports/*/report.json
fi
```

---

## Error Handling

**Common Errors:**

| Error | Cause | Solution |
|-------|-------|----------|
| `SourceDetectionError` | Cannot determine source type | Check source format |
| `MCPNotFoundError` | No MCP in source | Verify source contains MCP |
| `ProvisioningError` | Container failed to start | Check Docker, build images |
| `BridgeError` | Transport normalization failed | Check container logs |
| `AssessmentError` | Detector execution failed | Check target is responding |

**Example Error Handling:**

```python
from src.core.pipeline import AssessmentPipeline
from src.core.discovery import SourceDetectionError

async def safe_assess(source):
    try:
        pipeline = AssessmentPipeline()
        result = await pipeline.run(source=source)
        return result

    except SourceDetectionError as e:
        print(f"Invalid source: {e}")
        return None

    except Exception as e:
        print(f"Assessment failed: {e}")
        import traceback
        traceback.print_exc()
        return None
```

---

## Conclusion

The MCP Security Framework provides both CLI and Python APIs for flexible integration:
- **CLI** for manual testing and CI/CD
- **Python API** for programmatic control
- **Web API** for UI and remote access

Choose the interface that best fits your workflow.
