# MCPSF Batch Scanning Architecture (v0.4)

**Design Proposal for Scaling to 60-100+ MCP Servers**

---

## Executive Summary

This document proposes a **production-grade batch scanning architecture** to scale MCPSF from single-target assessments to orchestrating 60-100+ MCP servers efficiently. The design borrows proven patterns from `mcp-server-fuzzer` and `mcp-scanner` while maintaining MCPSF's unique signal-based detection framework.

**Key Improvements:**
1. **Target Registry System** - YAML-based server profiles with tags, auth, launch configs
2. **Batch Orchestration** - Parallel/sequential execution with bounded concurrency
3. **Per-Target Profiles** - Safe/balanced/aggressive modes with detector filtering
4. **Centralized Reporting** - Master index + per-target bundles
5. **Detector Enhancements** - Improved heuristics based on scanner patterns
6. **Resume/Skip Logic** - Incremental scanning with failure tracking

---

## 1. Target Registry System

### 1.1 Architecture

```
targets/
├── registry.yaml           # Master registry (target index)
├── profiles/              # Individual target configs
│   ├── dv-mcp-ch1.yaml
│   ├── filesystem-server.yaml
│   ├── slack-mcp.yaml
│   └── ...
└── groups/                # Target groups for bulk ops
    ├── public.txt         # List of target IDs
    ├── internal.txt
    └── critical.txt
```

### 1.2 Target Profile Schema

**File:** `targets/profiles/<name>.yaml`

```yaml
# Target Metadata
id: "filesystem-server-v1"           # Unique identifier
name: "MCP Filesystem Server"        # Human-readable name
tags: ["public", "stdio", "filesystem", "production"]
priority: "high"                      # high/medium/low (for scheduling)
status: "active"                      # active/disabled/maintenance

# Transport Configuration
transport:
  type: "stdio"                       # sse/stdio
  # For stdio:
  command: "npx"
  args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/test"]
  env:
    NODE_ENV: "production"
  working_dir: null
  # For SSE:
  # url: "http://localhost:9001/sse"
  # timeout_s: 30

# Healthcheck
healthcheck:
  enabled: true
  # For stdio: verify process started
  type: "process"                     # process/port/tool_count/custom
  # For SSE: verify endpoint responds
  # type: "endpoint"
  # url: "http://localhost:9001/health"
  # For tools: verify tool count
  # type: "tool_count"
  # min_tools: 3
  timeout_s: 10

# Authentication (optional)
auth:
  type: "api_key"                     # none/api_key/oauth/mtls
  api_key: "${FILESYSTEM_API_KEY}"    # Env var reference
  header_name: "X-API-Key"

# Assessment Profiles
# Override global settings per target
profiles:
  # Safe mode: minimal probing, passive only
  safe:
    mode: "safe"
    rate_limit:
      qps: 1
      burst: 3
    policy:
      max_total_requests: 100
    detectors:
      exclude: ["MCP-2024-CEX-001", "MCP-2024-CI-001"]  # Skip code exec detectors

  # Balanced mode: default
  balanced:
    mode: "balanced"
    rate_limit:
      qps: 2
      burst: 5
    policy:
      max_total_requests: 500

  # Aggressive mode: full active testing
  aggressive:
    mode: "aggressive"
    rate_limit:
      qps: 5
      burst: 10
    policy:
      max_total_requests: 2000
    detectors:
      include: []  # Run ALL detectors

# Scope Overrides (optional)
scope:
  allowed_prefixes:
    - "/resources"
    - "/tools"
    - "file://"
  blocked_paths:
    - "/etc/passwd"
    - "/root"

# Metadata
metadata:
  owner: "Security Team"
  project: "Internal Infrastructure"
  sla: "24h response time"
  last_assessed: "2025-11-15T10:00:00Z"
  notes: "Production filesystem server, handle with care"
```

### 1.3 Registry Index

**File:** `targets/registry.yaml`

```yaml
# Master registry - index of all targets
version: "1.0"
targets:
  - id: "dv-mcp-ch1"
    profile: "profiles/dv-mcp-ch1.yaml"
    enabled: true

  - id: "filesystem-server-v1"
    profile: "profiles/filesystem-server.yaml"
    enabled: true

  - id: "slack-mcp-prod"
    profile: "profiles/slack-mcp.yaml"
    enabled: false  # Disabled for maintenance

groups:
  public:
    - "dv-mcp-ch1"
    - "filesystem-server-v1"

  internal:
    - "slack-mcp-prod"

  critical:
    - "slack-mcp-prod"

# Default profile for targets without explicit config
defaults:
  profile: "balanced"
  timeout_s: 300
  max_retries: 2
```

---

## 2. Batch Orchestration Engine

### 2.1 BatchRunner Class

**Location:** `src/core/batch_runner.py`

```python
class BatchRunner:
    """
    Orchestrates batch assessments across multiple targets.

    Features:
    - Target discovery from registry
    - Parallel/sequential execution
    - Per-target timeout enforcement
    - Result aggregation
    - Resume/skip logic
    """

    def __init__(
        self,
        registry_path: str = "targets/registry.yaml",
        concurrency: int = 3,
        fail_fast: bool = False,
    ):
        self.registry = TargetRegistry.load(registry_path)
        self.concurrency = concurrency  # Max concurrent targets
        self.fail_fast = fail_fast
        self.state_file = Path("targets/.batch_state.json")

    async def run_batch(
        self,
        target_selector: str,  # "all", "tag=public", "id=foo,bar"
        profile: str = "balanced",
        resume: bool = False,
    ) -> BatchResult:
        """Run batch assessment"""

        # 1. Discover targets
        targets = self.registry.select_targets(target_selector)

        # 2. Load previous state (if resume=True)
        if resume:
            state = self._load_state()
            targets = [t for t in targets if state.get(t.id) != "success"]

        # 3. Execute with bounded parallelism
        results = []
        semaphore = asyncio.Semaphore(self.concurrency)

        async def assess_target(target):
            async with semaphore:
                try:
                    result = await self._assess_single_target(target, profile)
                    self._save_state(target.id, "success")
                    return result
                except Exception as e:
                    self._save_state(target.id, "failed")
                    if self.fail_fast:
                        raise
                    return TargetFailure(target.id, str(e))

        # Run concurrently
        tasks = [assess_target(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 4. Generate master report
        return self._build_batch_result(targets, results)
```

### 2.2 Target Selection DSL

```bash
# Select all active targets
mcpsf batch --targets all

# Select by tag
mcpsf batch --targets tag=public
mcpsf batch --targets tag=stdio,production

# Select by ID
mcpsf batch --targets id=dv-mcp-ch1,filesystem-server-v1

# Select by group
mcpsf batch --targets group=critical

# Combine with profile
mcpsf batch --targets tag=public --profile safe

# Resume failed targets
mcpsf batch --targets all --resume
```

---

## 3. Enhanced CLI Interface

### 3.1 New Commands

```bash
# Batch assessment
mcpsf batch --targets <selector> [--profile <safe|balanced|aggressive>] [--concurrency N] [--resume]

# Target management
mcpsf targets list [--tag <tag>] [--status <active|disabled>]
mcpsf targets show <target-id>
mcpsf targets validate <profile.yaml>
mcpsf targets add <profile.yaml>
mcpsf targets disable <target-id>
mcpsf targets enable <target-id>

# Registry operations
mcpsf registry init
mcpsf registry validate
mcpsf registry export --format json

# Existing commands (unchanged)
mcpsf assess <target>
mcpsf list-detectors
mcpsf version
```

### 3.2 Updated `mcpsf.py` Structure

```python
# mcpsf.py
subparsers = parser.add_subparsers(dest="command")

# SINGLE TARGET ASSESSMENT (existing)
assess_parser = subparsers.add_parser("assess")
assess_parser.add_argument("target")
# ... existing args ...

# BATCH ASSESSMENT (new)
batch_parser = subparsers.add_parser("batch")
batch_parser.add_argument("--targets", required=True, help="Target selector")
batch_parser.add_argument("--profile", default="balanced", choices=["safe", "balanced", "aggressive"])
batch_parser.add_argument("--concurrency", type=int, default=3, help="Max concurrent targets")
batch_parser.add_argument("--resume", action="store_true", help="Resume from previous run")
batch_parser.add_argument("--fail-fast", action="store_true", help="Stop on first failure")
batch_parser.add_argument("--output", default="./reports", help="Output directory")

# TARGET MANAGEMENT (new)
targets_parser = subparsers.add_parser("targets")
targets_subparsers = targets_parser.add_subparsers(dest="targets_command")

targets_subparsers.add_parser("list")
targets_subparsers.add_parser("validate").add_argument("profile")
# ... etc ...
```

---

## 4. Reporting Architecture

### 4.1 Directory Structure

```
reports/
├── index.json                    # Master index (all batches)
├── batch-2025-11-19-10-30/      # Batch run folder
│   ├── summary.json             # Batch summary
│   ├── summary.html             # Human-readable summary
│   ├── failed.json              # Failed targets
│   ├── dv-mcp-ch1/              # Per-target bundle
│   │   ├── report.json
│   │   ├── report.sarif
│   │   ├── report.txt
│   │   ├── audit.jsonl
│   │   └── metadata.json
│   ├── filesystem-server-v1/
│   │   └── ...
│   └── slack-mcp-prod/
│       └── ...
└── latest -> batch-2025-11-19-10-30  # Symlink to latest
```

### 4.2 Batch Summary Report

**File:** `reports/batch-<timestamp>/summary.json`

```json
{
  "batch_id": "batch-2025-11-19-10-30",
  "started_at": "2025-11-19T10:30:00Z",
  "completed_at": "2025-11-19T10:45:00Z",
  "duration_s": 900,
  "framework_version": "0.4.0",

  "targets": {
    "total": 15,
    "succeeded": 13,
    "failed": 2,
    "skipped": 0
  },

  "profile": "balanced",
  "concurrency": 3,

  "summary": {
    "total_vulnerabilities": 27,
    "by_severity": {
      "CRITICAL": 2,
      "HIGH": 8,
      "MEDIUM": 12,
      "LOW": 5
    },
    "top_findings": [
      {"detector_id": "MCP-2024-PI-001", "count": 5},
      {"detector_id": "MCP-2024-CE-001", "count": 3}
    ]
  },

  "targets_summary": [
    {
      "id": "dv-mcp-ch1",
      "status": "success",
      "vulnerabilities": 2,
      "duration_s": 120,
      "report_dir": "dv-mcp-ch1/"
    },
    {
      "id": "slack-mcp-prod",
      "status": "failed",
      "error": "Connection timeout after 30s"
    }
  ],

  "failed_targets": [
    {
      "id": "slack-mcp-prod",
      "error": "Connection timeout after 30s",
      "retries": 2
    }
  ]
}
```

### 4.3 Master Index

**File:** `reports/index.json`

```json
{
  "version": "1.0",
  "batches": [
    {
      "batch_id": "batch-2025-11-19-10-30",
      "timestamp": "2025-11-19T10:30:00Z",
      "targets_total": 15,
      "vulnerabilities_total": 27,
      "summary_file": "batch-2025-11-19-10-30/summary.json"
    }
  ],
  "latest": "batch-2025-11-19-10-30"
}
```

---

## 5. Detector Improvements (from Scanner Patterns)

### 5.1 Multi-Engine Detection (Inspired by mcp-scanner)

Current MCPSF uses pattern-based heuristics. We can add **confidence boosting** via multi-signal correlation:

```python
# In BaseDetector
class DetectionEngine(Enum):
    PATTERN = "pattern"      # Existing regex/keyword matching
    BEHAVIOR = "behavior"    # Runtime behavior observation
    SEMANTIC = "semantic"    # LLM-based contextual analysis (future)

class Signal:
    # Add engine field
    engine: DetectionEngine = DetectionEngine.PATTERN

# In detectors, emit signals from multiple engines
async def run(self, adapter, scope, profile):
    signals = []

    # Pattern-based (fast)
    pattern_signals = await self._check_patterns(adapter)
    signals.extend(pattern_signals)

    # Behavior-based (slower, more accurate)
    if scope["mode"] in ["balanced", "aggressive"]:
        behavior_signals = await self._check_behavior(adapter)
        signals.extend(behavior_signals)

    # Boost confidence if multiple engines agree
    confidence = self._calculate_confidence(signals)
```

### 5.2 YARA-Style Pattern Matching (from mcp-scanner)

Add support for custom rule files:

```yaml
# rules/custom-patterns.yaml
rules:
  - id: "CUSTOM-001"
    name: "Exposed Internal Tokens"
    pattern: "(internal_token|auth_secret)\\s*:\\s*['\"]([a-zA-Z0-9_-]{20,})['\"]"
    severity: "HIGH"
    apply_to: ["resources", "tool_responses"]
```

Load in detectors:

```python
from src.core.rule_engine import RuleEngine

class CustomPatternDetector(Detector):
    def __init__(self):
        super().__init__(...)
        self.rules = RuleEngine.load("rules/custom-patterns.yaml")

    async def run(self, adapter, scope, profile):
        resources = await adapter.list_resources()
        for resource in resources:
            content = await adapter.read_resource(resource["uri"])
            matches = self.rules.match(content)
            if matches:
                # Emit signals...
```

### 5.3 Behavioral Profiling (from mcp-server-fuzzer)

Add **multi-phase testing** like the fuzzer:

```python
# Phase 1: Baseline (passive enumeration)
async def _baseline_phase(self, adapter):
    """Passive profiling - list tools/resources only"""
    tools = await adapter.list_tools()
    resources = await adapter.list_resources()
    return {"tools": tools, "resources": resources}

# Phase 2: Realistic (benign inputs)
async def _realistic_phase(self, adapter, baseline):
    """Test with realistic, non-malicious inputs"""
    results = []
    for tool in baseline["tools"]:
        result = await adapter.call_tool(tool["name"], self._gen_realistic_args(tool))
        results.append(result)
    return results

# Phase 3: Aggressive (security payloads)
async def _aggressive_phase(self, adapter, baseline):
    """Test with security-focused payloads"""
    if self.scope["mode"] != "aggressive":
        return []  # Skip in safe/balanced modes

    results = []
    for tool in baseline["tools"]:
        result = await adapter.call_tool(tool["name"], self._gen_payload(tool))
        results.append(result)
    return results
```

### 5.4 SafetyBlocker Integration (from mcp-server-fuzzer)

Add **simulation mode** to detectors:

```python
class SafeAdapter:
    def __init__(self, ..., simulation_mode=False):
        self.simulation_mode = simulation_mode

    async def call_tool(self, name, args):
        if self.simulation_mode:
            # Don't actually call tool, return mock
            return {"simulated": True, "would_call": name, "args": args}

        # Normal execution
        return await self.base_adapter.call_tool(name, args)
```

Use in detectors:

```python
# In code_execution_detector.py
async def run(self, adapter, scope, profile):
    if scope["policy"]["dry_run"]:
        # Use simulation mode
        adapter.simulation_mode = True

    # Test dangerous tools safely
    result = await adapter.call_tool("execute_code", {"code": "1+1"})
    # ...
```

---

## 6. Implementation Phases

### Phase 6A: Target Registry (Week 1-2) 🎯

**Deliverables:**
- [ ] `src/core/target_registry.py` - Target loading/validation
- [ ] `targets/registry.yaml` - Master registry schema
- [ ] `targets/profiles/*.yaml` - Sample target profiles (5-10 examples)
- [ ] CLI: `mcpsf targets list/show/validate`
- [ ] Unit tests for registry operations

**Files to Create:**
- `src/core/target_registry.py`
- `src/core/models.py` (add TargetProfile, RegistryConfig models)
- `targets/registry.yaml`
- `targets/profiles/dv-mcp-ch1.yaml` (example)
- `tests/unit/test_target_registry.py`

---

### Phase 6B: Batch Orchestration (Week 3-4) 🎯

**Deliverables:**
- [ ] `src/core/batch_runner.py` - Batch orchestration engine
- [ ] CLI: `mcpsf batch --targets <selector>`
- [ ] Target selection DSL (all, tag=X, id=X,Y)
- [ ] Bounded parallelism (max_concurrent_targets)
- [ ] Per-target timeout enforcement
- [ ] Resume/skip logic (`.batch_state.json`)
- [ ] Integration tests with 3+ targets

**Files to Create/Modify:**
- `src/core/batch_runner.py`
- `src/core/models.py` (add BatchResult, TargetFailure)
- `mcpsf.py` (add batch command)
- `tests/integration/test_batch_runner.py`

---

### Phase 6C: Centralized Reporting (Week 5) 🎯

**Deliverables:**
- [ ] Batch summary report (JSON + HTML)
- [ ] Master index (`reports/index.json`)
- [ ] Failed targets tracking
- [ ] Top findings aggregation
- [ ] Symlink to latest batch
- [ ] CLI: `mcpsf reports summary --batch <id>`

**Files to Create/Modify:**
- `src/core/reporters/batch_reporter.py`
- `src/core/reporters/html_reporter.py` (batch summary template)
- `src/core/reporters/manager.py` (add batch methods)
- `tests/unit/test_batch_reporter.py`

---

### Phase 6D: Detector Enhancements (Week 6-7) 🎯

**Deliverables:**
- [ ] Multi-engine detection (pattern + behavior)
- [ ] Custom rule engine (YARA-style)
- [ ] Multi-phase testing (baseline → realistic → aggressive)
- [ ] Simulation mode for dry-run
- [ ] Confidence boosting algorithm
- [ ] 3-5 enhanced detectors with new patterns

**Files to Create/Modify:**
- `src/core/rule_engine.py`
- `src/core/detection_engine.py`
- `src/modules/base.py` (add multi-phase support)
- `rules/custom-patterns.yaml`
- Update 3-5 detectors with behavior phase
- `tests/unit/test_rule_engine.py`

---

### Phase 6E: Production Hardening (Week 8) 🎯

**Deliverables:**
- [ ] Error recovery and retry logic
- [ ] Resource cleanup on failure
- [ ] Progress indicators for batch runs
- [ ] Email/webhook notifications
- [ ] CI/CD integration examples
- [ ] Performance benchmarks (60+ targets)
- [ ] Complete documentation update

**Files to Create/Modify:**
- `src/core/notifications.py`
- `src/core/batch_runner.py` (add retry/recovery)
- `.github/workflows/batch-scan.yml` (CI/CD example)
- `docs/BATCH_SCANNING_GUIDE.md`
- Performance tests

---

## 7. Example Workflows

### 7.1 Scan All Public MCP Servers

```bash
# Create target profiles for 60 servers
mcpsf targets add targets/profiles/server-{1..60}.yaml

# Run batch with safe profile
mcpsf batch --targets tag=public --profile safe --concurrency 5

# Check results
mcpsf reports summary --batch latest

# Re-run failed targets
mcpsf batch --targets tag=public --resume
```

### 7.2 CI/CD Integration

```yaml
# .github/workflows/batch-scan.yml
name: MCP Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install MCPSF
        run: pip install -e .

      - name: Run Batch Scan
        env:
          MCP_API_KEYS: ${{ secrets.MCP_API_KEYS }}
        run: |
          mcpsf batch --targets tag=production --profile balanced --concurrency 3

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: reports/latest/

      - name: Check for Critical Findings
        run: |
          python scripts/check_critical.py reports/latest/summary.json
```

### 7.3 Progressive Scanning Strategy

```bash
# Stage 1: Quick scan (safe mode, public servers)
mcpsf batch --targets tag=public --profile safe --concurrency 10

# Stage 2: Medium scan (balanced mode, internal servers)
mcpsf batch --targets tag=internal --profile balanced --concurrency 5

# Stage 3: Deep scan (aggressive mode, critical servers)
mcpsf batch --targets tag=critical --profile aggressive --concurrency 1

# Stage 4: Re-scan high-risk findings
mcpsf batch --targets id=$(jq -r '.high_risk_targets[]' reports/latest/summary.json) --profile aggressive
```

---

## 8. Migration Path from v0.3 to v0.4

### 8.1 Backward Compatibility

✅ **Existing workflows continue to work:**

```bash
# v0.3 single-target assessment (unchanged)
mcpsf assess http://localhost:9001/sse
mcpsf assess http://localhost:9001/sse --scope scope.yaml
mcpsf list-detectors
```

✅ **New batch features are opt-in:**

```bash
# v0.4 batch scanning (new)
mcpsf batch --targets all
```

### 8.2 Migration Steps

1. **Initialize target registry:**
   ```bash
   mcpsf registry init
   ```

2. **Convert existing scope files to target profiles:**
   ```bash
   mcpsf targets import scope.yaml --id my-target
   ```

3. **Test with single target:**
   ```bash
   mcpsf batch --targets id=my-target --profile balanced
   ```

4. **Scale up gradually:**
   ```bash
   mcpsf batch --targets tag=test --concurrency 1
   mcpsf batch --targets tag=test --concurrency 3
   mcpsf batch --targets all --concurrency 5
   ```

---

## 9. Performance Targets

| Metric | Target | Justification |
|--------|--------|---------------|
| **Batch size** | 60-100 targets | Per requirements |
| **Concurrency** | 3-5 concurrent targets | Balance speed vs resource usage |
| **Per-target time** | 1-3 minutes | 14 detectors @ 5-10s each |
| **Total batch time** | 20-30 minutes | 60 targets / 3 concurrent × 2 min/target |
| **Memory usage** | <2GB total | 3 concurrent × ~500MB each |
| **CPU usage** | <50% on 4-core | Mostly I/O-bound (network waits) |
| **Failure rate** | <5% | With retries and healthchecks |

---

## 10. Key Design Decisions

### 10.1 Why YAML for Target Profiles?

✅ **Human-readable** - Easy to edit and review
✅ **Environment variable support** - `${VAR}` syntax
✅ **Standardized** - Same as scope.yaml
✅ **Version control friendly** - Diff-able, mergeable
✅ **Ecosystem support** - YAML is widely used in security tools

### 10.2 Why Bounded Parallelism vs Full Parallel?

✅ **Resource control** - Prevent memory/network exhaustion
✅ **Rate limit friendly** - Respect server QPS limits
✅ **Debugging** - Easier to track issues with fewer concurrent streams
✅ **Politeness** - Don't overwhelm target infrastructure

**Decision:** Default `concurrency=3`, configurable up to 10.

### 10.3 Why Per-Target Profiles vs Global Config?

✅ **Flexibility** - Different servers need different settings
✅ **Safety** - Production servers get "safe" mode by default
✅ **Auth isolation** - Each server can have unique credentials
✅ **Gradual rollout** - Enable/disable targets individually

**Decision:** Global defaults in `registry.yaml`, per-target overrides in `profiles/*.yaml`.

### 10.4 Why Resume/Skip Logic?

✅ **Long-running batches** - 60 targets × 2 min = 2 hours (at concurrency=1)
✅ **Failure recovery** - Don't re-run successful targets
✅ **Incremental scanning** - Add new targets without re-scanning all
✅ **Cost efficiency** - Avoid redundant work

**Decision:** State file tracks `{target_id: status}`, resume flag skips "success" entries.

---

## 11. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **Network failures** | Batch incomplete | Retry logic, resume flag, healthchecks |
| **Memory leaks** | OOM crash | Resource limits, cleanup on failure, bounded concurrency |
| **Slow targets** | Batch timeout | Per-target timeout, fail-fast mode |
| **Auth failures** | False negatives | Pre-flight auth check, clear error messages |
| **Registry corruption** | Cannot load targets | YAML validation, schema checks, backups |
| **Report storage growth** | Disk full | Retention policy, compression, cleanup scripts |

---

## 12. Success Metrics

**Phase 6A (Target Registry):**
- ✅ 10+ target profiles created
- ✅ Registry validates all profiles
- ✅ CLI can list/show/validate targets

**Phase 6B (Batch Orchestration):**
- ✅ Successfully scan 10 targets in parallel
- ✅ Resume works after interruption
- ✅ Fail-fast stops on first error

**Phase 6C (Centralized Reporting):**
- ✅ Batch summary shows aggregated stats
- ✅ Master index tracks all batches
- ✅ HTML report renders correctly

**Phase 6D (Detector Enhancements):**
- ✅ 3+ detectors use multi-phase testing
- ✅ Custom rule engine loads YAML rules
- ✅ Confidence scores improve by 10%+

**Phase 6E (Production Hardening):**
- ✅ Scan 60+ targets in <30 minutes
- ✅ <5% failure rate on production servers
- ✅ CI/CD integration works end-to-end

---

## 13. References

**External Projects:**
- [mcp-server-fuzzer](https://github.com/Agent-Hellboy/mcp-server-fuzzer) - Fuzzing patterns, safety blockers, multi-phase testing
- [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) - Multi-engine detection, config discovery, output formats

**Internal Docs:**
- [CLAUDE.md](../CLAUDE.md) - Current architecture (v0.3)
- [samples/scope.yaml](../samples/scope.yaml) - Scope configuration format
- [WEEKLY_PROJECT_UPDATE_2025-10-22.md](../Weekly report/WEEKLY_PROJECT_UPDATE_2025-10-22.md) - Latest progress

---

## 14. Next Steps

**Immediate Actions (This Week):**
1. ✅ Review this design doc with team
2. ✅ Approve target profile schema
3. ✅ Approve registry structure
4. ✅ Create GitHub issue for Phase 6A
5. ✅ Set up `targets/` directory structure

**Week 1-2 Deliverables:**
- Implement `TargetRegistry` class
- Create 5-10 example target profiles
- Add `mcpsf targets` CLI commands
- Write unit tests

**Decision Points:**
- [ ] **Concurrency default:** 3 or 5?
- [ ] **HTML reporting:** Use Jinja2 or static template?
- [ ] **LLM-based detection:** Add in 6D or defer to v0.5?
- [ ] **Notification method:** Email, Slack, webhook, or all?

---

**Document Status:** 📝 DRAFT - Awaiting team review
**Author:** Claude (with teammate input)
**Date:** 2025-11-19
**Version:** 1.0
