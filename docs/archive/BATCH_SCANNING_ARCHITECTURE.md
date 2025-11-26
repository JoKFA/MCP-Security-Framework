# MCPSF Batch Scanning Architecture Diagram

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            MCPSF CLI (mcpsf.py)                             │
│                                                                             │
│  Commands:                                                                  │
│  • mcpsf assess <target>        [Single-target mode - v0.3]                │
│  • mcpsf batch --targets <sel>  [Batch mode - v0.4 NEW]                    │
│  • mcpsf targets list/show      [Registry management - v0.4 NEW]           │
│  • mcpsf list-detectors                                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                    │                                 │
                    │ Single-target                   │ Batch mode
                    │ (unchanged)                     │ (new)
                    ▼                                 ▼
┌───────────────────────────────┐   ┌──────────────────────────────────────────┐
│       TestRunner              │   │          BatchRunner                     │
│  (src/core/runner.py)         │   │   (src/core/batch_runner.py - NEW)       │
│                               │   │                                          │
│  - Single target assessment   │   │  - Load target registry                  │
│  - Sequential detector exec   │   │  - Select targets (tag/id/group)         │
│  - Result aggregation         │   │  - Bounded parallelism (Semaphore)       │
│  - Report generation          │   │  - Per-target timeout                    │
│                               │   │  - Resume/skip logic                     │
│                               │   │  - Master report generation              │
└───────────────────────────────┘   └──────────────────────────────────────────┘
                    │                                 │
                    │                                 │ Spawns N × TestRunner
                    │                                 ▼
                    │               ┌─────────────────────────────────────────┐
                    │               │  Parallel Execution (asyncio.gather)    │
                    │               │                                         │
                    │               │  ┌──────────┐  ┌──────────┐  ┌────────┐│
                    │               │  │ Target 1 │  │ Target 2 │  │ Target │││
                    │               │  │ Runner   │  │ Runner   │  │ 3 ...  ││
                    │               │  └──────────┘  └──────────┘  └────────┘│
                    │               │       │             │             │     │
                    │               └───────┼─────────────┼─────────────┼─────┘
                    │                       │             │             │
                    └───────────────────────┴─────────────┴─────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SafeAdapter Wrapper                                │
│                      (src/core/safe_adapter.py)                             │
│                                                                             │
│  Enforces:                                                                  │
│  • Scope rules (allowed/blocked paths)                                     │
│  • Rate limiting (QPS, burst)                                              │
│  • Evidence redaction (secrets, payloads)                                  │
│  • Audit logging (NDJSON)                                                  │
│  • Request counting (max_total_requests)                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       McpClientAdapter                                      │
│                  (src/adapters/mcp_client_adapter.py)                       │
│                                                                             │
│  Transports:                                                                │
│  • SSE (HTTP/Server-Sent Events)                                           │
│  • stdio (Local process, stdin/stdout)                                     │
│                                                                             │
│  Operations:                                                                │
│  • connect() → initialize session                                          │
│  • list_tools/resources() → enumerate capabilities                         │
│  • call_tool() → execute tool                                              │
│  • read_resource() → fetch resource                                        │
│  • NDJSON capture → evidence logging                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                            │
                                            ▼
                               ┌────────────────────────┐
                               │    MCP Server Target   │
                               │  (Tools + Resources)   │
                               └────────────────────────┘
```

---

## Target Registry Architecture

```
targets/
├── registry.yaml                    # Master index
│   ├── targets[]                    # List of target refs
│   ├── groups{}                     # Tag-based grouping
│   └── defaults{}                   # Global defaults
│
├── profiles/                        # Per-target configs
│   ├── dv-mcp-ch1.yaml
│   │   ├── id, name, tags
│   │   ├── transport (sse/stdio)
│   │   ├── auth (api_key, oauth, ...)
│   │   ├── profiles (safe/balanced/aggressive)
│   │   ├── scope (allowed/blocked)
│   │   └── healthcheck
│   │
│   ├── filesystem-server.yaml
│   ├── slack-mcp-prod.yaml
│   └── ...
│
├── groups/                          # Target groups (optional)
│   ├── public.txt                   # id list
│   ├── internal.txt
│   └── critical.txt
│
└── .batch_state.json                # Resume state (git-ignored)
    └── { "target-id": "success|failed|timeout" }
```

**Flow:**
1. User runs `mcpsf batch --targets tag=public`
2. `BatchRunner` loads `registry.yaml`
3. Selects targets with `tag=public`
4. Loads each target's profile from `profiles/*.yaml`
5. Creates `TestRunner` for each target
6. Executes with bounded parallelism (Semaphore)
7. Aggregates results into batch report

---

## Batch Execution Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│ 1. Target Discovery                                                  │
│    BatchRunner.select_targets("tag=public")                          │
│    → [target1, target2, target3, ..., targetN]                       │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 2. Load Previous State (if --resume)                                 │
│    .batch_state.json → {"target1": "success", "target2": "failed"}   │
│    Filter out "success" targets                                      │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 3. Create Tasks (one per target)                                     │
│    tasks = [assess_target(t) for t in filtered_targets]              │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 4. Bounded Parallel Execution                                        │
│    semaphore = asyncio.Semaphore(concurrency)                        │
│    results = await asyncio.gather(*tasks)                            │
│                                                                       │
│    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│    │ Target 1    │  │ Target 2    │  │ Target 3    │  (max N at a  │
│    │ [RUNNING]   │  │ [RUNNING]   │  │ [RUNNING]   │   time)        │
│    └─────────────┘  └─────────────┘  └─────────────┘                │
│    ┌─────────────┐  ┌─────────────┐                                 │
│    │ Target 4    │  │ Target 5    │                                 │
│    │ [WAITING]   │  │ [WAITING]   │  (queued)                       │
│    └─────────────┘  └─────────────┘                                 │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 5. Per-Target Assessment                                             │
│    For each target:                                                  │
│      a) Load profile (profiles/<id>.yaml)                            │
│      b) Create TestRunner with profile.scope                         │
│      c) Run assessment (14 detectors)                                │
│      d) Save state → "success" / "failed"                            │
│      e) Generate report bundle (reports/<batch>/<id>/)               │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 6. Aggregate Results                                                 │
│    - Collect all AssessmentResult objects                            │
│    - Count total vulnerabilities by severity                         │
│    - Track failed targets                                            │
│    - Generate summary statistics                                     │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│ 7. Master Report Generation                                          │
│    reports/batch-<timestamp>/                                        │
│      ├── summary.json           (aggregated stats)                   │
│      ├── summary.html           (human-readable)                     │
│      ├── failed.json            (error details)                      │
│      ├── target1/               (per-target bundles)                 │
│      │   ├── report.json                                             │
│      │   ├── report.sarif                                            │
│      │   ├── report.txt                                              │
│      │   ├── audit.jsonl                                             │
│      │   └── metadata.json                                           │
│      ├── target2/                                                    │
│      └── ...                                                          │
│                                                                       │
│    reports/index.json           (master index of all batches)        │
│    reports/latest → batch-<timestamp>  (symlink)                     │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Detector Enhancement Architecture (Multi-Engine)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        BaseDetector                                 │
│                                                                     │
│  async def run(adapter, scope, profile) → DetectionResult           │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
         ┌────────────────────┴────────────────────┐
         │ Multi-Phase Execution (NEW in v0.4)     │
         └────────────────────┬────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Phase 1:        │  │ Phase 2:        │  │ Phase 3:        │
│ BASELINE        │  │ REALISTIC       │  │ AGGRESSIVE      │
│ (Passive)       │  │ (Active, Safe)  │  │ (Security)      │
├─────────────────┤  ├─────────────────┤  ├─────────────────┤
│ • Enumerate     │  │ • Call tools    │  │ • Injection     │
│   tools/        │  │   with benign   │  │   payloads      │
│   resources     │  │   inputs        │  │ • Edge cases    │
│ • Read schemas  │  │ • Observe       │  │ • Malicious     │
│ • Pattern match │  │   behavior      │  │   inputs        │
│                 │  │ • Time analysis │  │ • Privilege     │
│ Always runs     │  │ Runs in         │  │   escalation    │
│                 │  │ balanced+       │  │ Only in         │
│                 │  │                 │  │ aggressive mode │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                              ▼
         ┌─────────────────────────────────────────┐
         │  Multi-Engine Signal Correlation        │
         │                                         │
         │  Engine 1: Pattern Matching (regex)     │
         │  Engine 2: Behavioral Analysis          │
         │  Engine 3: Custom Rules (YARA-style)    │
         │  [Future] Engine 4: LLM-as-Judge        │
         └─────────────────────────────────────────┘
                              │
                              ▼
         ┌─────────────────────────────────────────┐
         │  Confidence Scoring                     │
         │                                         │
         │  If 1 engine detects → 60% confidence   │
         │  If 2 engines detect → 80% confidence   │
         │  If 3+ engines detect → 95% confidence  │
         └─────────────────────────────────────────┘
                              │
                              ▼
                      DetectionResult
                      (status, signals, PoCs)
```

---

## Reporting Architecture (Batch + Single)

```
                    ┌────────────────────────────────┐
                    │     ReportManager              │
                    │  (src/core/reporters/          │
                    │   manager.py)                  │
                    └────────────────────────────────┘
                                 │
                ┌────────────────┴────────────────┐
                │                                 │
                ▼                                 ▼
┌───────────────────────────┐    ┌───────────────────────────────┐
│  Single-Target Mode       │    │  Batch Mode (NEW v0.4)        │
│  (v0.3 - unchanged)       │    │                               │
├───────────────────────────┤    ├───────────────────────────────┤
│ generate_bundle(result)   │    │ generate_batch_report(        │
│  → reports/<ServerName>/  │    │     batch_results[]           │
│     ├── report.json       │    │   )                           │
│     ├── report.sarif      │    │  → reports/batch-<ts>/        │
│     ├── report.txt        │    │     ├── summary.json          │
│     ├── audit.jsonl       │    │     ├── summary.html          │
│     └── metadata.json     │    │     ├── failed.json           │
│                           │    │     ├── target1/              │
│                           │    │     │   └── [same as single]  │
│                           │    │     ├── target2/              │
│                           │    │     └── ...                   │
│                           │    │                               │
│                           │    │  + reports/index.json         │
│                           │    │  + reports/latest (symlink)   │
└───────────────────────────┘    └───────────────────────────────┘
```

**Key Points:**
- Single-target workflow **unchanged** - backward compatible
- Batch mode adds **master index** and **aggregation**
- Each target in a batch gets same bundle structure as single-target
- HTML summary shows **cross-target analysis** (top findings, severity distribution)

---

## Data Flow: Target Selection DSL

```
User Input:
    mcpsf batch --targets "tag=public,production"

         │
         ▼
┌─────────────────────────────────────────────────────────┐
│ TargetRegistry.select_targets("tag=public,production")  │
└─────────────────────────────────────────────────────────┘
         │
         ▼ Parse DSL
┌─────────────────────────────────────────────────────────┐
│ Selector AST:                                           │
│   type: "tag"                                           │
│   values: ["public", "production"]                      │
│   operator: "AND" (both tags required)                  │
└─────────────────────────────────────────────────────────┘
         │
         ▼ Load registry.yaml
┌─────────────────────────────────────────────────────────┐
│ Registry:                                               │
│   targets:                                              │
│     - id: "dv-mcp-ch1"                                  │
│       tags: ["public", "test"]                          │
│     - id: "slack-mcp"                                   │
│       tags: ["public", "production"]  ✓ MATCH           │
│     - id: "internal-db"                                 │
│       tags: ["internal", "production"]                  │
└─────────────────────────────────────────────────────────┘
         │
         ▼ Filter by selector
┌─────────────────────────────────────────────────────────┐
│ Selected Targets:                                       │
│   [                                                     │
│     TargetProfile(id="slack-mcp", ...)                  │
│   ]                                                     │
└─────────────────────────────────────────────────────────┘
         │
         ▼
     Pass to BatchRunner
```

**Supported Selectors:**
- `all` - All active targets
- `tag=X` - Single tag
- `tag=X,Y` - Multiple tags (AND logic)
- `id=X,Y,Z` - Specific IDs
- `group=X` - Predefined group from `groups/*.txt`
- `status=active` - Filter by status

---

## State Management (Resume Logic)

```
Initial Run:
    mcpsf batch --targets all

         │
         ▼
┌─────────────────────────────────────────────────────────┐
│ BatchRunner creates: targets/.batch_state.json          │
│ {                                                       │
│   "batch_id": "batch-2025-11-19-10-30",                 │
│   "started_at": "...",                                  │
│   "targets": {                                          │
│     "target1": "success",                               │
│     "target2": "failed",    ← Connection timeout        │
│     "target3": "success",                               │
│     "target4": null         ← Interrupted before start  │
│   }                                                     │
│ }                                                       │
└─────────────────────────────────────────────────────────┘

Resume Run:
    mcpsf batch --targets all --resume

         │
         ▼
┌─────────────────────────────────────────────────────────┐
│ BatchRunner.load_state()                                │
│   → Skip "success" targets                              │
│   → Retry "failed" and null targets                     │
│                                                         │
│ Filtered Targets: [target2, target4]                    │
└─────────────────────────────────────────────────────────┘
         │
         ▼
    Run only target2 and target4
```

---

## Authentication Flow (Per-Target)

```
Target Profile (profiles/slack-mcp.yaml):
  auth:
    type: "api_key"
    api_key: "${SLACK_API_KEY}"    ← Env var reference
    header_name: "X-API-Key"

         │
         ▼
┌─────────────────────────────────────────────────────────┐
│ ScopeConfig.from_yaml() expands environment variables:  │
│   os.environ.get("SLACK_API_KEY")                       │
│   → "xoxb-1234567890-abcdefghijk..."                    │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│ SafeAdapter passes auth to McpClientAdapter:            │
│   headers = {                                           │
│     "X-API-Key": "xoxb-1234567890-abcdefghijk..."       │
│   }                                                     │
└─────────────────────────────────────────────────────────┘
         │
         ▼
    MCP Server authenticates request
```

**Security Features:**
- Credentials NEVER hardcoded in YAML
- Environment variable expansion (`${VAR}`)
- Redacted in audit logs
- Per-target isolation (Target A's key ≠ Target B's key)

---

## File Structure (v0.4 Complete)

```
mcp-security-framework/
├── mcpsf.py                         # CLI entry point
│                                    #   + batch command (NEW)
│
├── src/
│   ├── adapters/
│   │   └── mcp_client_adapter.py    # Transport layer
│   │
│   ├── core/
│   │   ├── runner.py                # Single-target orchestration
│   │   ├── batch_runner.py          # Batch orchestration (NEW)
│   │   ├── target_registry.py       # Target management (NEW)
│   │   ├── rule_engine.py           # Custom YARA-style rules (NEW)
│   │   ├── safe_adapter.py          # Safety wrapper
│   │   ├── policy.py                # Scope/rate/redaction
│   │   ├── models.py                # Pydantic models
│   │   │                            #   + TargetProfile (NEW)
│   │   │                            #   + BatchResult (NEW)
│   │   └── reporters/
│   │       ├── manager.py           # Report orchestration
│   │       │                        #   + batch methods (NEW)
│   │       ├── batch_reporter.py    # Batch summary (NEW)
│   │       ├── html_reporter.py     # HTML templates (NEW)
│   │       ├── json_reporter.py
│   │       ├── sarif_reporter.py
│   │       └── cli_reporter.py
│   │
│   └── modules/
│       ├── base.py                  # BaseDetector
│       │                            #   + multi-phase support (NEW)
│       ├── registry.py              # Detector discovery
│       └── detectors/               # 14 detectors
│           └── ...                  #   + behavior phases (NEW)
│
├── targets/                         # Target registry (NEW)
│   ├── registry.yaml                # Master index
│   ├── profiles/                    # Per-target configs
│   │   ├── dv-mcp-ch1.yaml
│   │   ├── filesystem-server.yaml
│   │   └── ...
│   ├── groups/                      # Target groups
│   │   ├── public.txt
│   │   └── critical.txt
│   └── .batch_state.json            # Resume state (git-ignored)
│
├── rules/                           # Custom detection rules (NEW)
│   └── custom-patterns.yaml
│
├── reports/                         # Generated reports
│   ├── index.json                   # Master index (NEW)
│   ├── latest -> batch-X/           # Symlink (NEW)
│   ├── batch-2025-11-19-10-30/      # Batch reports (NEW)
│   │   ├── summary.json
│   │   ├── summary.html
│   │   ├── target1/                 # Per-target bundles
│   │   │   ├── report.json
│   │   │   ├── report.sarif
│   │   │   ├── report.txt
│   │   │   ├── audit.jsonl
│   │   │   └── metadata.json
│   │   └── ...
│   └── ServerName/                  # Single-target (v0.3 format)
│       └── ...
│
├── captures/                        # Audit logs
│   └── audit_<id>.jsonl
│
├── tests/
│   ├── unit/
│   │   ├── test_target_registry.py  # NEW
│   │   ├── test_batch_runner.py     # NEW
│   │   └── ...
│   └── integration/
│       └── test_batch_workflow.py   # NEW
│
└── docs/
    ├── BATCH_SCANNING_DESIGN.md     # This document
    └── BATCH_SCANNING_ARCHITECTURE.md  # Visual diagrams
```

---

## Performance Model

```
Scenario: 60 targets, concurrency=3, avg 2 min/target

Timeline:
  00:00 ─┬─ [Target 1] [Target 2] [Target 3]  (start first 3)
         │     ▼            ▼           ▼
  02:00 ─┼─ [DONE]      [DONE]      [DONE]
         │
  02:00 ─┼─ [Target 4] [Target 5] [Target 6]  (next 3)
         │     ▼            ▼           ▼
  04:00 ─┼─ [DONE]      [DONE]      [DONE]
         │
         ... (repeat 20 times)
         │
  40:00 ─┴─ [DONE] All 60 targets complete

Total Time: ~40 minutes (60 / 3 × 2)

Optimizations:
- Faster targets free up slots earlier (actual: ~30-35 min)
- Failed targets exit quickly (timeout + retry)
- Healthchecks catch dead servers early
```

**Bottlenecks:**
1. **Network I/O** - Most time spent waiting for MCP responses
2. **Rate limiting** - QPS constraints slow down detector execution
3. **Slow servers** - One slow target can block a slot

**Mitigations:**
1. Increase concurrency (5-10 targets)
2. Use per-target timeouts (fail fast)
3. Prioritize fast/critical targets (priority field)

---

## Summary

This architecture enables MCPSF to **scale from 1 to 100+ targets** while maintaining:

✅ **Backward compatibility** - Single-target workflow unchanged
✅ **Flexibility** - Per-target profiles, tags, auth, scope
✅ **Safety** - Same guardrails, rate limits, redaction
✅ **Performance** - Bounded parallelism, resume logic
✅ **Observability** - Master index, batch summaries, HTML reports
✅ **Extensibility** - Multi-engine detection, custom rules

**Next:** Implement Phase 6A (Target Registry) 🚀
