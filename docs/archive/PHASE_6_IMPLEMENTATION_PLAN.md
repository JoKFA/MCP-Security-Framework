# Phase 6: Batch Scanning Implementation Plan

**Goal:** Scale MCPSF from single-target assessments to 60-100+ MCP servers with unified target management.

---

## Design Documents

1. **[BATCH_SCANNING_DESIGN.md](./BATCH_SCANNING_DESIGN.md)** - Complete architecture design
2. **[BATCH_SCANNING_ARCHITECTURE.md](./BATCH_SCANNING_ARCHITECTURE.md)** - Visual diagrams and data flows
3. **[UNIFIED_TARGET_SYSTEM.md](./UNIFIED_TARGET_SYSTEM.md)** - Single & batch UX (THIS IS THE KEY DOC!)

**Read in order:** 3 → 1 → 2

---

## Core Design Principles

### 1. Unified Target System
```
targets/profiles/*.yaml = Source of truth for ALL MCP configurations
     ↓
  Used by both:
     • mcpsf assess --target <id>    (single)
     • mcpsf batch --targets <sel>   (multiple)
```

### 2. Progressive Enhancement
```
Day 1: mcpsf assess --transport sse --url http://...  (direct, no config)
    ↓
Day 2: mcpsf assess --transport ... --save-target my-mcp  (save for reuse)
    ↓
Day 3: mcpsf assess --target my-mcp  (use saved config)
    ↓
Week 2: mcpsf batch --targets all  (scale to 100+ targets)
```

### 3. Backward Compatibility
- ✅ Existing `mcpsf assess <url>` workflows unchanged
- ✅ `scope.yaml` files can be imported via `registry import`
- ✅ All v0.3 detectors work without modification

---

## Implementation Phases

### 📋 Phase 6A: Target Registry Foundation (Week 1-2)

**Goal:** Core infrastructure for target management

**Deliverables:**
- [ ] `src/core/models.py` - Add `TargetProfile`, `TargetRef`, `TransportConfig`, `HealthcheckConfig` models
- [ ] `src/core/target_registry.py` - Implement `TargetRegistry` class
- [ ] `targets/` directory structure created (✅ DONE)
- [ ] `targets/registry.yaml` schema finalized (✅ DONE)
- [ ] `targets/profiles/TEMPLATE.yaml` created (✅ DONE)
- [ ] Unit tests for registry operations

**CLI Commands:**
```bash
mcpsf targets init [--interactive]
mcpsf targets list [--tag <tag>]
mcpsf targets show <target-id>
mcpsf targets validate <profile.yaml>
mcpsf registry validate
```

**Files to Create:**
- `src/core/target_registry.py` (NEW)
- `src/core/models.py` (UPDATE - add TargetProfile models)
- `tests/unit/test_target_registry.py` (NEW)
- `tests/unit/test_target_profile.py` (NEW)

**Success Criteria:**
- ✅ Load `targets/registry.yaml` successfully
- ✅ Parse 5+ target profiles without errors
- ✅ `targets list` shows all registered targets
- ✅ `targets validate` catches schema errors

---

### 📋 Phase 6B: Single-Target Integration (Week 3)

**Goal:** Bridge registry system with existing TestRunner

**Deliverables:**
- [ ] `TargetProfile.to_scope_config()` method
- [ ] `mcpsf assess --target <id>` support
- [ ] `mcpsf assess --save-target <id>` flag
- [ ] Interactive `targets init` wizard
- [ ] Registry import for v0.3 scope files

**CLI Commands:**
```bash
mcpsf assess --target <id> [--profile <mode>]
mcpsf assess --transport sse --url ... --save-target <id>
mcpsf targets init  # Interactive wizard
mcpsf registry import scope.yaml --id <id>
```

**Files to Modify:**
- `mcpsf.py` (UPDATE - add `--target` and `--save-target` flags)
- `src/core/models.py` (UPDATE - add `to_scope_config()` method)
- `src/core/runner.py` (UPDATE - accept TargetProfile)

**Success Criteria:**
- ✅ `mcpsf assess --target dv-mcp-ch1` works end-to-end
- ✅ `--save-target` creates valid profile YAML
- ✅ Interactive wizard generates working configs
- ✅ Imported scope.yaml files run successfully

---

### 📋 Phase 6C: Batch Orchestration (Week 4-5)

**Goal:** Multi-target parallel execution

**Deliverables:**
- [ ] `src/core/batch_runner.py` - BatchRunner class
- [ ] Target selection DSL (all, tag=X, id=X,Y)
- [ ] Bounded parallelism (asyncio.Semaphore)
- [ ] Per-target timeout enforcement
- [ ] Resume/skip logic (`.batch_state.json`)
- [ ] Integration tests with 5+ targets

**CLI Commands:**
```bash
mcpsf batch --targets <selector> [--profile <mode>] [--concurrency N] [--resume]
```

**Files to Create:**
- `src/core/batch_runner.py` (NEW)
- `src/core/models.py` (UPDATE - add BatchResult, TargetFailure)
- `tests/integration/test_batch_runner.py` (NEW)

**Success Criteria:**
- ✅ Scan 5 targets in parallel (concurrency=3)
- ✅ `--resume` skips successful targets
- ✅ Failed targets don't block the batch
- ✅ Batch completes in <10 minutes

---

### 📋 Phase 6D: Centralized Reporting (Week 6)

**Goal:** Aggregate findings across targets

**Deliverables:**
- [ ] `src/core/reporters/batch_reporter.py` - Batch summary
- [ ] `reports/batch-<timestamp>/` structure
- [ ] Master index (`reports/index.json`)
- [ ] HTML batch summary report
- [ ] Failed targets tracking
- [ ] Top findings aggregation

**Report Structure:**
```
reports/
├── index.json                    # Master index
├── latest -> batch-2025-11-19/   # Symlink
└── batch-2025-11-19-10-30/
    ├── summary.json
    ├── summary.html
    ├── failed.json
    ├── target1/
    │   └── [standard bundle]
    └── target2/
        └── [standard bundle]
```

**Files to Create:**
- `src/core/reporters/batch_reporter.py` (NEW)
- `src/core/reporters/html_reporter.py` (NEW - for summary.html)
- `src/core/reporters/manager.py` (UPDATE - add batch methods)

**Success Criteria:**
- ✅ `summary.json` aggregates all findings
- ✅ `summary.html` renders correctly in browser
- ✅ `reports/index.json` tracks all batches
- ✅ Failed targets logged with error details

---

### 📋 Phase 6E: Detector Enhancements (Week 7-8)

**Goal:** Improve detection accuracy with multi-engine approach

**Deliverables:**
- [ ] Multi-phase testing (baseline → realistic → aggressive)
- [ ] Custom rule engine (YARA-style patterns)
- [ ] Multi-engine confidence boosting
- [ ] Simulation mode for dry-run
- [ ] 3-5 enhanced detectors with behavior phase

**Pattern Sources:**
- mcp-server-fuzzer: Multi-phase fuzzing, safety blockers
- mcp-scanner: Multi-engine detection (API + YARA + LLM)

**Files to Create:**
- `src/core/rule_engine.py` (NEW)
- `src/core/detection_engine.py` (NEW)
- `rules/custom-patterns.yaml` (NEW)
- `src/modules/base.py` (UPDATE - add multi-phase support)

**Success Criteria:**
- ✅ Pattern + behavior engines agree → 95% confidence
- ✅ Custom YARA-style rules load successfully
- ✅ 3+ detectors use multi-phase testing
- ✅ Confidence scores improve by 10%+

---

### 📋 Phase 6F: Production Hardening (Week 9)

**Goal:** Prepare for production use with 60-100+ targets

**Deliverables:**
- [ ] Error recovery and retry logic
- [ ] Resource cleanup on failure
- [ ] Progress indicators for batch runs
- [ ] Email/webhook notifications
- [ ] CI/CD integration examples
- [ ] Performance benchmarks (60+ targets)
- [ ] Complete documentation

**Files to Create:**
- `src/core/notifications.py` (NEW)
- `.github/workflows/batch-scan.yml` (NEW - CI/CD example)
- `docs/BATCH_SCANNING_GUIDE.md` (NEW - user guide)
- `scripts/import_targets.py` (NEW - bulk import)

**Success Criteria:**
- ✅ Scan 60+ targets in <30 minutes
- ✅ <5% failure rate on production servers
- ✅ Graceful degradation on errors
- ✅ CI/CD workflow runs successfully

---

## File Structure Summary

```
mcp-security-framework/
├── mcpsf.py                          # CLI - ENHANCED
│
├── src/
│   ├── adapters/
│   │   └── mcp_client_adapter.py     # UNCHANGED
│   │
│   ├── core/
│   │   ├── runner.py                 # MINOR UPDATES (accept TargetProfile)
│   │   ├── batch_runner.py           # NEW (Phase 6C)
│   │   ├── target_registry.py        # NEW (Phase 6A)
│   │   ├── rule_engine.py            # NEW (Phase 6E)
│   │   ├── detection_engine.py       # NEW (Phase 6E)
│   │   ├── notifications.py          # NEW (Phase 6F)
│   │   ├── safe_adapter.py           # UNCHANGED
│   │   ├── policy.py                 # UNCHANGED
│   │   ├── models.py                 # ENHANCED (add TargetProfile, BatchResult)
│   │   └── reporters/
│   │       ├── manager.py            # ENHANCED (add batch methods)
│   │       ├── batch_reporter.py     # NEW (Phase 6D)
│   │       ├── html_reporter.py      # NEW (Phase 6D)
│   │       └── ...                   # UNCHANGED
│   │
│   └── modules/
│       ├── base.py                   # ENHANCED (multi-phase support)
│       └── detectors/                # ENHANCED (3-5 detectors)
│
├── targets/                          # NEW (✅ CREATED)
│   ├── registry.yaml
│   ├── profiles/
│   │   ├── dv-mcp-ch1.yaml
│   │   ├── filesystem-server.yaml
│   │   ├── time-server.yaml
│   │   └── TEMPLATE.yaml
│   ├── groups/
│   │   ├── public.txt
│   │   └── test.txt
│   └── .batch_state.json             # Auto-generated
│
├── rules/                            # NEW (Phase 6E)
│   └── custom-patterns.yaml
│
├── reports/                          # ENHANCED
│   ├── index.json                    # NEW
│   ├── latest -> batch-X/            # NEW
│   ├── batch-<timestamp>/            # NEW
│   │   ├── summary.json
│   │   ├── summary.html
│   │   └── target1/, target2/, ...
│   └── ServerName/                   # Existing single-target
│
├── scripts/                          # NEW
│   ├── import_targets.py
│   └── check_critical.py
│
├── tests/
│   ├── unit/
│   │   ├── test_target_registry.py   # NEW
│   │   ├── test_batch_runner.py      # NEW
│   │   └── ...
│   └── integration/
│       └── test_batch_workflow.py    # NEW
│
└── docs/
    ├── BATCH_SCANNING_DESIGN.md      # ✅ CREATED
    ├── BATCH_SCANNING_ARCHITECTURE.md # ✅ CREATED
    ├── UNIFIED_TARGET_SYSTEM.md      # ✅ CREATED
    ├── PHASE_6_IMPLEMENTATION_PLAN.md # ✅ THIS FILE
    └── BATCH_SCANNING_GUIDE.md       # TODO (Phase 6F)
```

---

## Timeline Overview

| Phase | Duration | Key Deliverable | Status |
|-------|----------|-----------------|--------|
| **6A** | Week 1-2 | Target Registry | 🔵 TODO |
| **6B** | Week 3 | Single-Target Integration | 🔵 TODO |
| **6C** | Week 4-5 | Batch Orchestration | 🔵 TODO |
| **6D** | Week 6 | Centralized Reporting | 🔵 TODO |
| **6E** | Week 7-8 | Detector Enhancements | 🔵 TODO |
| **6F** | Week 9 | Production Hardening | 🔵 TODO |

**Total:** ~9 weeks (2-3 months)

---

## Performance Targets

| Metric | v0.3 (Current) | v0.4 (Target) |
|--------|----------------|---------------|
| **Targets per run** | 1 | 60-100+ |
| **Concurrency** | 1 | 3-5 (configurable) |
| **Setup time** | 5 min (manual) | 30 sec (wizard) |
| **Per-target time** | 1-3 min | 1-3 min (unchanged) |
| **Total batch time** | N/A | 20-30 min (60 targets) |
| **Failure tolerance** | Hard fail | Graceful degradation |
| **Resume support** | No | Yes |
| **Config reuse** | Manual | Automatic (registry) |

---

## Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **Breaking v0.3 workflows** | HIGH | Extensive backward compat testing |
| **Memory leaks in batch mode** | HIGH | Bounded concurrency, resource cleanup |
| **Registry corruption** | MEDIUM | YAML validation, backups, version control |
| **Slow targets blocking batch** | MEDIUM | Per-target timeouts, fail-fast mode |
| **Complex UX** | MEDIUM | Interactive wizards, clear docs |

---

## Success Metrics

### Phase 6A-B Success (Weeks 1-3)
- ✅ 10+ target profiles created and validated
- ✅ `mcpsf assess --target <id>` works for 5+ targets
- ✅ Interactive wizard generates valid configs
- ✅ All v0.3 tests still pass

### Phase 6C-D Success (Weeks 4-6)
- ✅ Batch scan 10 targets in parallel successfully
- ✅ Resume logic works after interruption
- ✅ Batch summary shows aggregated stats
- ✅ HTML report renders correctly

### Phase 6E Success (Weeks 7-8)
- ✅ Multi-engine detection improves confidence by 10%+
- ✅ Custom rules load and execute
- ✅ 3+ detectors use multi-phase testing

### Phase 6F Success (Week 9)
- ✅ Scan 60+ targets in <30 minutes
- ✅ <5% failure rate on production servers
- ✅ CI/CD integration works end-to-end
- ✅ Documentation complete and reviewed

---

## Next Steps (Immediate)

### 1. Team Review (This Week)
- [ ] Review UNIFIED_TARGET_SYSTEM.md design
- [ ] Approve target profile schema
- [ ] Approve registry structure
- [ ] Decide on concurrency default (3 or 5?)
- [ ] Decide on HTML templating engine (Jinja2?)

### 2. Create GitHub Issues (Next Week)
- [ ] Issue: Phase 6A - Target Registry Foundation
- [ ] Issue: Phase 6B - Single-Target Integration
- [ ] Issue: Phase 6C - Batch Orchestration
- [ ] Issue: Phase 6D - Centralized Reporting
- [ ] Issue: Phase 6E - Detector Enhancements
- [ ] Issue: Phase 6F - Production Hardening

### 3. Start Phase 6A (Week After Next)
- [ ] Implement `TargetProfile` Pydantic model
- [ ] Implement `TargetRegistry` class
- [ ] Write unit tests
- [ ] Add `mcpsf targets list/show/validate` commands
- [ ] Test with 5 example profiles

---

## References

**Design Documents:**
- [UNIFIED_TARGET_SYSTEM.md](./UNIFIED_TARGET_SYSTEM.md) - 🌟 **START HERE**
- [BATCH_SCANNING_DESIGN.md](./BATCH_SCANNING_DESIGN.md)
- [BATCH_SCANNING_ARCHITECTURE.md](./BATCH_SCANNING_ARCHITECTURE.md)

**External Inspiration:**
- [mcp-server-fuzzer](https://github.com/Agent-Hellboy/mcp-server-fuzzer) - Multi-phase testing, safety blockers
- [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) - Multi-engine detection, config discovery

**Internal:**
- [CLAUDE.md](../CLAUDE.md) - v0.3 architecture
- [samples/scope.yaml](../samples/scope.yaml) - Original scope format
- [targets/profiles/TEMPLATE.yaml](../targets/profiles/TEMPLATE.yaml) - Target profile template

---

## Questions for Team

1. **Concurrency default:** 3 or 5? (3 is safer, 5 is faster)
2. **HTML reporting:** Use Jinja2 templates or static HTML?
3. **LLM-based detection:** Include in Phase 6E or defer to v0.5?
4. **Notification methods:** Email, Slack, webhook, or all?
5. **CLI naming:** `mcpsf batch` or `mcpsf scan-batch` or `mcpsf multi`?
6. **Profile location:** Keep in `targets/profiles/` or move to `config/targets/`?

---

**Document Status:** 📋 READY FOR REVIEW
**Created:** 2025-11-19
**Version:** 1.0
**Author:** Claude (with teammate design input)
