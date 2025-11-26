# Documentation Index & Summary

**Version:** 0.4.0
**Last Updated:** 2025-11-24
**Purpose:** Quick reference for all MCPSF documentation

---

## üìö Core Documentation (Current)

| Document | Audience | Purpose |
|----------|----------|---------|
| **[README.md](README.md)** | Everyone | Main hub: overview, quick start, prerequisites, limitations |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Developers, Engineers | Complete system architecture and data flow |
| **[WRAPPER_GUIDE.md](WRAPPER_GUIDE.md)** | Developers, DevOps | AMSAW v2 discovery/provisioning/bridge details |
| **[DETECTORS_GUIDE.md](DETECTORS_GUIDE.md)** | Security Engineers | Detector taxonomy, behaviors, authoring, testing |
| **[REPORTS_GUIDE.md](REPORTS_GUIDE.md)** | DevOps, Security Teams | Report formats, CI/CD integration, analysis |
| **[API_REFERENCE.md](API_REFERENCE.md)** | Developers, Automation | CLI, Python API, Web API, config files |
| **[WEB_VIEW_README.md](../WEB_VIEW_README.md)** | Web UI Users | Running the Flask web view and browsing reports |
| **[OLD_AUTO_SANDBOX_ANALYSIS.md](OLD_AUTO_SANDBOX_ANALYSIS.md)** | Developers | Historical context: old vs new system |

---

## üìñ Documentation Guide by Role

### **For New Users / Quick Start**
1. **[README.md](README.md)** - Prereqs, install, basic usage
2. **[DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md)** - Choose the next doc

### **For Developers / Integration**
1. **[README.md](README.md)** - Setup and CLI usage
2. **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design + data flows
3. **[WRAPPER_GUIDE.md](WRAPPER_GUIDE.md)** - AMSAW v2 details
4. **[API_REFERENCE.md](API_REFERENCE.md)** - CLI/Python/Web APIs

### **For Security Engineers**
1. **[ARCHITECTURE.md](ARCHITECTURE.md)** - Phase 4 assessment model
2. **[DETECTORS_GUIDE.md](DETECTORS_GUIDE.md)** - Detector behaviors + authoring
3. **[REPORTS_GUIDE.md](REPORTS_GUIDE.md)** - Finding interpretation + CI

### **For DevOps / CI**
1. **[REPORTS_GUIDE.md](REPORTS_GUIDE.md)** - SARIF/JSON and pipelines
2. **[API_REFERENCE.md](API_REFERENCE.md)** - Automation hooks
3. **[WRAPPER_GUIDE.md](WRAPPER_GUIDE.md)** - Docker/bridge expectations

### **For Web UI Users**
1. **[WEB_VIEW_README.md](../WEB_VIEW_README.md)** - Run the web UI and view reports
2. **[REPORTS_GUIDE.md](REPORTS_GUIDE.md)** - Report content reference

### **For AI / Future Sessions**
1. **[README.md](README.md)** - Project overview
2. **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical details
3. **[OLD_AUTO_SANDBOX_ANALYSIS.md](OLD_AUTO_SANDBOX_ANALYSIS.md)** - Historical context

---

## üóÇÔ∏?Documentation Structure

```
docs/
©¿©§©§ README.md                          # Main documentation hub
©¿©§©§ ARCHITECTURE.md                    # System architecture (detailed)
©¿©§©§ WRAPPER_GUIDE.md                   # AMSAW v2 details
©¿©§©§ DETECTORS_GUIDE.md                 # Detector taxonomy + authoring
©¿©§©§ REPORTS_GUIDE.md                   # Reporting and CI/CD integration
©¿©§©§ API_REFERENCE.md                   # CLI/Python/Web APIs
©¿©§©§ OLD_AUTO_SANDBOX_ANALYSIS.md       # Historical: old vs new system
©¿©§©§ DOCUMENTATION_INDEX.md             # This file
©∏©§©§ WEB_VIEW_README.md                 # Flask web UI reference

©∏©§©§ archive/                           # Historical development docs
    ©¿©§©§ AMSAW_FULL_SNAPSHOT.md         # Development snapshot
    ©¿©§©§ AUTO_SANDBOX_IMPLEMENTATION.md  # Old implementation details
    ©¿©§©§ FIXES_APPLIED.md               # Development log
    ©¿©§©§ IMPLEMENTATION_STATUS.md        # Development log
    ©¿©§©§ REDESIGN_PLAN.md               # Original design doc (superseded by ARCHITECTURE.md)
    ©¿©§©§ SIDECAR_PATTERN.md             # Design exploration
    ©¿©§©§ UI_EVALUATION_2025-11-19.md    # UI exploration (keep bookmarked for next UI revamp)
    ©∏©§©§ MCP_TEST_PLAYBOOK_2025-11-05.md # Test notes
```

---

## üìä Documentation Cleanup Summary

### Archived (Moved to `docs/archive/`)
These docs served their purpose during development but are now superseded:
- ‚ú?`AMSAW_FULL_SNAPSHOT.md` ‚Ü?Historical snapshot (166KB)
- ‚ú?`AUTO_SANDBOX_IMPLEMENTATION.md` ‚Ü?Old implementation (30KB)
- ‚ú?`FIXES_APPLIED.md` ‚Ü?Development log (11KB)
- ‚ú?`IMPLEMENTATION_STATUS.md` ‚Ü?Development log (8KB)
- ‚ú?`REDESIGN_PLAN.md` ‚Ü?Superseded by ARCHITECTURE.md (43KB)
- ‚ú?`SIDECAR_PATTERN.md` ‚Ü?Design exploration (10KB)
- ‚ú?`UI_EVALUATION_2025-11-19.md` ‚Ü?UI exploration (20KB)
- ‚ú?`MCP_TEST_PLAYBOOK_2025-11-05.md` ‚Ü?Test notes (5KB)

### Deleted
- ‚ú?`CLOUD_ROADMAP.md` ‚Ü?Not relevant to current system

### Kept & Refactored
- ‚ú?`README.md` ‚Ü?Completely rewritten (production-ready)
- ‚ú?`ARCHITECTURE.md` ‚Ü?NEW comprehensive technical guide
- ‚ú?`OLD_AUTO_SANDBOX_ANALYSIS.md` ‚Ü?Valuable historical analysis

---

## üéØ Documentation Principles

### Clarity
- Clear section headers
- Visual diagrams (ASCII art)
- Code examples with comments
- Consistent formatting

### Completeness
- Cover all system components
- Include examples for each feature
- Document edge cases and limitations
- Provide troubleshooting guidance

### Accessibility
- Multiple entry points for different audiences
- Progressive disclosure (overview ‚Ü?details)
- Cross-references between documents
- Searchable structure

### Maintainability
- Version numbers on all docs
- Last-updated dates
- Clear ownership (who updates what)
- Separation of stable vs evolving content

---

## üìà Key System Metrics (Quick Reference)

| Metric | Value |
|--------|-------|
| **Total LOC** | ~4,500 lines |
| **Assessment Time** | 30-90 seconds |
| **Setup Time** | 10-20 seconds |
| **Success Rate** | 100% (Python MCPs) |
| **Detectors** | 14 |
| **Languages** | Python, Node.js |
| **Transports** | stdio, SSE |

---

## üöÄ Quick Command Reference

```bash
# Installation
git clone https://github.com/yourorg/mcp-security-framework
cd mcp-security-framework
pip install -r requirements.txt

# Basic assessment
python mcpsf.py assess <source>

# Common sources:
python mcpsf.py assess targets/vulnerable/dv-mcp/challenges/easy/challenge1
python mcpsf.py assess @modelcontextprotocol/server-time
python mcpsf.py assess https://github.com/modelcontextprotocol/servers/tree/main/src/time

# With options:
python mcpsf.py assess <source> --detectors MCP-2024-PI-001
python mcpsf.py assess <source> -o ./reports
python mcpsf.py assess <source> --profile aggressive

# Testing:
pytest tests/unit/
python tests/test_challenge1.py
```

---

## üìù Future Documentation Plans

### Phase 1 (Complete) - Core & Specialized
- README.md - Main hub
- ARCHITECTURE.md - System design
- WRAPPER_GUIDE.md - AMSAW v2 implementation
- DETECTORS_GUIDE.md - Detector taxonomy/authoring
- REPORTS_GUIDE.md - Reporting + CI/CD
- API_REFERENCE.md - CLI/Python/Web APIs
- WEB_VIEW_README.md - Flask web UI reference

### Phase 2 (Next) - Advanced Topics
- CONTRIBUTING.md - Dev workflow and release process (current)
- TROUBLESHOOTING.md - Common provisioning/detector/report issues (to add)
- PERFORMANCE.md - Optimization guide (to add)
- SECURITY.md - Threat model deep dive (to add)

### Phase 3 (Future) - Playbooks & Scaling
- Batch scanning guide (revisit archive docs for inputs)
- Web UI UX revamp (see archive/UI_EVALUATION_2025-11-19.md)

## ‚ú?Documentation Checklist

Before each release, ensure:
- [ ] All version numbers updated
- [ ] Last-updated dates current
- [ ] Code examples tested
- [ ] Links validated (no 404s)
- [ ] Diagrams up-to-date
- [ ] Metrics current
- [ ] Changelog updated

---

## ü§ù Contributing to Documentation

1. **Small fixes:** Edit directly, create PR
2. **New sections:** Open issue first for discussion
3. **New guides:** Use existing guides as template
4. **Always:** Test code examples before committing

---

## üìß Documentation Support

- **Issues:** https://github.com/yourorg/mcp-security-framework/issues
- **Discussions:** https://github.com/yourorg/mcp-security-framework/discussions
- **Questions:** Tag with `documentation` label

---

**Documentation Status:** Production-ready ‚ú?
**Next Update:** When new features ship (v0.5.0)


