# Weekly Project Update

**Project Title:** MCP Security Framework – Automated Vulnerability Assessment Tool for Model Context Protocol Servers  
**Week #:** 6  
**Date:** November 5, 2025  
**Student:** Yaoting, Joshua, Tanish  
**Instructor:** Mohammand

---

## 1. Summary

This week we finished integrating the two detectors pulled from the `active-attacks` branch (Privilege Abuse and Unauthenticated Access), validated the entire detector suite against ten public MCP servers, and captured repeatable execution steps in a new test playbook. The framework now has coverage for permission mismatches, baseline authentication checks, and a verified workflow for both official SDK samples and third-party servers.

---

## 2. Progress

### Detector Integration
- Refined **Privilege Abuse Detector (MCP-2024-PA-001)** to use capability inference, purpose classification, and mode-aware scoring. Complementary to Excessive Permissions; catches “simple tool with dangerous capability” mismatches.
- Updated **Unauthenticated Access Detector (MCP-2024-UA-001)** to produce structured evidence, partial-access findings, and better support for servers without resource listings.

### Test Campaign
- Cloned and configured 10 MCP servers under `targets/`, covering official SDK samples, productivity utilities, vector/file tools, and two intentionally vulnerable repos.
- Ran `mcpsf.py assess … --mode aggressive` sequentially (one target at a time) and archived reports for each run in `reports/<SERVER_NAME>/`.
- Documented the exact setup/execute/cleanup steps in `docs/MCP_TEST_PLAYBOOK_2025-11-05.md`.

### Notable Findings
- Privilege Abuse detector fired on 4/10 targets (e.g., read-only todo tools executing commands).
- Unauthenticated Access detector flagged 9/10 targets (expected for local samples).
- No false positives on clean samples (`simple-resource`, `simple-prompt`); known vulnerable servers (command-executor, hubble) returned expected critical findings.

---

## 3. Issues / Blockers

| Issue | Impact | Resolution |
|-------|--------|------------|
| Node-based servers log plain text before JSON handshake | Produces benign `UNKNOWN` statuses | Accept for now; note in playbook with recommendation to mute logs / use SSE |
| Hubble MCP server missing SQLite deps | Initial run failed with `MODULE_NOT_FOUND` | Installed `sqlite3` + `sqlite` via npm before re-running |
| Excel MCP CLI requires explicit `stdio` argument | First run aborted due to missing command argument | Updated invocation to append `/stdio` |

No remaining blockers; outstanding improvement ideas captured in playbook.

---

## 4. Plan for Next Week

1. Wrap the 10 MCP runs in reusable PowerShell scripts (launch + teardown) to reduce manual setup.
2. Add expectation tests so CI can diff detector outcomes against known-good baselines.
3. Investigate log suppression / SSE mode for noisy stdio servers (Starwind UI, fetch, hubble).
4. Start designing detector coverage dashboard (per-detector pass/fail matrix).

---

## 5. Risk & Mitigation

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Manual setup remains error-prone | Medium | Script automation (plan item #1) |
| Detector regressions go unnoticed | Medium | Baseline comparison tooling (plan item #2) |
| High volume of report artifacts inflating repo | Low | Option to prune raw outputs once baseline-capture tooling is in place |

---

## 6. Questions for Instructor / TA

1. Would you prefer the 10-server run to stay in the repo (for grading transparency) or staged elsewhere to keep the repository light?
2. Do we need to expand documentation on how to obtain vulnerable MCP builds, or is the playbook sufficient?
3. Any additional detectors you’d like prioritized after privilege/auth checks?

---

## 7. Attachments / Links

- **Branch:** `v0.3/Modules_Runer_Ready`
- **Detectors:** `src/modules/detectors/privilege_abuse.py`, `src/modules/detectors/unauth_access.py`
- **Playbook:** `docs/MCP_TEST_PLAYBOOK_2025-11-05.md`
- **Sample Reports:** `reports/COMMAND_EXECUTOR/`, `reports/EXCEL_MCP/`, `reports/WIKIPEDIA_MCP/`
- **Command Template:** `python mcpsf.py assess <target> --mode aggressive --output reports/<NAME>`

---

## 8. Metrics Summary

| Metric | Value |
|--------|-------|
| Detectors integrated this week | 2 |
| MCP servers exercised | 10 |
| Vulnerability findings (total) | 36 (multiple per server) |
| False positives observed | 0 |
| Unknown statuses | 3 (stdout noise; noted) |
| Report bundles generated | 10 |

---

## 9. Additional Notes

- `test-data/` fixture folder still used by standalone filesystem test scripts, so it remains in the repo.
- Added doc ensures teammates can rebuild environments quickly; future automation work should reference it.
- After the test run, all stray Node processes were terminated (`Get-Process node | Stop-Process -Force`) to keep local environment clean.

---

**Prepared By:** Yaoting  
**Date:** November 5, 2025

