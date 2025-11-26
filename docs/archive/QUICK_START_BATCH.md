# MCPSF Batch Scanning - Quick Start Guide

**TL;DR:** Scale from 1 MCP to 100+ MCPs with unified target management.

---

## 3-Minute Overview

### What's New in v0.4?

```
v0.3: mcpsf assess http://localhost:9001/sse
         ↓ (one at a time, manual config)

v0.4: mcpsf batch --targets all --concurrency 5
         ↓ (100+ targets, parallel, reusable configs)
```

**Key Features:**
- ✅ **Unified Registry** - Single source of truth for all MCPs
- ✅ **Single & Batch** - Same configs work for 1 or 100 targets
- ✅ **Progressive** - Start simple, scale gradually
- ✅ **Resume Logic** - Pick up where you left off
- ✅ **Parallel Execution** - 3-5 targets at once

---

## Quick Examples

### Example 1: Your First Target (30 seconds)

```bash
# Method A: Direct connection (no config)
mcpsf assess --transport sse --url http://localhost:9001/sse

# Method B: Save for reuse
mcpsf assess --transport sse --url http://localhost:9001/sse --save-target my-mcp
# ✓ Saved to targets/profiles/my-mcp.yaml
# → Next time: mcpsf assess --target my-mcp
```

### Example 2: Interactive Setup (1 minute)

```bash
mcpsf targets init
# ? Target ID: my-server
# ? Transport: sse
# ? URL: http://localhost:9001/sse
# ? Tags: production,api
# ✓ Created targets/profiles/my-server.yaml

# Use it:
mcpsf assess --target my-server
```

### Example 3: Batch Scan (5 minutes setup, then autopilot)

```bash
# Add 3 targets
mcpsf targets init --id server1 --type sse --url http://host1:9001/sse --tags prod
mcpsf targets init --id server2 --type sse --url http://host2:9001/sse --tags prod
mcpsf targets init --id server3 --type sse --url http://host3:9001/sse --tags prod

# Scan all in parallel
mcpsf batch --targets tag=prod --concurrency 3

# Check results
open reports/latest/summary.html
```

---

## CLI Cheat Sheet

See [UNIFIED_TARGET_SYSTEM.md](./UNIFIED_TARGET_SYSTEM.md) for complete documentation.

### Add per-target setup + auto-launch (for “hard” targets)

If a target needs dependencies before it can run (e.g., DV-MCP, local SSE servers), add `setup_commands` under `launch` in its profile:

```yaml
launch:
  enabled: true
  setup_commands:
    - "pip install -e ."
    - "npm install"
  command: "python"
  args: ["challenges/easy/challenge1/server_sse.py"]
  working_dir: "targets/vulnerable/dv-mcp"
  wait_for_ready: true
  ready_timeout_s: 30
  ready_check: "endpoint"
```

When you run `mcpsf assess --target-id ...` or `mcpsf batch ...`, MCPSF will run the setup commands, launch, wait for ready, assess, and shut down automatically.

---

**Happy Scanning! 🚀**
