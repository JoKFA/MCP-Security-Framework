# MCP Security Framework - Target Registry

This directory contains the target registry for batch assessments.

## Directory Structure

```
targets/
├── registry.yaml          # Master index of all targets
├── profiles/             # Individual target configurations
│   ├── dv-mcp-ch1.yaml
│   ├── filesystem-server.yaml
│   ├── time-server.yaml
│   └── TEMPLATE.yaml     # Template for new targets
├── groups/              # Target groups for bulk operations
│   ├── public.txt
│   └── test.txt
└── .batch_state.json    # Resume state (auto-generated, git-ignored)
```

## Quick Start

See full documentation in the file.
