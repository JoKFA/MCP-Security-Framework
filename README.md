# MCP Security Testing Framework

A Metasploit-like tool for testing and exploiting MCP (Model Context Protocol) servers.

## Project Structure

```
mcp-security-framework/
├── LICENSE                # MIT License
├── README.md              # This file
├── CLAUDE.md              # Architecture & development docs
├── pyproject.toml         # Package metadata
├── requirements.txt       # Dependencies
│
├── src/
│   ├── __init__.py        # Package entry point
│   ├── adapters/          # Protocol adapters (stdio, http/sse)
│   │   ├── mcp_client_adapter.py    # Main adapter (MCP SDK)
│   │   └── http_sse_adapter.py      # Raw protocol adapter
│   ├── core/              # Test runner (future)
│   └── modules/           # Test/exploit modules (future)
│
├── examples/              # Example usage scripts
│   ├── test_dv_mcp_challenge1.py
│   ├── test_dv_mcp_challenge2.py
│   └── test_official_time_server.py
│
├── docs/                  # Additional documentation
│   ├── ADAPTER_FLOW.md
│   ├── VULNERABILITY_COVERAGE.md
│   └── FILE_INVENTORY.md
│
├── tests/                 # Test suite (future)
│   ├── unit/
│   └── integration/
│
├── targets/               # Test targets (local only, not in git)
│   ├── vulnerable/        # Vulnerable servers for testing
│   │   └── dv-mcp/       # Damn Vulnerable MCP
│   ├── official/          # Official MCP servers
│   └── custom/            # User's own test servers
│
├── captures/              # Evidence logs (generated, not in git)
└── reports/               # Test reports (generated, not in git)
```

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start DV-MCP Test Server

```bash
cd targets/vulnerable/dv-mcp
python challenges/easy/challenge1/server_sse.py
```

### 3. Run Example Script

```bash
python examples/test_dv_mcp_challenge1.py
```

This will:
- Connect to DV-MCP Challenge 1
- List available tools and resources
- Read the credentials resource (intentional vulnerability)
- Call the get_user_info tool
- Save all traffic to `captures/test_mcp_challenge1.ndjson`

**Other examples:**
```bash
python examples/test_dv_mcp_challenge2.py      # Test Challenge 2 (Tool Poisoning)
python examples/test_official_time_server.py   # Test official MCP time server (stdio)
```

### Example Usage

```python
from src.adapters import McpClientAdapter

# Connect via SSE
adapter = McpClientAdapter(transport="sse", url="http://localhost:9001/sse")
await adapter.connect()

# List tools
tools = await adapter.list_tools()

# Call a tool
result = await adapter.call_tool("get_user_info", {"username": "admin"})

# Read a resource (this exposes credentials in DV-MCP Challenge 1)
resource = await adapter.read_resource("internal://credentials")

# Save evidence
adapter.save_capture("captures/evidence.ndjson")
```

## Current Status

**✅ Phase 1: Connection Layer - COMPLETE**

- McpClientAdapter implemented using official MCP SDK
- Successfully connects to DV-MCP via SSE transport
- NDJSON capture system working
- Tested against DV-MCP Challenge 1 (credential exposure vulnerability)

**📋 Next Phase: Test Runner & Modules**

See `CLAUDE.md` for detailed architecture and development roadmap.
