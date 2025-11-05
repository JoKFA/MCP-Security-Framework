# How MCP (Model Context Protocol) Works

## TL;DR
MCP is like an API that uses JSON-RPC messages. You send JSON requests with method names, server responds with JSON.

## What is MCP?

MCP is a protocol (like HTTP, but specifically for AI/LLM context). It lets applications expose:
- **Tools**: Functions the AI can call (e.g., "execute_command", "read_file")
- **Resources**: Data the AI can read (e.g., "notes://user123", "internal://credentials")
- **Prompts**: Pre-built prompts

## How It Works (Like an API)

### 1. **Connection**
You connect to an MCP server (like connecting to an API endpoint):
- **SSE**: HTTP connection to `http://localhost:9001/sse` (Server-Sent Events)
- **stdio**: Launch a process and talk via stdin/stdout

### 2. **Initialize Handshake**
First thing you send:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {}
  }
}
```

Server responds:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {},
      "resources": {}
    },
    "serverInfo": {
      "name": "Challenge 1 - Basic Prompt Injection",
      "version": "1.16.0"
    }
  }
}
```

### 3. **List Tools** (What we do in our detector)
We send:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list"
}
```

Server responds:
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "execute_command",
        "description": "Execute a system command",
        "inputSchema": {
          "type": "object",
          "properties": {
            "command": {"type": "string"}
          }
        }
      }
    ]
  }
}
```

### 4. **Call a Tool** (Active testing)
We send:
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "execute_command",
    "arguments": {
      "command": "echo safe_test_marker"
    }
  }
}
```

Server responds:
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Command output:\nsafe_test_marker"
      }
    ],
    "isError": false
  }
}
```

### 5. **Read a Resource** (For prompt injection testing)
We send:
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "resources/read",
  "params": {
    "uri": "notes://MCPSF_INJECT_abc123"
  }
}
```

Server responds:
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "contents": [
      {
        "uri": "notes://MCPSF_INJECT_abc123",
        "mimeType": "text/plain",
        "text": "No notes found for user: MCPSF_INJECT_abc123"
      }
    ]
  }
}
```

## The Flow in Our Code

1. **Connect**: `adapter.connect()` → Sends `initialize` message
2. **List Tools**: `adapter.list_tools()` → Sends `tools/list` message
   - Returns list of tool dicts (that's what we analyze!)
3. **Call Tool**: `adapter.call_tool('execute_command', {'command': 'echo test'})` 
   - Sends `tools/call` message with tool name and arguments
   - Returns result from the tool
4. **Read Resource**: `adapter.read_resource('notes://user123')`
   - Sends `resources/read` message with URI
   - Returns resource content

## Why It's Like an API

- **Request/Response**: You send a request, get a response
- **Method Names**: Like REST endpoints (`tools/list`, `tools/call`)
- **JSON Format**: Everything is JSON
- **Stateless**: Each request is independent

## Key Difference from REST APIs

- Uses **JSON-RPC 2.0** protocol (not REST)
- Messages have `id`, `method`, `params` structure
- Two transports: HTTP (SSE) or process (stdio)
- Designed specifically for AI/LLM context sharing

## In Our Detector Code

When we do:
```python
tools = await adapter.list_tools()
```

Behind the scenes:
1. Adapter sends: `{"method": "tools/list", ...}`
2. Server responds: `{"result": {"tools": [...]}}`
3. Adapter converts it to Python dicts: `[{"name": "...", "description": "...", ...}]`
4. We get those dicts and analyze them!

That's why `tool` is a dict - it came from the JSON response!

