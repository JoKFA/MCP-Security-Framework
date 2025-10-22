"""
MCP Client Adapter for MCP Security Testing Framework

Uses the official MCP Python SDK to connect to servers via stdio or SSE.
Captures all requests/responses in NDJSON format for evidence collection.
"""

import json
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client


class McpClientAdapter:
    """Adapter using official MCP SDK for connecting to servers"""

    def __init__(self, transport: str = "sse", **transport_config):
        """
        Initialize MCP client adapter

        Args:
            transport: "stdio" or "sse"
            **transport_config: Transport-specific config
                For SSE: url (required), timeout (optional)
                For stdio: command, args, env (optional)
        """
        self.transport = transport
        self.transport_config = transport_config
        self.session: Optional[ClientSession] = None
        self.capture_log: List[Dict[str, Any]] = []
        self._connected = False
        self._client_exit_stack = None
        self._session_exit_stack = None

    def _log_event(self, event_type: str, data: Any, **metadata):
        """Log an event to the capture log"""
        event = {
            "type": event_type,
            "ts": datetime.now(timezone.utc).isoformat(),
            "data": data,
            **metadata
        }
        self.capture_log.append(event)
        return event

    @asynccontextmanager
    async def _get_client(self):
        """Get the appropriate MCP client based on transport type"""
        if self.transport == "sse":
            url = self.transport_config.get("url")
            if not url:
                raise ValueError("SSE transport requires 'url' parameter")

            # Use SSE client with proper headers
            async with sse_client(url) as (read, write):
                yield (read, write)

        elif self.transport == "stdio":
            command = self.transport_config.get("command")
            args = self.transport_config.get("args", [])
            env = self.transport_config.get("env")

            if not command:
                raise ValueError("stdio transport requires 'command' parameter")

            server_params = StdioServerParameters(
                command=command,
                args=args,
                env=env
            )

            async with stdio_client(server_params) as (read, write):
                yield (read, write)
        else:
            raise ValueError(f"Unknown transport: {self.transport}")

    async def connect(self) -> Dict[str, Any]:
        """
        Connect to the MCP server and initialize session

        Returns:
            Connection info dict with server capabilities
        """
        self._log_event("connection_attempt", {
            "transport": self.transport,
            "config": self.transport_config
        })

        try:
            # Store client and session context managers manually
            if self.transport == "sse":
                url = self.transport_config.get("url")
                if not url:
                    raise ValueError("SSE transport requires 'url' parameter")

                client_cm = sse_client(url)

            elif self.transport == "stdio":
                command = self.transport_config.get("command")
                args = self.transport_config.get("args", [])
                env = self.transport_config.get("env")

                if not command:
                    raise ValueError("stdio transport requires 'command' parameter")

                server_params = StdioServerParameters(
                    command=command,
                    args=args,
                    env=env
                )
                client_cm = stdio_client(server_params)
            else:
                raise ValueError(f"Unknown transport: {self.transport}")

            # Enter client context
            self._client_exit_stack = client_cm
            read, write = await client_cm.__aenter__()

            # Create and enter session context
            session_cm = ClientSession(read, write)
            self._session_exit_stack = session_cm
            self.session = await session_cm.__aenter__()

            # Initialize connection
            init_result = await self.session.initialize()

            connection_info = {
                "transport": self.transport,
                "server_info": {
                    "name": init_result.serverInfo.name,
                    "version": init_result.serverInfo.version
                },
                "capabilities": {
                    "resources": init_result.capabilities.resources is not None,
                    "tools": init_result.capabilities.tools is not None,
                    "prompts": init_result.capabilities.prompts is not None
                },
                "protocol_version": init_result.protocolVersion
            }

            self._log_event("connection_established", connection_info)
            self._connected = True

            return connection_info

        except Exception as e:
            self._log_event("connection_error", {"error": str(e)})
            # Clean up if connection failed
            await self.disconnect()
            raise

    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from the MCP server"""
        if not self.session:
            raise Exception("Not connected. Call connect() first.")

        self._log_event("request", {"method": "tools/list"})

        try:
            result = await self.session.list_tools()
            tools = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.inputSchema
                }
                for tool in result.tools
            ]

            self._log_event("response", {"tools": tools})
            return tools

        except Exception as e:
            self._log_event("error", {"method": "tools/list", "error": str(e)})
            raise

    async def list_resources(self) -> List[Dict[str, Any]]:
        """List available resources from the MCP server"""
        if not self.session:
            raise Exception("Not connected. Call connect() first.")

        self._log_event("request", {"method": "resources/list"})

        try:
            result = await self.session.list_resources()
            resources = [
                {
                    "uri": str(resource.uri),  # Convert to string (Pydantic AnyUrl → str)
                    "name": resource.name,
                    "description": resource.description,
                    "mimeType": resource.mimeType
                }
                for resource in result.resources
            ]

            self._log_event("response", {"resources": resources})
            return resources

        except Exception as e:
            self._log_event("error", {"method": "resources/list", "error": str(e)})
            raise

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool on the MCP server"""
        if not self.session:
            raise Exception("Not connected. Call connect() first.")

        self._log_event("request", {
            "method": "tools/call",
            "tool": name,
            "arguments": arguments
        })

        try:
            result = await self.session.call_tool(name, arguments)

            response_data = {
                "content": [
                    {
                        "type": item.type,
                        "text": getattr(item, 'text', None)
                    }
                    for item in result.content
                ],
                "isError": result.isError if hasattr(result, 'isError') else False
            }

            self._log_event("response", {
                "tool": name,
                "result": response_data
            })

            return response_data

        except Exception as e:
            self._log_event("error", {
                "method": "tools/call",
                "tool": name,
                "error": str(e)
            })
            raise

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a resource from the MCP server"""
        if not self.session:
            raise Exception("Not connected. Call connect() first.")

        self._log_event("request", {
            "method": "resources/read",
            "uri": uri
        })

        try:
            result = await self.session.read_resource(uri)

            resource_data = {
                "uri": uri,
                "contents": [
                    {
                        "uri": content.uri,
                        "mimeType": content.mimeType,
                        "text": getattr(content, 'text', None),
                        "blob": getattr(content, 'blob', None)
                    }
                    for content in result.contents
                ]
            }

            self._log_event("response", resource_data)
            return resource_data

        except Exception as e:
            self._log_event("error", {
                "method": "resources/read",
                "uri": uri,
                "error": str(e)
            })
            raise

    def get_capture_log(self) -> List[Dict[str, Any]]:
        """Get all captured events"""
        return self.capture_log

    def save_capture(self, filepath: str):
        """Save capture log to NDJSON file"""
        with open(filepath, 'w') as f:
            for event in self.capture_log:
                # Convert to dict with string representations for non-serializable objects
                serializable_event = json.loads(json.dumps(event, default=str))
                f.write(json.dumps(serializable_event) + '\n')

    async def disconnect(self):
        """Disconnect from the server"""
        if self._connected:
            self._log_event("disconnect", {"transport": self.transport})

        # Exit session context if exists
        if self._session_exit_stack:
            try:
                await self._session_exit_stack.__aexit__(None, None, None)
            except:
                pass
            self._session_exit_stack = None

        # Exit client context if exists
        if self._client_exit_stack:
            try:
                await self._client_exit_stack.__aexit__(None, None, None)
            except:
                pass
            self._client_exit_stack = None

        self.session = None
        self._connected = False
