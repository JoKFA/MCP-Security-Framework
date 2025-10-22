"""
Safe adapter wrapper - enforces policy guardrails around MCP adapter.

Wraps McpClientAdapter to provide:
- Scope enforcement (allowed/blocked paths)
- Rate limiting (QPS, burst, backoff)
- Evidence redaction
- Audit logging
- Request counting and limits
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from src.adapters.mcp_client_adapter import McpClientAdapter
from src.core.policy import ScopeConfig, RateLimiter, Redactor, AuditLogger
from src.core.models import ServerProfile, ServerCapabilities


class SafeAdapterError(Exception):
    """Base exception for safe adapter errors."""
    pass


class ScopeViolationError(SafeAdapterError):
    """Raised when a request violates scope rules."""
    pass


class RateLimitExceededError(SafeAdapterError):
    """Raised when rate limit is exceeded."""
    pass


class RequestLimitExceededError(SafeAdapterError):
    """Raised when max total requests limit is reached."""
    pass


class SafeAdapter:
    """
    Safe wrapper around McpClientAdapter.

    Enforces scope, rate limits, redaction, and audit logging.
    All detector interactions go through this adapter.
    """

    def __init__(
        self,
        base_adapter: McpClientAdapter,
        scope: ScopeConfig,
        audit_log_path: Optional[Path] = None,
    ):
        """
        Initialize safe adapter.

        Args:
            base_adapter: McpClientAdapter instance
            scope: Scope configuration with policy settings
            audit_log_path: Path for audit log (default: scope.reporting.output_dir/audit.jsonl)
        """
        self.base_adapter = base_adapter
        self.scope = scope

        # Initialize safety components
        self.rate_limiter = RateLimiter(scope.rate_limit)
        self.redactor = Redactor(scope.policy.max_payload_kb)

        # Initialize audit logger
        if audit_log_path is None:
            output_dir = Path(scope.reporting.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            audit_log_path = output_dir / "audit.jsonl"

        self.audit_logger = AuditLogger(audit_log_path)

        # Request tracking
        self.request_count = 0
        self.max_requests = scope.policy.max_total_requests

        # Server profile (populated on connect)
        self.server_profile: Optional[ServerProfile] = None

    async def connect(self) -> ServerProfile:
        """
        Connect to MCP server and build profile.

        Returns:
            ServerProfile with capabilities

        Raises:
            Exception: On connection failure
        """
        await self.audit_logger.log("connect_attempt", {
            "target": self.scope.target,
            "transport": self.scope.transport or "auto",
        })

        try:
            # Connect via base adapter
            connection_info = await self.base_adapter.connect()

            # Build server profile
            self.server_profile = ServerProfile(
                server_name=connection_info["server_info"]["name"],
                server_version=connection_info["server_info"]["version"],
                protocol_version=connection_info["protocol_version"],
                capabilities=ServerCapabilities(
                    resources=connection_info["capabilities"]["resources"],
                    tools=connection_info["capabilities"]["tools"],
                    prompts=connection_info["capabilities"]["prompts"],
                ),
                transport=connection_info["transport"],
                endpoint=self.scope.target if connection_info["transport"] != "stdio" else None,
                auth_type=self.scope.auth.type,
                exposure="local" if "localhost" in self.scope.target else "unknown",
            )

            await self.audit_logger.log("connect_success", {
                "server_name": self.server_profile.server_name,
                "server_version": self.server_profile.server_version,
                "capabilities": {
                    "resources": self.server_profile.capabilities.resources,
                    "tools": self.server_profile.capabilities.tools,
                    "prompts": self.server_profile.capabilities.prompts,
                },
            })

            return self.server_profile

        except Exception as e:
            await self.audit_logger.log("connect_error", {"error": str(e)})
            raise

    async def list_resources(self) -> List[Dict[str, Any]]:
        """
        List resources with scope filtering.

        Returns:
            List of resource dicts (only allowed ones)

        Raises:
            RequestLimitExceededError: If max requests reached
        """
        self._check_request_limit()

        if self.scope.policy.dry_run:
            await self.audit_logger.log("dry_run", {"method": "list_resources"})
            return []

        await self.rate_limiter.acquire()
        self.request_count += 1

        await self.audit_logger.log("request", {
            "method": "list_resources",
            "request_count": self.request_count,
        })

        try:
            resources = await self.base_adapter.list_resources()

            # Filter by scope rules
            allowed_resources = []
            for resource in resources:
                uri = resource.get("uri", "")
                if self.scope.is_path_allowed(uri):
                    allowed_resources.append(resource)
                else:
                    await self.audit_logger.log("scope_filtered", {
                        "resource_uri": uri,
                        "reason": "not in allowed_prefixes or blocked",
                    })

            # Redact if needed
            if self.scope.policy.redact_evidence:
                redacted = self.redactor.redact_payload(allowed_resources, "list_resources")
                await self.audit_logger.log("response", {
                    "method": "list_resources",
                    "resource_count": len(allowed_resources),
                    "evidence": redacted,
                })
            else:
                await self.audit_logger.log("response", {
                    "method": "list_resources",
                    "resources": allowed_resources,
                })

            return allowed_resources

        except Exception as e:
            await self.audit_logger.log("error", {
                "method": "list_resources",
                "error": str(e),
            })
            raise

    async def list_tools(self) -> List[Dict[str, Any]]:
        """
        List tools with scope filtering.

        Returns:
            List of tool dicts (only allowed ones)

        Raises:
            RequestLimitExceededError: If max requests reached
        """
        self._check_request_limit()

        if self.scope.policy.dry_run:
            await self.audit_logger.log("dry_run", {"method": "list_tools"})
            return []

        await self.rate_limiter.acquire()
        self.request_count += 1

        await self.audit_logger.log("request", {
            "method": "list_tools",
            "request_count": self.request_count,
        })

        try:
            tools = await self.base_adapter.list_tools()

            # Filter by scope rules (tool names)
            allowed_tools = []
            for tool in tools:
                name = tool.get("name", "")
                # Treat tool names like paths for filtering
                if self.scope.is_path_allowed(f"/tools/{name}"):
                    allowed_tools.append(tool)
                else:
                    await self.audit_logger.log("scope_filtered", {
                        "tool_name": name,
                        "reason": "not in allowed_prefixes or blocked",
                    })

            # Redact if needed
            if self.scope.policy.redact_evidence:
                redacted = self.redactor.redact_payload(allowed_tools, "list_tools")
                await self.audit_logger.log("response", {
                    "method": "list_tools",
                    "tool_count": len(allowed_tools),
                    "evidence": redacted,
                })
            else:
                await self.audit_logger.log("response", {
                    "method": "list_tools",
                    "tools": allowed_tools,
                })

            return allowed_tools

        except Exception as e:
            await self.audit_logger.log("error", {
                "method": "list_tools",
                "error": str(e),
            })
            raise

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """
        Read a resource with scope enforcement.

        Args:
            uri: Resource URI

        Returns:
            Resource data

        Raises:
            ScopeViolationError: If URI violates scope rules
            RequestLimitExceededError: If max requests reached
        """
        # Check scope first (before rate limiting)
        if not self.scope.is_path_allowed(uri):
            await self.audit_logger.log("scope_violation", {
                "method": "read_resource",
                "uri": uri,
                "reason": "URI not allowed by scope rules",
            })
            raise ScopeViolationError(f"Resource URI not allowed: {uri}")

        self._check_request_limit()

        if self.scope.policy.dry_run:
            await self.audit_logger.log("dry_run", {
                "method": "read_resource",
                "uri": uri,
            })
            return {"uri": uri, "contents": []}

        await self.rate_limiter.acquire()
        self.request_count += 1

        await self.audit_logger.log("request", {
            "method": "read_resource",
            "uri": uri,
            "request_count": self.request_count,
        })

        try:
            resource_data = await self.base_adapter.read_resource(uri)

            # Redact if needed
            if self.scope.policy.redact_evidence:
                redacted = self.redactor.redact_payload(resource_data, "read_resource")
                await self.audit_logger.log("response", {
                    "method": "read_resource",
                    "uri": uri,
                    "evidence": redacted,
                })
            else:
                await self.audit_logger.log("response", {
                    "method": "read_resource",
                    "resource": resource_data,
                })

            return resource_data

        except Exception as e:
            await self.audit_logger.log("error", {
                "method": "read_resource",
                "uri": uri,
                "error": str(e),
            })
            raise

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """
        Call a tool with scope enforcement.

        Args:
            name: Tool name
            arguments: Tool arguments

        Returns:
            Tool result

        Raises:
            ScopeViolationError: If tool violates scope rules
            RequestLimitExceededError: If max requests reached
        """
        # Check scope (treat tool name as path)
        tool_path = f"/tools/{name}"
        if not self.scope.is_path_allowed(tool_path):
            await self.audit_logger.log("scope_violation", {
                "method": "call_tool",
                "tool": name,
                "reason": "Tool not allowed by scope rules",
            })
            raise ScopeViolationError(f"Tool not allowed: {name}")

        self._check_request_limit()

        if self.scope.policy.dry_run:
            await self.audit_logger.log("dry_run", {
                "method": "call_tool",
                "tool": name,
                "arguments": arguments,
            })
            return {"content": [], "isError": False}

        await self.rate_limiter.acquire()
        self.request_count += 1

        # Redact arguments if they contain large payloads
        redacted_args = arguments
        if self.scope.policy.redact_evidence:
            redacted_args_data = self.redactor.redact_payload(arguments, "tool_arguments")
            # Keep original for actual call, log redacted version
            log_args = redacted_args_data
        else:
            log_args = arguments

        await self.audit_logger.log("request", {
            "method": "call_tool",
            "tool": name,
            "arguments": log_args,
            "request_count": self.request_count,
        })

        try:
            result = await self.base_adapter.call_tool(name, arguments)

            # Redact result if needed
            if self.scope.policy.redact_evidence:
                redacted_result = self.redactor.redact_payload(result, "tool_result")
                await self.audit_logger.log("response", {
                    "method": "call_tool",
                    "tool": name,
                    "evidence": redacted_result,
                })
            else:
                await self.audit_logger.log("response", {
                    "method": "call_tool",
                    "tool": name,
                    "result": result,
                })

            return result

        except Exception as e:
            await self.audit_logger.log("error", {
                "method": "call_tool",
                "tool": name,
                "error": str(e),
            })
            raise

    async def disconnect(self) -> None:
        """Disconnect from server and finalize audit log."""
        await self.audit_logger.log("disconnect", {
            "total_requests": self.request_count,
            "rate_limiter_stats": self.rate_limiter.get_stats(),
            "audit_log_stats": self.audit_logger.get_stats(),
        })

        await self.base_adapter.disconnect()

    def _check_request_limit(self) -> None:
        """
        Check if request limit has been reached.

        Raises:
            RequestLimitExceededError: If max_total_requests reached
        """
        if self.request_count >= self.max_requests:
            raise RequestLimitExceededError(
                f"Max requests limit reached: {self.max_requests}"
            )

    def get_server_profile(self) -> Optional[ServerProfile]:
        """Get server profile (available after connect)."""
        return self.server_profile

    def get_audit_log_path(self) -> Path:
        """Get path to audit log file."""
        return self.audit_logger.log_path

    def get_stats(self) -> Dict[str, Any]:
        """Get adapter statistics."""
        return {
            "request_count": self.request_count,
            "max_requests": self.max_requests,
            "rate_limiter": self.rate_limiter.get_stats(),
            "audit_log": self.audit_logger.get_stats(),
            "server_profile": self.server_profile.model_dump() if self.server_profile else None,
        }


# Helper function to create SafeAdapter from scope file
async def create_safe_adapter_from_scope(
    scope_path: str,
    audit_log_path: Optional[Path] = None,
) -> SafeAdapter:
    """
    Create SafeAdapter from scope.yaml file.

    Args:
        scope_path: Path to scope.yaml
        audit_log_path: Optional audit log path

    Returns:
        SafeAdapter instance (not yet connected)

    Usage:
        adapter = await create_safe_adapter_from_scope("scope.yaml")
        profile = await adapter.connect()
        resources = await adapter.list_resources()
        await adapter.disconnect()
    """
    from src.core.policy import load_scope_config

    scope = load_scope_config(scope_path)

    # Create base adapter from scope.target
    if scope.target.startswith("http://") or scope.target.startswith("https://"):
        # SSE transport
        base_adapter = McpClientAdapter(transport="sse", url=scope.target)
    elif scope.target.startswith("stdio://"):
        # Parse stdio:// URL
        # Format: stdio://command/arg1/arg2/...
        parts = scope.target[8:].split("/")
        command = parts[0] if parts else "npx"
        args = parts[1:] if len(parts) > 1 else []

        base_adapter = McpClientAdapter(transport="stdio", command=command, args=args)
    else:
        raise ValueError(f"Unknown target format: {scope.target}")

    return SafeAdapter(base_adapter, scope, audit_log_path)
