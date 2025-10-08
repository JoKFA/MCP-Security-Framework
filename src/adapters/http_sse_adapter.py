"""
HTTP/SSE Adapter for MCP Security Testing Framework

Connects to MCP servers over HTTP with Server-Sent Events (SSE) streaming.
Captures all requests/responses in NDJSON format for evidence collection.
"""

import json
import time
from typing import Optional, Generator, Dict, Any, List
from datetime import datetime
import httpx
from httpx_sse import connect_sse


class HttpSseAdapter:
    """Adapter for connecting to MCP servers via HTTP/SSE transport"""

    def __init__(self, base_url: str, timeout: int = 30):
        """
        Initialize HTTP/SSE adapter

        Args:
            base_url: Base URL of the MCP server (e.g., http://localhost:9001)
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session_id: Optional[str] = None
        self.messages_endpoint: Optional[str] = None
        self.client = httpx.Client(timeout=timeout)
        self.capture_log: List[Dict[str, Any]] = []

    def _log_event(self, event_type: str, data: Any, **metadata):
        """Log an event to the capture log"""
        event = {
            "type": event_type,
            "ts": datetime.utcnow().isoformat() + "Z",
            "data": data,
            **metadata
        }
        self.capture_log.append(event)
        return event

    def connect(self) -> Dict[str, Any]:
        """
        Connect to the MCP server and establish SSE session

        Returns:
            Connection info dict with session_id and endpoint
        """
        sse_url = f"{self.base_url}/sse"

        self._log_event("connection_attempt", {"url": sse_url})

        try:
            # Connect to SSE endpoint to get session info
            with connect_sse(self.client, "GET", sse_url) as event_source:
                for sse_event in event_source.iter_sse():
                    if sse_event.event == "endpoint":
                        # Extract session endpoint from SSE data
                        endpoint_path = sse_event.data.strip()
                        self.messages_endpoint = f"{self.base_url}{endpoint_path}"

                        # Extract session ID from endpoint path
                        # Format: /messages/?session_id=<id>
                        if "session_id=" in endpoint_path:
                            self.session_id = endpoint_path.split("session_id=")[1]

                        connection_info = {
                            "session_id": self.session_id,
                            "messages_endpoint": self.messages_endpoint,
                            "sse_url": sse_url
                        }

                        self._log_event("connection_established", connection_info)
                        return connection_info

            raise Exception("No endpoint event received from SSE")

        except Exception as e:
            self._log_event("connection_error", {"error": str(e)})
            raise

    def send(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a JSON-RPC message to the MCP server

        Args:
            message: JSON-RPC message dict

        Returns:
            Response dict from server
        """
        if not self.messages_endpoint:
            raise Exception("Not connected. Call connect() first.")

        start_time = time.time()
        self._log_event("request", message)

        try:
            response = self.client.post(
                self.messages_endpoint,
                json=message,
                headers={"Content-Type": "application/json"}
            )

            latency_ms = int((time.time() - start_time) * 1000)

            response.raise_for_status()
            response_data = response.json()

            self._log_event("response", response_data, latency_ms=latency_ms)
            return response_data

        except Exception as e:
            self._log_event("request_error", {"error": str(e)}, latency_ms=int((time.time() - start_time) * 1000))
            raise

    def receive_stream(self, timeout: Optional[int] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Receive streaming SSE events from the server

        Args:
            timeout: Optional timeout override

        Yields:
            Parsed SSE event data as dicts
        """
        if not self.messages_endpoint:
            raise Exception("Not connected. Call connect() first.")

        # For MCP SSE, we typically listen on the main SSE endpoint
        sse_url = f"{self.base_url}/sse"

        try:
            with connect_sse(self.client, "GET", sse_url, timeout=timeout or self.timeout) as event_source:
                for sse_event in event_source.iter_sse():
                    event_data = {
                        "event": sse_event.event,
                        "data": sse_event.data,
                        "id": sse_event.id,
                        "retry": sse_event.retry
                    }
                    self._log_event("sse_event", event_data)
                    yield event_data

        except Exception as e:
            self._log_event("stream_error", {"error": str(e)})
            raise

    def close(self):
        """Close the HTTP client connection"""
        self._log_event("disconnect", {"session_id": self.session_id})
        self.client.close()

    def get_connection_info(self) -> Dict[str, Any]:
        """Get current connection information"""
        return {
            "base_url": self.base_url,
            "session_id": self.session_id,
            "messages_endpoint": self.messages_endpoint,
            "timeout": self.timeout
        }

    def get_capture_log(self) -> List[Dict[str, Any]]:
        """Get all captured events"""
        return self.capture_log

    def save_capture(self, filepath: str):
        """Save capture log to NDJSON file"""
        with open(filepath, 'w') as f:
            for event in self.capture_log:
                f.write(json.dumps(event) + '\n')
