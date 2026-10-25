"""
MCP client for PointGuardAI Gateway.

Sends MCP JSON-RPC 2.0 requests to the gateway's virtual server endpoint
with the required OBO headers.
"""
import json
import requests
from typing import Any


class MCPClient:
    def __init__(
        self,
        gateway_url: str,
        gateway_token: str,
        virtual_server_id: str,
        user_token: str,
        agent_name: str,
    ):
        self.endpoint = f"{gateway_url.rstrip('/')}/servers/{virtual_server_id}/mcp"
        self.headers = {
            "Authorization": f"Bearer {gateway_token}",
            "x-user-token": f"Bearer {user_token}",
            "X-Agent-Token": agent_name,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        self._call_id = 0

    def _next_id(self) -> int:
        self._call_id += 1
        return self._call_id

    def list_tools(self) -> list[dict]:
        """Get the list of available MCP tools from the gateway."""
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/list",
        }
        resp = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        if "error" in result:
            raise RuntimeError(f"MCP error: {result['error']}")
        return result.get("result", {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any] = None) -> Any:
        """Call a specific MCP tool and return the result."""
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments or {},
            },
        }
        resp = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        if "error" in result:
            raise RuntimeError(f"MCP error: {result['error']['message']}")
        content = result.get("result", {})
        if content.get("isError"):
            raise RuntimeError(f"Tool error: {content}")
        # Parse the text content
        items = content.get("content", [])
        if items and items[0].get("type") == "text":
            try:
                return json.loads(items[0]["text"])
            except json.JSONDecodeError:
                return items[0]["text"]
        return content
