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
        warden_url: str = "",
        warden_vs_id: str = "",
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
        self._warden_url = warden_url.rstrip("/") if warden_url else ""
        self._warden_vs_id = warden_vs_id

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

    def scan(self, text: str, direction: str) -> dict:
        """Run text through the Warden interceptor pipeline.

        direction: 'inbound'  = user message heading to the agent
                   'outbound' = agent reply heading back to the user

        Returns the pipeline result dict:
          { action: 'allow'|'block'|'mask'|'warn', text: str, reason: str|None }
        Falls back to allow if Warden is not configured or unreachable.
        """
        if not self._warden_url or not self._warden_vs_id:
            return {"action": "allow", "text": text, "reason": None}
        url = f"{self._warden_url}/api/interceptors/{self._warden_vs_id}/scan"
        try:
            resp = requests.post(
                url,
                json={"text": text, "direction": direction},
                timeout=5,
            )
            resp.raise_for_status()
            result = resp.json()
            # Ensure 'text' key is always present for callers to use the (possibly masked) version
            if "text" not in result:
                result["text"] = text
            return result
        except Exception as exc:
            print(f"[Interceptor] Scan failed ({exc}), continuing.")
            return {"action": "allow", "text": text, "reason": None}
