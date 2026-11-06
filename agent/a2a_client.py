"""
A2A (Agent2Agent 1.0) client for calling other agents THROUGH the Warden gateway.

The agent never talks to the remote agent directly and never holds its credentials:
Warden authenticates this agent (X-Agent-Token), enforces A2A policy, scans the message and the
response, and forwards the call with its own signed delegation token.
"""
import uuid
from typing import Any, Optional

import requests

A2A_VERSION = "1.0"


class A2AError(Exception):
    """Raised for gateway/agent errors (policy denial, auth failure, target down, ...)."""

    def __init__(self, message: str, code: Optional[int] = None, http_status: Optional[int] = None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class A2AClient:
    def __init__(self, warden_url: str, vs_id: str, target_id: str, agent_token: str, user_token: str = ""):
        self.endpoint = f"{warden_url.rstrip('/')}/a2a/{vs_id}/{target_id}"
        self.headers = {
            "Content-Type": "application/json",
            "A2A-Version": A2A_VERSION,
            "X-Agent-Token": agent_token,
        }
        # Optional: lets Warden verify and propagate the end user's identity to the target agent.
        if user_token:
            self.headers["X-User-Token"] = f"Bearer {user_token}"
        self.context_id = str(uuid.uuid4())  # one A2A conversation per agent session

    def get_card(self) -> dict:
        """The gateway's Agent Card for the target (its interface points at Warden)."""
        try:
            r = requests.get(f"{self.endpoint}/.well-known/agent-card.json", timeout=10)
            r.raise_for_status()
            return r.json()
        except requests.RequestException as exc:
            raise A2AError(f"Could not fetch the agent card from Warden: {exc}")

    def send_message(self, text: str, skill_id: Optional[str] = None) -> dict:
        """
        A2A SendMessage. Returns {state, task_id, text, data}.
        Raises A2AError with the gateway's reason on denial / failure.
        """
        message: dict[str, Any] = {
            "messageId": str(uuid.uuid4()),
            "contextId": self.context_id,
            "role": "ROLE_USER",
            "parts": [{"text": text}],
        }
        params: dict[str, Any] = {"message": message}
        if skill_id:
            params["metadata"] = {"skillId": skill_id}

        body = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "SendMessage", "params": params}
        try:
            r = requests.post(self.endpoint, json=body, headers=self.headers, timeout=90)
        except requests.RequestException as exc:
            raise A2AError(f"Could not reach the Warden gateway: {exc}")

        try:
            payload = r.json()
        except ValueError:
            raise A2AError(f"Gateway returned a non-JSON response (HTTP {r.status_code})", http_status=r.status_code)

        if "error" in payload:
            err = payload["error"]
            detail = err.get("data", {}).get("reason") if isinstance(err.get("data"), dict) else None
            raise A2AError(err.get("message", "A2A error") + (f" ({detail})" if detail else ""),
                           code=err.get("code"), http_status=r.status_code)

        result = payload.get("result", {})
        task = result.get("task") or result.get("message") or {}
        state = (task.get("status") or {}).get("state", "TASK_STATE_COMPLETED")
        texts, data = [], []
        for artifact in task.get("artifacts", []):
            for part in artifact.get("parts", []):
                if "text" in part:
                    texts.append(part["text"])
                if "data" in part:
                    data.append(part["data"])
        for part in task.get("parts", []):  # a direct Message reply
            if "text" in part:
                texts.append(part["text"])
        status_msg = ((task.get("status") or {}).get("message") or {}).get("parts", [])
        failure = " ".join(p.get("text", "") for p in status_msg)

        if state in ("TASK_STATE_FAILED", "TASK_STATE_REJECTED", "TASK_STATE_CANCELED"):
            raise A2AError(failure or f"The remote agent ended the task as {state}")
        return {"state": state, "task_id": task.get("id"), "text": "\n".join(texts), "data": data}
