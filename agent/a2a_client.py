"""
A2A (Agent2Agent 1.0 and 0.3) client for calling other agents THROUGH the Warden gateway.

The agent never talks to the remote agent directly and never holds its credentials:
Warden authenticates this agent (X-Agent-Token), enforces A2A policy, scans the message and the
response, and forwards the call with its own signed delegation token.

Each agent registered in Warden speaks ONE A2A version (shown in Warden > A2A Agents), and its gateway
endpoint speaks that same version. Pass the matching `version` ("1.0" or "0.3"), otherwise Warden answers
"method not found" and says which version the agent speaks.

Approval policies: a call that Warden holds for human approval raises A2AApprovalRequired (it carries the ticket).
Pass wait_for_approval=<seconds> to send_message, or call wait_for_approval(), to block until an admin decides;
the approved call is then forwarded by Warden and its result is returned like any other reply.
"""
import time
import uuid
from typing import Any, Optional

import requests

A2A_VERSION = "1.0"
SUPPORTED_VERSIONS = ("1.0", "0.3")


class A2AError(Exception):
    """Raised for gateway/agent errors (policy denial, auth failure, target down, ...)."""

    def __init__(self, message: str, code: Optional[int] = None, http_status: Optional[int] = None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class A2AApprovalRequired(A2AError):
    """Warden is holding the call until an admin approves or denies it (A2A approval policy)."""

    def __init__(self, message: str, ticket_id: str, poll_url: str, expires_at: Optional[str] = None,
                 timeout_action: Optional[str] = None, http_status: Optional[int] = None):
        super().__init__(message, code=-32011, http_status=http_status)
        self.ticket_id = ticket_id
        self.poll_url = poll_url
        self.expires_at = expires_at
        self.timeout_action = timeout_action


class A2AClient:
    def __init__(self, warden_url: str, vs_id: str, target_id: str, agent_token: str, user_token: str = "",
                 version: str = A2A_VERSION):
        if version not in SUPPORTED_VERSIONS:
            raise ValueError(f"version must be one of {SUPPORTED_VERSIONS}")
        self.version = version
        self.warden_url = warden_url.rstrip("/")
        self.endpoint = f"{self.warden_url}/a2a/{vs_id}/{target_id}"
        self.headers = {
            "Content-Type": "application/json",
            "X-Agent-Token": agent_token,
        }
        if version == "1.0":  # A2A 0.3 has no A2A-Version header
            self.headers["A2A-Version"] = A2A_VERSION
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

    def send_message(self, text: str, skill_id: Optional[str] = None, wait_for_approval: float = 0) -> dict:
        """
        A2A SendMessage. Returns {state, task_id, text, data}.
        Raises A2AError with the gateway's reason on denial / failure, and A2AApprovalRequired when an approval
        policy holds the call (unless wait_for_approval > 0: then it waits that many seconds for the decision).
        """
        v03 = self.version == "0.3"
        message: dict[str, Any] = {
            "messageId": str(uuid.uuid4()),
            "contextId": self.context_id,
            "role": "user" if v03 else "ROLE_USER",
            "parts": [{"kind": "text", "text": text}] if v03 else [{"text": text}],
        }
        if v03:
            message["kind"] = "message"
        params: dict[str, Any] = {"message": message}
        if skill_id:
            params["metadata"] = {"skillId": skill_id}

        body = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "message/send" if v03 else "SendMessage", "params": params}
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
            data_ = err.get("data") if isinstance(err.get("data"), dict) else {}
            detail = data_.get("reason")
            if err.get("code") == -32011 and data_.get("ticket_id"):
                pending = A2AApprovalRequired(err.get("message", "Approval required") + (f" ({detail})" if detail else ""),
                                              ticket_id=data_["ticket_id"], poll_url=data_.get("poll_url", ""),
                                              expires_at=data_.get("expires_at"), timeout_action=data_.get("timeout_action"),
                                              http_status=r.status_code)
                if wait_for_approval and wait_for_approval > 0:
                    return self.wait_for_approval(pending, timeout=wait_for_approval)
                raise pending
            raise A2AError(err.get("message", "A2A error") + (f" ({detail})" if detail else ""),
                           code=err.get("code"), http_status=r.status_code)

        return self._normalise(payload.get("result", {}))

    def wait_for_approval(self, approval: "A2AApprovalRequired", timeout: float = 300, interval: float = 2) -> dict:
        """
        Polls the approval ticket until an admin decides, then returns the approved call's result (same shape as
        send_message). Raises A2AError if it is denied, expires, fails to execute, or this wait times out
        (the ticket stays valid: you can call this again with the same A2AApprovalRequired).
        """
        url = f"{self.warden_url}/api/approvals/{approval.ticket_id}/status"
        deadline = time.time() + timeout
        while True:
            try:
                r = requests.get(url, timeout=15)
                body = r.json()
            except (requests.RequestException, ValueError) as exc:
                raise A2AError(f"Could not read the approval ticket: {exc}")
            status = body.get("status")
            if status == "executed" and body.get("result") is not None:
                return self._normalise(body["result"])
            if r.status_code >= 400:  # denied, expired, or the approved call failed
                raise A2AError(body.get("error") or f"Approval ticket ended as {status}", http_status=r.status_code)
            if time.time() >= deadline:
                raise A2AError(f"Still waiting for approval after {timeout:g}s (ticket {approval.ticket_id})")
            time.sleep(interval)

    def _normalise(self, result: dict) -> dict:
        v03 = self.version == "0.3"
        # 1.0 wraps the reply ({"task": ...} / {"message": ...}); 0.3 returns a bare Task or Message.
        task = result if v03 else (result.get("task") or result.get("message") or {})
        state = (task.get("status") or {}).get("state", "completed" if v03 else "TASK_STATE_COMPLETED")
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

        if state in ("TASK_STATE_FAILED", "TASK_STATE_REJECTED", "TASK_STATE_CANCELED", "failed", "rejected", "canceled"):
            raise A2AError(failure or f"The remote agent ended the task as {state}")
        return {"state": state, "task_id": task.get("id"), "text": "\n".join(texts), "data": data}
