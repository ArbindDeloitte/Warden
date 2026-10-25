"""Test PointGuard MCP gateway with user Okta token (OBO handled by PointGuard)."""
import json, sys, getpass
import requests
from dotenv import load_dotenv
import os

load_dotenv()

GW_URL  = os.environ.get("PG_GATEWAY_URL", "").rstrip("/")
VS_ID   = os.environ.get("PG_VIRTUAL_SERVER_ID", "")
MCP_URL = f"{GW_URL}/servers/{VS_ID}/mcp"

print(f"MCP endpoint: {MCP_URL}")
print()

user_token = input("Paste your Okta user access token (from SecureBank Dev Tools): ").strip()
if not user_token:
    print("No token provided.")
    sys.exit(1)

headers = {
    "Authorization": f"Bearer {user_token}",
    "Content-Type":  "application/json",
    "Accept":        "application/json, text/event-stream",
}

def mcp_call(method, params=None, session_id=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params:
        body["params"] = params
    h = dict(headers)
    if session_id:
        h["mcp-session-id"] = session_id
    r = requests.post(MCP_URL, headers=h, json=body, timeout=20)
    return r

# Step 1: initialize
print("Step 1: initialize ...")
r1 = mcp_call("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "banking-agent", "version": "1"},
})
print(f"  Status: {r1.status_code}")
if r1.status_code != 200:
    print(f"  Body: {r1.text[:400]}")
    sys.exit(1)

session_id = r1.headers.get("mcp-session-id")
print(f"  Session ID: {session_id}")
data = r1.json()
if "error" in data:
    print(f"  Error: {data['error']}")
    sys.exit(1)
print(f"  Server: {data.get('result', {}).get('serverInfo', {})}")

# Step 2: initialized notification
print("\nStep 2: initialized notification ...")
body = {"jsonrpc": "2.0", "method": "notifications/initialized"}
h2 = dict(headers)
if session_id:
    h2["mcp-session-id"] = session_id
r2 = requests.post(MCP_URL, headers=h2, json=body, timeout=10)
print(f"  Status: {r2.status_code}")

# Step 3: tools/list
print("\nStep 3: tools/list ...")
r3 = mcp_call("tools/list", session_id=session_id)
print(f"  Status: {r3.status_code}")
if r3.status_code != 200:
    print(f"  Body: {r3.text[:400]}")
    sys.exit(1)

data3 = r3.json()
if "error" in data3:
    print(f"  Error: {data3['error']}")
    sys.exit(1)

tools = data3.get("result", {}).get("tools", [])
print(f"\nSUCCESS — {len(tools)} tools available via PointGuard:")
for t in tools:
    print(f"  • {t['name']}")
