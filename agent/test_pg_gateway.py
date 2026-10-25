"""
Test the PointGuard MCP gateway directly.

Usage:
  python test_pg_gateway.py              # uses PG_ADMIN_TOKEN in Authorization
  python test_pg_gateway.py --user       # prompts for user Okta token too
"""
import json
import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv()

GW_URL = os.environ.get("PG_GATEWAY_URL", "").rstrip("/")
VS_ID  = os.environ.get("PG_VIRTUAL_SERVER_ID", "")
GW_TOKEN = os.environ.get("PG_ADMIN_TOKEN", "")
AGENT_NAME = os.environ.get("PG_AGENT_NAME", "banking-agent")

MCP_URL = f"{GW_URL}/servers/{VS_ID}/mcp"

print(f"Gateway URL : {GW_URL}")
print(f"Virtual Server: {VS_ID}")
print(f"MCP endpoint: {MCP_URL}")
print(f"GW token present: {'YES' if GW_TOKEN else 'NO'}")
print()

user_token = None
if "--user" in sys.argv:
    user_token = input("Paste your Okta user access token: ").strip() or None

# Build headers per PointGuard documentation:
#   Authorization: Bearer <GW_TOKEN>   — gateway API token (authenticates the agent)
#   x-user-token: Bearer <USER_TOKEN>  — user Okta token (PointGuard does OBO)
#   X-Agent-Token: <agent_name>        — agent identifier
headers = {
    "Authorization": f"Bearer {GW_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
if user_token:
    headers["x-user-token"] = f"Bearer {user_token}"
    headers["X-Agent-Token"] = AGENT_NAME

print("Headers sent:")
for k, v in headers.items():
    display = v if len(v) < 60 else v[:40] + "…" + v[-10:]
    print(f"  {k}: {display}")
print()


def mcp_post(method, params=None, session_id=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params:
        body["params"] = params
    h = dict(headers)
    if session_id:
        h["mcp-session-id"] = session_id
    try:
        r = requests.post(MCP_URL, headers=h, json=body, timeout=20)
        return r
    except requests.exceptions.ConnectionError as e:
        print(f"  Connection error: {e}")
        return None
    except requests.exceptions.Timeout:
        print("  Timeout after 20s")
        return None


def show(r, label):
    if r is None:
        return
    print(f"  Status : {r.status_code}")
    print(f"  Headers: {dict(r.headers)}")
    try:
        body = r.json()
        print(f"  Body   : {json.dumps(body, indent=2)[:800]}")
    except Exception:
        print(f"  Body   : {r.text[:800]}")
    print()


# ── Step 1: initialize ────────────────────────────────────────────────────────
print("=== Step 1: initialize ===")
r1 = mcp_post("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": AGENT_NAME, "version": "1"},
})
show(r1, "initialize")

if r1 is None or r1.status_code != 200:
    print("Initialize failed — trying tools/list directly (some gateways are stateless).")
    print()

    # ── Stateless attempt: direct tools/list ─────────────────────────────────
    print("=== Stateless: tools/list ===")
    r_tl = mcp_post("tools/list")
    show(r_tl, "tools/list")
    sys.exit(0)

session_id = r1.headers.get("mcp-session-id")
print(f"  Session ID: {session_id}")

# ── Step 2: initialized notification ─────────────────────────────────────────
print("=== Step 2: initialized notification ===")
h2 = dict(headers)
if session_id:
    h2["mcp-session-id"] = session_id
r2 = requests.post(MCP_URL, headers=h2,
                   json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                   timeout=10)
show(r2, "initialized")

# ── Step 3: tools/list ───────────────────────────────────────────────────────
print("=== Step 3: tools/list ===")
r3 = mcp_post("tools/list", session_id=session_id)
show(r3, "tools/list")

if r3 and r3.status_code == 200:
    try:
        tools = r3.json().get("result", {}).get("tools", [])
        print(f"SUCCESS — {len(tools)} tools via PointGuard gateway:")
        for t in tools:
            print(f"  • {t['name']}")
    except Exception as e:
        print(f"Could not parse tools: {e}")
