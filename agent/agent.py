#!/usr/bin/env python3
"""
Banking Agent — Claude-powered conversational agent.

Uses Claude (via AWS Bedrock) as the LLM brain, with PointGuardAI MCP Gateway
tools for OBO-delegated banking operations.  Just type naturally.

Usage:
    pip install -r requirements.txt
    cp .env.example .env   # fill in your values
    python agent.py
"""
import json
import os
import sys
import textwrap
from datetime import datetime

import anthropic
from dotenv import load_dotenv

load_dotenv()

# ── ANSI colour helpers ───────────────────────────────────────────────────────
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_GREY   = "\033[90m"

def _c(text, *codes): return "".join(codes) + str(text) + _RESET
def _bold(t):   return _c(t, _BOLD)
def _dim(t):    return _c(t, _DIM)
def _cyan(t):   return _c(t, _BOLD, _CYAN)
def _green(t):  return _c(t, _GREEN)
def _yellow(t): return _c(t, _YELLOW)
def _grey(t):   return _c(t, _GREY)


# ── User-token helpers ────────────────────────────────────────────────────────

def _get_user_token() -> str:
    """Return the user Okta access token, acquiring it if necessary."""
    token = os.environ.get("USER_TOKEN", "").strip()
    if token:
        return token

    print("\nNo USER_TOKEN found in environment.")
    client_id = os.environ.get("OKTA_CLIENT_ID", "").strip()
    issuer    = os.environ.get("OKTA_ISSUER", "").strip()

    choices = []
    if client_id and issuer:
        choices.append(("1", "Open browser (Okta PKCE login) — automatic"))
    choices.append(("2" if choices else "1", "Paste token manually"))

    print("How would you like to authenticate?\n")
    for key, label in choices:
        print(f"  {key}. {label}")

    choice = input("\nChoice: ").strip()

    if choices and choices[0][0] == "1" and choice == "1":
        from token_helper import get_access_token_via_pkce
        port = int(os.environ.get("OKTA_REDIRECT_PORT", "8765"))
        scopes = [
            "accounts:read", "accounts:balance:read",
            "accounts:transactions:read", "accounts:statements:read",
            "payments:read", "payments:initiate", "payments:approve",
            "standing-orders:manage", "transfers:external:create",
        ]
        token = get_access_token_via_pkce(issuer, client_id, scopes, port)
        print("Token acquired via PKCE.\n")
        return token
    else:
        print("\nPaste your Okta access token then press Enter:\n")
        token = input().strip()
        if not token:
            print("No token provided. Exiting.")
            sys.exit(1)
        return token


def _decode_sub(token: str) -> str:
    """Best-effort: decode the sub/email from the JWT payload (no verification)."""
    try:
        import base64
        parts = token.split(".")
        if len(parts) >= 2:
            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
            return (
                payload.get("email")
                or payload.get("preferred_username")
                or payload.get("sub")
                or "authenticated user"
            )
    except Exception:
        pass
    return "authenticated user"


# ── Banner ────────────────────────────────────────────────────────────────────

def _banner(user_label: str, model: str) -> str:
    return (
        f"\n{'═' * 56}\n"
        f"   {_bold('SecureBank AI Agent')}  ·  powered by Claude\n"
        f"   Operating as : {_cyan(user_label)}\n"
        f"   Model        : {_dim(model)}\n"
        f"{'═' * 56}\n"
        f"  Type your request in plain English.\n"
        f"  Commands: {_dim('exit')} / {_dim('quit')} — end session  ·  {_dim('clear')} — new conversation\n"
    )


# ── MCP → Anthropic tool-format converter ─────────────────────────────────────

def _mcp_tools_to_anthropic(mcp_tools: list[dict]) -> list[dict]:
    """Convert MCP tool definitions to the format Anthropic's API expects."""
    result = []
    for t in mcp_tools:
        schema = t.get("inputSchema") or {"type": "object", "properties": {}}
        result.append({
            "name": t["name"],
            "description": t.get("description", ""),
            "input_schema": schema,
        })
    return result


# ── Agentic loop ──────────────────────────────────────────────────────────────

# ── A2A: calling other agents through Warden ──────────────────────────────────

A2A_TOOL_NAME = "ask_credit_card_agent"


def _a2a_tool_from_card(card: dict) -> dict:
    """Build an Anthropic tool definition from the remote agent's (gateway) Agent Card."""
    skills = card.get("skills", [])
    skill_lines = "\n".join(f"- {s['id']}: {s.get('description', s.get('name', ''))}" for s in skills)
    return {
        "name": A2A_TOOL_NAME,
        "description": (
            f"Ask the '{card.get('name', 'remote')}' agent (a separate agent, reached over the A2A protocol "
            f"through the Warden gateway). {card.get('description', '')}\n"
            f"Use this for anything about the user's CREDIT CARDS (limits, balances, due dates, rewards, "
            f"card transactions, freezing a card). Bank accounts and transfers use the other tools.\n"
            f"Skills:\n{skill_lines}"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {"type": "string", "description": "Natural-language request for the credit card agent."},
                "skill_id": {"type": "string", "enum": [s["id"] for s in skills],
                             "description": "Optional: the specific skill to invoke."},
            },
            "required": ["question"],
        },
    }


def _call_a2a(a2a_client, tool_input: dict) -> str:
    from a2a_client import A2AError
    print(_grey("  >>  A2A call to credit-card-agent (via Warden gateway)"))
    try:
        res = a2a_client.send_message(tool_input.get("question", ""), tool_input.get("skill_id"))
    except A2AError as exc:
        print(_yellow(f"  !!  A2A call refused/failed: {exc}"))
        return f"Error: the A2A call did not succeed — {exc}"
    print(_grey(f"  OK  A2A task {res['task_id']} -> {res['state']}"))
    return json.dumps({"summary": res["text"], "details": res["data"]}, ensure_ascii=False)


def _run_turn(
    anthropic_client: anthropic.Anthropic,
    model: str,
    system: str,
    messages: list[dict],
    tools: list[dict],
    mcp_client,
    a2a_client=None,
) -> str:
    """
    Run a single user turn: call Claude, execute any tool calls, loop until
    the model stops with 'end_turn'.  Returns the final assistant text.
    """
    while True:
        response = anthropic_client.messages.create(
            model=model,
            max_tokens=4096,
            system=system,
            tools=tools,
            messages=messages,
        )

        # Append raw assistant blocks to history
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            # Collect and return all text blocks
            return "\n".join(
                b.text for b in response.content if hasattr(b, "text")
            )

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type != "tool_use":
                    continue

                print(_grey(f"\n  ⚙  {block.name}({json.dumps(block.input, separators=(',', ':'))})"))

                if a2a_client is not None and block.name == A2A_TOOL_NAME:
                    out = _call_a2a(a2a_client, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": out,
                        **({"is_error": True} if out.startswith("Error:") else {}),
                    })
                    continue

                try:
                    result = mcp_client.call_tool(block.name, block.input)
                    content = json.dumps(result, ensure_ascii=False)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": content,
                    })
                except Exception as exc:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": f"Error: {exc}",
                        "is_error": True,
                    })

            messages.append({"role": "user", "content": tool_results})

        else:
            # Unexpected stop reason — surface the raw text and break
            texts = [b.text for b in response.content if hasattr(b, "text")]
            return "\n".join(texts) if texts else f"[stop_reason={response.stop_reason}]"


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are SecureBank's AI banking assistant.  The user has already authenticated
via Okta and you have access to their accounts through a secure MCP gateway.

Your job is to help users with their banking needs by calling the available MCP
tools and presenting results in a clear, friendly way.

Guidelines:
- Use tools proactively — don't ask the user to provide IDs you can look up yourself
  (e.g. if they say "check my balance", list_accounts first then get the balance).
- Format currency values neatly (e.g. $1,234.56).
- Format dates as "Oct 7, 2026" style.
- For tables, use a clean text layout.
- Never expose raw JSON to the user — always summarise results conversationally.
- Keep responses concise.  If there are many items, show the most relevant ones.
- For destructive actions (payments, transfers), always confirm the key details
  before calling the tool, and confirm success or failure afterwards.
- Never fabricate data — if a tool returns no results, say so clearly.
"""


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # ── 1. Validate gateway env vars ─────────────────────────────────────────
    gateway_url       = os.environ.get("PG_GATEWAY_URL", "").strip()
    gateway_token     = os.environ.get("PG_GATEWAY_TOKEN", "").strip()
    virtual_server_id = os.environ.get("PG_VIRTUAL_SERVER_ID", "").strip()
    agent_name        = os.environ.get("PG_AGENT_NAME", "banking-agent").strip()
    warden_url        = os.environ.get("WARDEN_URL", "http://localhost:3003").strip()
    warden_vs_id      = os.environ.get("WARDEN_VS_ID", "").strip()

    missing = [v for v, val in [
        ("PG_GATEWAY_URL", gateway_url),
        ("PG_GATEWAY_TOKEN", gateway_token),
        ("PG_VIRTUAL_SERVER_ID", virtual_server_id),
    ] if not val]
    if missing:
        print("\nERROR: Missing required environment variables:")
        for v in missing: print(f"  - {v}")
        print("\nCopy .env.example to .env and fill in the values.")
        sys.exit(1)

    # ── 2. Validate Anthropic / Bedrock env vars ──────────────────────────────
    anthropic_key     = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    anthropic_base    = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    model             = os.environ.get("AGENT_MODEL_ID",
                                       "us.anthropic.claude-3-5-sonnet-20241022-v2:0").strip()

    if not anthropic_key:
        print("\nERROR: ANTHROPIC_API_KEY is not set.")
        print("Add it to your .env file (see .env.example).")
        sys.exit(1)

    # ── 3. Acquire user token & build display name ────────────────────────────
    user_token  = _get_user_token()
    user_label  = _decode_sub(user_token)

    # ── 4. Initialise clients ─────────────────────────────────────────────────
    from mcp_client import MCPClient

    mcp = MCPClient(
        gateway_url=gateway_url,
        gateway_token=gateway_token,
        virtual_server_id=virtual_server_id,
        user_token=user_token,
        agent_name=agent_name,
        warden_url=warden_url,
        warden_vs_id=warden_vs_id,
    )

    kwargs = {"api_key": anthropic_key}
    if anthropic_base:
        kwargs["base_url"] = anthropic_base

    llm = anthropic.Anthropic(**kwargs)

    # ── 5. Fetch available MCP tools ──────────────────────────────────────────
    print("\nConnecting to MCP gateway…", end=" ", flush=True)
    try:
        mcp_tools  = mcp.list_tools()
        anth_tools = _mcp_tools_to_anthropic(mcp_tools)
        print(_green(f"OK  ({len(anth_tools)} tools available)"))
    except Exception as exc:
        print(f"\nFailed to fetch tools: {exc}")
        sys.exit(1)

    # ── 5b. Optional A2A: expose the credit card agent as a tool ──────────────
    a2a = None
    a2a_vs     = os.environ.get("WARDEN_A2A_VS_ID", "").strip()
    a2a_target = os.environ.get("WARDEN_A2A_TARGET_ID", "").strip()
    a2a_token  = os.environ.get("WARDEN_A2A_AGENT_TOKEN", "").strip()
    system_prompt = SYSTEM_PROMPT
    if a2a_vs and a2a_target and a2a_token:
        from a2a_client import A2AClient, A2AError
        try:
            a2a = A2AClient(warden_url, a2a_vs, a2a_target, a2a_token, user_token)
            anth_tools.append(_a2a_tool_from_card(a2a.get_card()))
            system_prompt += (
                "\nCredit card questions are handled by a separate specialist agent. Use the "
                f"{A2A_TOOL_NAME} tool for them (it runs over the A2A protocol via the Warden gateway). "
                "If it reports that access was denied by policy, tell the user plainly that this action "
                "is not permitted for you — do not retry or look for a workaround.\n"
            )
            print(_green(f"A2A enabled: credit-card-agent via Warden (+1 tool)"))
        except A2AError as exc:
            a2a = None
            print(_yellow(f"A2A disabled — {exc}"))

    # ── 6. Start chat ─────────────────────────────────────────────────────────
    print(_banner(user_label, model))

    messages: list[dict] = []

    while True:
        try:
            user_input = input(_bold("You: ")).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\nGoodbye!\n")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit", "bye", "q"):
            print("\nGoodbye!\n")
            break

        if user_input.lower() == "clear":
            messages = []
            print(_grey("  Conversation cleared.\n"))
            continue

        # ── Inbound scan: user message → agent ───────────────────────────────
        inbound = mcp.scan(user_input, "inbound")
        if inbound.get("action") == "block":
            print(_yellow(f"\n  [Interceptor] Message blocked: {inbound.get('reason') or 'policy violation'}\n"))
            continue
        # Use masked text if the pipeline redacted anything
        safe_input = inbound.get("text") or user_input

        messages.append({"role": "user", "content": safe_input})

        try:
            reply = _run_turn(llm, model, system_prompt, messages, anth_tools, mcp, a2a)
        except anthropic.APIStatusError as exc:
            print(_yellow(f"\n  API error {exc.status_code}: {exc.message}\n"))
            messages.pop()   # remove the user turn that failed
            continue
        except Exception as exc:
            print(_yellow(f"\n  Error: {exc}\n"))
            messages.pop()
            continue

        # ── Outbound scan: agent response → user ─────────────────────────────
        outbound = mcp.scan(reply, "outbound")
        if outbound.get("action") == "block":
            reply = "[Response blocked by security policy]"
        else:
            # Use masked version if the pipeline redacted anything
            reply = outbound.get("text") or reply

        # Wrap long lines for readability
        wrapped = "\n".join(
            textwrap.fill(line, width=80, subsequent_indent="  ") if len(line) > 80 else line
            for line in reply.splitlines()
        )
        print(f"\n{_bold('Assistant:')} {wrapped}\n")


if __name__ == "__main__":
    main()
