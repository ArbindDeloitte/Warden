# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecureBank is a full-stack banking application that demonstrates **OAuth 2.0 On-Behalf-Of (OBO) token exchange**. An AI agent operates on behalf of a signed-in user, with the MCP Gateway performing the token exchange so the agent never holds user credentials directly.

## Components & Ports

| Component | Directory | Port | Runtime |
|---|---|---|---|
| Banking Backend + MCP Server | `banking-app/backend/` | 3001 | Node.js 22.5+ (ESM) |
| Banking Frontend | `banking-app/frontend/` | 5173 | React + Vite |
| Warden MCP Gateway | `mcp-virtual-server/` | 3003 | Node.js (CJS) |
| Local PII Analyzer | `presidio-server/` | 5001 | Python (waitress) |
| Python Agent | `agent/` | — | Python 3.11+ |

## Commands

### Banking Backend
```bash
cd banking-app/backend
npm install
npm start          # production
npm run dev        # watch mode (node --watch)
```

### Banking Frontend
```bash
cd banking-app/frontend
npm install
npm run dev        # Vite dev server → http://localhost:5173
npm run build
```

### MCP Virtual Server
```bash
cd mcp-virtual-server
npm install
npm start          # production
npm run dev        # watch mode
```

### Python Agent
```bash
cd agent
pip install -r requirements.txt
cp .env.example .env   # fill in PG_GATEWAY_URL, PG_GATEWAY_TOKEN, PG_VIRTUAL_SERVER_ID, ANTHROPIC_API_KEY
python agent.py
```

### Utility Scripts (agent/)
```bash
python test_mcp.py        # test raw MCP tool calls through the gateway
python test_pg_gateway.py # test PointGuardAI gateway connectivity
python test_llm.py        # test Anthropic API connectivity
python probe_gateway.py   # inspect gateway state
```

## Architecture & Key Flows

### Token Flow (OBO)
```
User → React Frontend (Okta PKCE) → Banking REST API (port 3001)
                                          ↑ verifies JWT against Okta JWKS
Agent → MCP Gateway → Okta OBO exchange → Banking MCP endpoint (/mcp on 3001)
```

1. Frontend authenticates via Okta Authorization Code + PKCE; token audience is `api://banking`.
2. Agent acquires a user token (PKCE via `token_helper.py` or manual paste).
3. Agent sends MCP tool calls with three headers: `Authorization: Bearer <gateway_token>`, `x-user-token: Bearer <user_token>`, `X-Agent-Token: <agent_name>`.
4. The gateway (PointGuardAI or `mcp-virtual-server`) performs RFC 8693 token exchange against Okta, yielding an OBO token scoped to `api://banking-mcp`.
5. Banking MCP server at `POST /mcp` decodes the OBO JWT (no crypto verification — gateway is the trust boundary) and calls `getOrCreateUser(db, sub)` to bind the session to the correct user.
6. REST routes at `/api/*` do full Okta JWT verification via `@okta/jwt-verifier`.

### Dual Security Model
The backend has **two auth paths** that must be understood together:
- **REST API** (`/api/*`): uses `verifyToken` middleware in `src/middleware/auth.js` — full Okta JWKS verification, extracts `req.user` with `sub`, `email`, `groups`, `scp`.
- **MCP endpoint** (`/mcp`): trusts the gateway as a trust boundary; only decodes the JWT payload (base64, no signature check) to get `sub`/`email`/`name` and calls `getOrCreateUser`.

Adding a new scope-protected REST route: apply `verifyToken` then `requireScope('scope:name')` middleware.

### MCP Server Architecture
`banking-app/backend/src/mcp/server.js` uses `createMcpServer(userId, db)` — the user ID and DB reference are closed over in each tool handler. Every tool operates strictly on the authenticated user's data. Sessions are held in a `Map<sessionId, {transport}>` with 30-minute auto-expiry. The `enableJsonResponse: true` option on `StreamableHTTPServerTransport` makes the gateway's non-SSE `Accept` header work transparently.

### MCP Virtual Server / Warden (Custom Gateway)
`mcp-virtual-server/` is a self-hosted MCP gateway ("Warden"). It implements:
- **MCP registry**: upstream MCP server registrations (`/api/mcp`)
- **Virtual servers**: named routing contexts (`/api/virtual-servers`)
- **Cedar-style policy engine** (`src/services/policyEngine.js`): deny-by-default, priority-ordered permit/forbid policies evaluated against `{mcpServerId, toolName, scopes, groups, sub}`
- **OBO service** (`src/services/oboService.js`): RFC 8693 token exchange with Redis-backed caching (`src/services/tokenCache.js`)
- **Bidirectional interceptor pipeline** (`src/interceptors/`): scans inbound tool arguments and outbound MCP responses before they reach the LLM or caller
- **Audit log**: every proxied call is recorded
- Persistence: SQLite via `src/db/database.js`; the gateway state (servers, virtual servers, policies) survives restarts

### Interceptor Pipeline
`src/interceptors/InterceptorPipeline.js` runs all enabled scanners and passes results to `ActionEngine.js`:

- **`RegexScanner`** (`scanners/RegexScanner.js`): in-process pattern matching for SSN, IBAN, credit cards, email, phone numbers, and prompt injection phrases. Runs synchronously, <1 ms.
- **`PresidioScanner`** (`scanners/PresidioScanner.js`): calls `http://localhost:5001/analyze` (the local `presidio-server/server.py`). Uses regex engine; extensible to spaCy NER on Python 3.11/3.12.
- **`ActionEngine`** (`ActionEngine.js`): evaluates scanner results against priority-ordered rules stored in `interceptor_rules` table. Actions: `block` (403), `mask` (replace matched spans), `warn` (pass + log), `allow`.

**Critical — `applyMasks` deduplication**: matches are sorted by start position DESC and applied back-to-front. A `processedStart` guard skips any match whose `end > processedStart` to prevent double-replacement when both scanners detect the same span (e.g., IBAN detected by RegexScanner AND PresidioScanner at identical offsets).

**Outbound masking**: `proxy.js` extracts `result.result.content[].text` items, joins them with `\n\n---\n\n`, scans the combined string, then re-injects masked text back into the content array via `injectMcpTextItems`. Never scan raw `JSON.stringify(result)` — replacements inside JSON string values corrupt the JSON structure.

### Warden admin security
- **Admin authentication** (`middleware/adminAuth.js`): when `WARDEN_ADMIN_TOKEN` is set (in `mcp-virtual-server/.env`; `npm run admin-token` creates/rotates it without printing it), everything under `/api` needs it as `X-Admin-Token`, `Authorization: Bearer <token>`, or the session cookie from `POST /api/auth/login` (HttpOnly, SameSite=Strict, 12 h, HMAC-signed and bound to the token, so rotating the token ends every session; the Warden UI shows a sign-in screen). Failed logins are throttled (10 per 10 min per address, then 429). **Unset = open mode** (the old behaviour, with a loud startup warning); there is deliberately no default token.
- **Exempt data-plane routes** (they authenticate themselves): `/api/proxy/*` (API key + agent token + user token), `/api/vault/{checkout,sign,validate}` (agent token), `/api/health`, and — requiring an agent token (+ the VS's API key) in secure mode — `POST /api/interceptors/:vs/scan` and `GET /api/approvals/:id/status` (a caller sees only its own tickets; others look nonexistent). `/a2a/*` and `/.well-known/*` are not under `/api`. A test sweep (`scripts/test-admin-security.js`) walks every registered route and fails if a non-exempt one answers without credentials, so a newly added route can't be left open by accident.
- **User-token audience/issuer** (`virtual_servers.user_token_audience` / `user_token_issuer`, UI: Edit Virtual Server): checked by `verifyToken` on top of signature + expiry (proxy and A2A user tokens). Blank = not checked (old behaviour); they are different from `okta_audience`, the audience Warden requests when it exchanges the token. Updates that omit them leave them alone; `''` clears. Set on `banking-vs` to the backend's `OKTA_AUDIENCE` / `OKTA_ISSUER`.
- **Anonymous virtual servers are refused** (`routes/virtualServers.js`, `virtual_servers.allow_anonymous`): a tool-proxying VS (`protocol` mcp or both) with `require_obo = 0` **and** `require_agent_token = 0` identifies nobody (no user token, no agent token), so POST/PUT answer 400 `anonymous_virtual_server` unless the body says `allow_anonymous: true` (the UI asks for confirmation; the card shows an *Anonymous* badge; acknowledging is written to `event_log` as `log_type='config'`). A2A-only VSes are exempt. The flag is cleared when the VS is secured, is never reusable, and omitted fields keep their stored value; because the PUT resets omitted `require_agent_token`, an old client that omits it can no longer silently downgrade a secured VS. A one-time migration (only when the column is first created) grandfathered VSes already in that state. **Unverified claims are never an identity**: when a VS has no way to verify user tokens (no `jwks_uri`, no issuer, no `JWKS_URI`), `verifyToken` falls back to reading the token unchecked (dev mode); `proxy.js` then drops those claims (`sub`/`groups`/scopes are empty for policy and audit — otherwise a forged JWT could satisfy a `group_contains`/`scope_contains`/`sub_equals` rule on an agent-only VS), and a VS with `require_obo` on is refused with 401 `no_idp_configured`. Saving `require_obo` on with no issuer/`jwks_uri`/`JWKS_URI` is refused too (400 `obo_without_idp`; A2A-only VSes are exempt). A vaulted upstream credential is never injected for an unidentified caller regardless (`vault.js`: agent identity required). Test: `npm run test:anonymous` in `mcp-virtual-server/`.
- **Rate limiting** (`middleware/rateLimit.js`): per calling agent (token hash, else IP), fixed 1-minute window, `WARDEN_RATE_LIMIT_PER_MIN` (default 300, 0 = off) on the proxy, A2A POSTs (JSON-RPC `-32012`), vault checkout/sign and scan. The admin API is not limited.
- **Bind address**: Warden listens on `127.0.0.1` by default (`WARDEN_HOST=0.0.0.0` to expose it; then firewall it and set the admin token). Scripts that use the admin API (`demo/broker`, `gateway-key.js`, `credit-card-agent/setup-warden.js`) read `WARDEN_ADMIN_TOKEN` from the environment or Warden's `.env` (an explicitly empty value means none; tests rely on that).
- Not done (infrastructure, not code): Okta access-token lifetime (set short in the Okta authorization-server access policy), TLS between services, DPoP/mTLS token binding.

### Credential Vault (Warden)
Global encrypted secret store so agents never hold credentials in code or `.env`. Code: `src/services/vault.js` (access, leases, `vault://` resolution, redaction, JWT signing), `src/services/vaultPolicy.js` (policy engine), `src/routes/vault.js` (admin + agent API under `/api/vault`). Tables: `vault_secrets`, `vault_policies`, `vault_leases`. Values use AES-256-GCM via `services/secrets.js` (key outside the DB) and are **write-only** — no API returns them after creation.

- **Access = policy**: deny-by-default `vault_policies` (caller `any|agent|group`, secret or `*`, optional virtual-server scope, operations `reveal|broker|sign`, `max_ttl_seconds`). Priority DESC; on a tie a `forbid` is consulted before a `permit`; first match decides. A VS-scoped policy never matches a request that names no VS.
- **Three modes**: `reveal` = `POST /api/vault/checkout` (X-Agent-Token) returns value + lease; **`broker`** = Warden injects the value so the agent never sees it — a *whole-string* `vault://name` in tool arguments, or in an MCP server's `auth_config` / a VS's `okta_client_secret`; `sign` = `POST /api/vault/sign` signs a JWT with a stored `private_key` (metadata `client_id`/`token_url`/`kid` drive iss/sub/aud/kid; iat/exp/jti always set by Warden).
- **Proxy order matters**: `proxy.js` resolves `vault://` refs (`prepareToolCall`) only *after* the inbound scan and policy allow, so interceptors/audit/approval tickets only ever see the placeholder. Injected values are redacted from the response and error text (`redact`, deep string walk — never `JSON.stringify` the result). Approval tickets store `agent_id` so refs resolve (and are re-policy-checked) at execution time; a revoked policy fails the ticket closed.
- **Upstream auth injection** applies only when `auth_config` contains a `vault://` ref (plain configs keep their old discovery-only behaviour). `apikey` always applies; `bearer`/`basic` replace `Authorization` only when the VS has `require_obo = 0` (otherwise the OBO token wins).
- **Per-virtual-server switch** (`virtual_servers.vault_enabled`, UI: Edit Virtual Server → Pipeline Features → Credential Vault): when 0 the vault is never consulted for calls on that VS — `vault://` text in arguments passes through untouched, an MCP server whose `auth_config` has a `vault://` credential is refused with `code: vault_disabled` (never called without its credential; audited), `/api/vault/checkout|sign` naming that VS return 403, and a `vault://` Okta client secret on it is a clear config error. Existing VSes migrate to 1 (behaviour unchanged); the API default when the field is omitted is 1; the UI's *new* VS default is off. Note: a VS that uses an MCP server with a vault credential (e.g. `banking-vs` + `bank-mcp` once the gateway key is enabled) must keep it on. Updates that omit the field never change it.
- **Agents can't enumerate secrets**: not-found, disabled, expired and denied return the identical 403 message; the real reason is in `event_log` (`log_type='vault_access'`, never contains values). System use (OBO client secret, discovery) bypasses agent policy but is audited with `principal: 'system'`.
- Rotation bumps `version` and revokes outstanding leases. Python SDK: `agent/vault_client.py` (`get`, `sign`, `is_valid`); smoke test `agent/test_vault.py`. Regression suite (throwaway DB + fake upstream): `node scripts/test-vault.js` in `mcp-virtual-server/`.
- Vault administration is part of Warden's admin API, protected by `WARDEN_ADMIN_TOKEN` (see *Warden admin security*). In open mode (token unset) anyone who can reach port 3003 can create vault policies.

### A2A versions (Warden gateway)
Warden gateways the **JSON-RPC binding of A2A 1.0 and 0.3**. Version is a property of each registered remote agent (`a2a_agents.protocol_version`, default `'1.0'`): chosen at registration (`POST /api/a2a-agents` `protocol_version`: `auto` | `1.0` | `0.3`; UI: Register A2A Agent → A2A version), validated against the card (`detectVersion` / `parseCard(card, requested)` in `services/a2aCards.js`; an explicit choice that disagrees with the card is rejected; refresh re-validates and fails closed if the card changed version), and **not changeable later** (re-register). The agent's gateway endpoint `/a2a/:vsId/:agentId` then speaks that same version to the caller AND the remote — **no translation**, so policy, interceptor scanning, task ownership and the circuit breaker behave identically.
- Everything version-specific is the `PROTOCOLS` table in `routes/a2a.js`: 1.0 = `SendMessage`/`SendStreamingMessage`/`GetTask`/`ListTasks`/`CancelTask`/`SubscribeToTask`, wrapped results (`{task}`/`{statusUpdate}`…), `TASK_STATE_*`, sends `A2A-Version: 1.0`; 0.3 = `message/send`/`message/stream`/`tasks/get`/`tasks/cancel`/`tasks/resubscribe` (no list), bare results discriminated by `kind`, lowercase states, **no `A2A-Version` header** (sent only to 1.0 agents; if a caller sends it, it must match the agent's version).
- Gateway card is built per version (`buildGatewayCard`): 0.3 → `protocolVersion`, `url` = Warden, `preferredTransport: JSONRPC`, other interfaces/signatures/security dropped, push + extended card advertised off; also served at `/.well-known/agent.json` for 0.3 agents only. A 0.3 card whose preferred transport is gRPC/REST is accepted only if `additionalInterfaces` offers JSON-RPC. 0.2.x and earlier are rejected.
- A caller using the other version's method names gets `-32601` with `data.reason` naming the right method. Audit events (`a2a_call`) record `a2a_version`.
- Python client: `agent/a2a_client.py` `A2AClient(..., version="0.3")`; `test_a2a.py` reads `WARDEN_A2A_VERSION`. Tests: `node scripts/test-a2a-versions.js` in `mcp-virtual-server/`.

### A2A approval policies
`a2a_policies.effect` is `permit | forbid | approval` (plus `approval_ttl_minutes` 1–10080, default 30, and `approval_timeout_action` `deny`|`approve`, default `deny`; an unknown action falls back to deny, never to auto-approve). Evaluation stays first-match by priority (`services/a2aPolicy.js`; decision `allow|deny|approval`). An approval policy **gates initiating calls only**: it matches like a *forbid* when the request names no skill (so omitting `skillId` can't dodge it) and like a *permit* for follow-ups (`GetTask`/`CancelTask`/subscribe — the task was approved when started, and ownership protects it), where it simply allows.
- **Flow** (`routes/a2a.js`): after policy, `require_user`, ownership/param validation and the **inbound scan**, an `approval` verdict stores a ticket in the shared `approval_tickets` table (`kind='a2a'`; `a2a_*` columns hold the *already scanned* params, delegation chain and verified-user claims — no user token is stored; `mcp_server_id` = target agent id, `tool_name` = skill or method) and answers **HTTP 202 + JSON-RPC error `-32011`** whose `data` has `ticket_id`, `poll_url`, `expires_at`, `timeout_action`. The remote is not contacted. Streaming requests are held too and, once approved, run as the version's **plain send** (no open connection to stream to).
- **Decision** (`routes/approvals.js`, same Approvals page/endpoints as MCP): approve → `a2a.executeApprovedTicket` forwards the call and stores the outbound-scanned JSON-RPC result on the ticket (task saved under the original caller, so follow-ups work); deny/expire are audited (`a2a_call`, `ticket_id` in `data`, decision `approval` → `allow`/`deny`/`error`; `approval` is not scored). **Everything is re-checked at execution**: agent still active and assigned to the VS, calling agent still active, and no `forbid` added since (any failure → `exec_error`, status stays `approved`). Callers poll `GET /api/approvals/:id/status` (executed → result; denied/expired → 403; failed → 502). The status endpoint now reports `exec_error` before "approved, executing" for MCP tickets too (it used to hide failures forever).
- Python client: `A2AClient.send_message(..., wait_for_approval=<seconds>)` / `wait_for_approval(A2AApprovalRequired)`. The banking chat relay passes Warden's 202/`-32011` through untouched; the chat (`pages/Agent.jsx`) handles it like MCP approvals: `sendA2AMessage` throws `A2AApprovalPendingError` (`services/a2aClient.js`), the chat shows a "waiting" bubble and polls the ticket status every 5 s (through the banking backend relay as the agent that made the call, `GET /api/warden/approvals/:id/status?kind=mcp|a2a`; in secure mode Warden shows a ticket only to its own agent or an admin), `interpretApprovalStatus` turns the payload into pending / done / denied / expired / failed, and a done result is rendered through `showA2aResult` and the normal outbound chat scan. Only one approval can be polled at a time (shared with MCP; a second one replaces the first). Tests: `node scripts/test-a2a-approval.js` (Warden) and `node scripts/test-a2a-approval-chat.js` (chat client logic) in the respective `scripts/` folders.

### Local PII Analyzer (`presidio-server/`)
`presidio-server/server.py` is a self-hosted replacement for the presidio-analyzer Docker image. Start with `py -3 server.py` (requires `flask` + `waitress`). Exposes `/health` and `/analyze` (POST). Uses pure regex — no spaCy, no Docker. Phone pattern requires mandatory separators (`[-.\s]`) to avoid false-positive matches on 10-digit account numbers.

### Database (Banking Backend)
Uses Node.js 22.5+ built-in `node:sqlite` (synchronous `DatabaseSync` API — similar to `better-sqlite3`). The DB file defaults to `banking-app/backend/banking.db`. First startup auto-seeds demo data via `seed.js`. Real Okta users are provisioned on first MCP/REST call via `getOrCreateUser`.

### Frontend Auth
`banking-app/frontend/src/oktaConfig.js` holds the Okta OIDC config. `src/services/api.js` attaches the Okta access token to every REST request. `src/services/mcpProxy.js` calls MCP tools and the A2A Credit Card Agent through the backend's Warden relay (below) for the in-browser agent demo page.

### Warden Relay (browser → backend → Warden)
**The browser holds no Warden credential — never add `VITE_*` secrets** (Vite inlines every referenced `VITE_*` into the public bundle). `banking-app/backend/src/routes/warden.js` (`/api/warden/{config,tool,a2a}`) verifies the user's Okta token (`verifyToken`), then `services/wardenGateway.js` adds the Warden **agent token and API key** and forwards to Warden's proxy / A2A endpoint, returning Warden's status and body unchanged (including 202 `pending_approval`). Credentials come from the Warden Credential Vault at runtime via `services/wardenVault.js` (`reveal` checkout, cached in memory for the lease, single-flight).
- **Exactly two identities, no gateway agent**: the relay is not an agent. MCP tool calls go out as the banking agent (`WARDEN_AGENT_TOKEN`) and A2A messages as the A2A agent (`WARDEN_A2A_AGENT_TOKEN`), so Warden allowlists, policies, scoring and the audit trail stay keyed to the same two agents. Browser-supplied `X-Agent-Token` / `X-API-Key` / `x-user-token` are ignored; headers are built fresh.
- **Bootstrap**: an agent's own token *is* its identity, so it cannot live in the vault (you need it to open the vault). Both tokens are the backend's only local Warden secrets, in `banking-app/backend/.env.local` (git-ignored; loaded in `index.js`). Each agent authenticates to the vault as itself and reads **only** the shared Warden API key (`WARDEN_API_KEY_SECRET`) under its own `reveal` policy (caller = that agent, **no VS scope** — a VS-scoped checkout must present the very API key being fetched). One vault client + lease cache per agent; neither agent can read the other's secrets. Leave `WARDEN_API_KEY_SECRET` empty if the VS has no API keys (the vault is then never contacted).
- **Config (backend `.env`, non-secret)**: `WARDEN_URL`, `WARDEN_VIRTUAL_SERVER_ID`, `WARDEN_MCP_SERVER_ID`, `WARDEN_A2A_VS_ID`, `WARDEN_A2A_TARGET_ID`, `WARDEN_API_KEY_SECRET` (the secret's *name*). `credit-card-agent/setup-warden.js` writes the A2A ids and token to the backend `.env.local`.
- **Gateway key on `/mcp` (opt-in)**: `/mcp` decodes the JWT without verifying it, so anything that can reach port 3001 could forge a user. With `MCP_GATEWAY_KEY_SHA256` set (hash only), `requireGatewayKey` in `index.js` rejects any `/mcp` request (POST/GET/DELETE) lacking a matching `X-Gateway-Key`; malformed value = refuse to start, unset = open. Warden holds the key as vault secret `banking-mcp-gateway-key` and **brokers** it: `bank-mcp`'s `auth_config` is `apikey X-Gateway-Key = vault://banking-mcp-gateway-key`, and each allowlisted agent needs a `broker` vault policy (VS-scoped). Manage it with `npm run gateway-key -- status|enable|rollback` in `banking-app/backend/` (enable generates the key straight into the vault — nobody sees it — and saves only the hash to `.env.local`; re-run to rotate; Warden is changed first and the backend enforces only after a restart, so it can't be locked out; a rotation takes effect only after the backend restart and fails closed until then). Test: `npm run test:gateway-key`.
- Chat scanning and approval polling also go through the relay now (`POST /api/warden/scan`, `GET /api/warden/approvals/:id/status`): the backend calls Warden as the banking agent (`agent: 'mcp'`) or the A2A agent (`'a2a'`) with that agent's token (+ API key), so the browser never contacts Warden at all. `WARDEN_CHAT_VS_ID` (backend `.env`, non-secret) names the virtual server that hosts the shared chat-scan interceptors. Warden takes the scanning agent's identity from the token (the body's `agent_name` is ignored in secure mode), so findings and scores can't be attributed to another agent. If scanning can't run the chat fails open (logged in the console).
- `broker` mode does not apply to this key: it authenticates the caller *to* Warden, whereas brokering injects upstream credentials after Warden has authenticated the caller.
- Regression suite (throwaway Warden + fake upstream + real `index.js`): `npm run test:warden-relay` in `banking-app/backend/`.

## Environment Variables

### Banking Backend (`.env` in `banking-app/backend/`)
| Variable | Purpose |
|---|---|
| `OKTA_ISSUER` | Okta authorization server URL |
| `OKTA_AUDIENCE` | Expected token audience (default `api://banking`) |
| `FRONTEND_URL` | CORS allowed origin (default `http://localhost:5173`) |
| `DB_PATH` | Override SQLite file location |
| `PORT` | Server port (default 3001) |
| `OBO_*` | Dev-only OBO verifier vars (surfaced at `/api/dev/config`) |

### Python Agent (`.env` in `agent/`)
| Variable | Purpose |
|---|---|
| `PG_GATEWAY_URL` | Gateway base URL |
| `PG_GATEWAY_TOKEN` | Gateway API token |
| `PG_VIRTUAL_SERVER_ID` | Virtual server ID on the gateway |
| `PG_AGENT_NAME` | Agent identity for policy enforcement (default `banking-agent`) |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `ANTHROPIC_BASE_URL` | Optional (Bedrock / proxy) |
| `AGENT_MODEL_ID` | Claude model ID (default `us.anthropic.claude-3-5-sonnet-20241022-v2:0`) |
| `USER_TOKEN` | Pre-set Okta user token (skips interactive login) |
| `OKTA_CLIENT_ID` / `OKTA_ISSUER` | Enables PKCE login flow in agent |

### MCP Virtual Server (`.env` in `mcp-virtual-server/`)
Needs `PORT`, Redis connection vars, and an admin API token. See `OKTA_SETUP.md` for Okta OBO client credentials stored per-virtual-server in the DB.

## Notable Patterns

- **`node:sqlite` BigInt**: `lastInsertRowid` is returned as `BigInt` — always coerce with `Number(result.lastInsertRowid)` before passing to other queries.
- **Accept header patching**: The backend's `patchAcceptHeader` function in `index.js` silently adds `text/event-stream` to requests that only send `application/json`, preventing SDK errors when a gateway strips the SSE accept type.
- **`fallback_to_client_credentials: false`**: The gateway is explicitly configured to reject calls that lack a user token — the backend never acts as the gateway's own identity.
- **Demo user**: Seed data uses `okta_sub = 'demo-user-seed'`; only reachable without a token (unauthenticated dev inspection).
- **Per-user MCP session keying**: `mcpClient.js` keys sessions as `url + sha256(oboToken)[:16]` — prevents user A's session (bound to their DB user ID at `initialize` time) from being reused for user B. Never pre-warm sessions at startup without a real user OBO token.
- **Redis reconnect strategy**: `tokenCache.js` sets `socket: { connectTimeout: 2000, reconnectStrategy: false }` — without this, `await redisClient.connect()` hangs indefinitely when Redis is unavailable, causing 20-second proxy timeouts on every call.
- **Interceptor mask deduplication**: `ActionEngine.applyMasks` processes matches from highest start position to lowest. A `processedStart` guard skips any match whose `end > processedStart` — prevents double-replacement corruption when the same text span is detected by both RegexScanner and PresidioScanner.
- **Python 3.14 + spaCy**: spaCy's Cython extensions produce `OverflowError: Python int too large to convert to C ssize_t` on Python 3.14. The local Presidio server uses pure regex as a workaround. spaCy NER (for PERSON/ORG/LOC detection) requires Python 3.11 or 3.12.
