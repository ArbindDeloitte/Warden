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

### Local PII Analyzer (`presidio-server/`)
`presidio-server/server.py` is a self-hosted replacement for the presidio-analyzer Docker image. Start with `py -3 server.py` (requires `flask` + `waitress`). Exposes `/health` and `/analyze` (POST). Uses pure regex — no spaCy, no Docker. Phone pattern requires mandatory separators (`[-.\s]`) to avoid false-positive matches on 10-digit account numbers.

### Database (Banking Backend)
Uses Node.js 22.5+ built-in `node:sqlite` (synchronous `DatabaseSync` API — similar to `better-sqlite3`). The DB file defaults to `banking-app/backend/banking.db`. First startup auto-seeds demo data via `seed.js`. Real Okta users are provisioned on first MCP/REST call via `getOrCreateUser`.

### Frontend Auth
`banking-app/frontend/src/oktaConfig.js` holds the Okta OIDC config. `src/services/api.js` attaches the Okta access token to every REST request. `src/services/mcpProxy.js` lets the frontend call MCP tools directly through the backend for the in-browser agent demo page.

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
