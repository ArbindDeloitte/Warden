# SecureBank — MCP + Warden Demo

A full-stack banking application demonstrating **OAuth 2.0 On-Behalf-Of (OBO) token exchange** and **AI agent security** with the **Warden MCP Gateway**.

An AI agent operates on behalf of a signed-in user. Warden performs the OBO token exchange so the agent never holds user credentials, enforces Cedar-style access policies, and runs a bidirectional interceptor pipeline that blocks prompt injection and masks PII before any data reaches the LLM.

---

## Architecture

```
User ──► React Frontend (Okta PKCE) ──► Banking REST API  :3001
                                               │
Agent ──► Warden Gateway :3003                 │
            │  ① verify API key                │
            │  ② verify user JWT               │
            │  ③ inbound intercept scan        │
            │  ④ Cedar policy check            │
            │  ⑤ OBO token exchange (Okta)    │
            │  ⑥ forward to MCP endpoint ─────┘
            │  ⑦ outbound intercept scan
            └──► masked/filtered response ──► Agent / Frontend
```

### Components

| Component | Directory | Port | Runtime |
|---|---|---|---|
| Banking Backend + MCP Server | `banking-app/backend/` | 3001 | Node.js 22.5+ (ESM) |
| Banking Frontend | `banking-app/frontend/` | 5173 | React + Vite |
| Warden (MCP Virtual Server) | `mcp-virtual-server/` | 3003 | Node.js (CJS) |
| Python Agent | `agent/` | — | Python 3.11+ |
| PII Analyzer (local Presidio) | `presidio-server/` | 5001 | Python (waitress) |

---

## Quick Start

### 1. Banking Backend

```bash
cd banking-app/backend
cp .env.example .env   # fill in OKTA_ISSUER, OKTA_AUDIENCE
npm install
npm run dev            # http://localhost:3001
```

### 2. Banking Frontend

```bash
cd banking-app/frontend
npm install
npm run dev            # http://localhost:5173
```

### 3. Warden Gateway

```bash
cd mcp-virtual-server
cp .env.example .env   # fill in PORT, REDIS_URL, ADMIN_API_TOKEN, Okta OBO credentials
npm install
npm run dev            # http://localhost:3003
```

> **Redis**: Warden uses Redis for OBO token caching. If Redis is unavailable, Warden falls back gracefully (tokens fetched live every call). Set `socket.reconnectStrategy: false` in `src/services/tokenCache.js` to avoid startup hangs.

### 4. PII Analyzer (optional — enhances Presidio scanner)

```bash
cd presidio-server
pip install flask waitress
py -3 server.py        # http://localhost:5001
```

### 5. Python Agent

```bash
cd agent
pip install -r requirements.txt
cp .env.example .env   # fill in PG_GATEWAY_URL, PG_GATEWAY_TOKEN, PG_VIRTUAL_SERVER_ID, ANTHROPIC_API_KEY
python agent.py
```

---

## Warden — The Security Layer

Warden is a self-hosted MCP gateway that sits between the AI agent and the banking MCP server. Every tool call passes through it.

### What Warden Does

| Feature | Description |
|---|---|
| **API key enforcement** | Per-virtual-server API keys gate access |
| **JWT verification** | Validates Okta access tokens on every call |
| **OBO token exchange** | RFC 8693 — exchanges user AT-A for MCP-scoped AT-B |
| **Cedar-style policies** | Deny-by-default; permit rules specify tool, scope, group conditions |
| **Bidirectional interceptors** | Inbound (user → LLM) and outbound (MCP response → user) scans |
| **Audit log** | Every proxied call recorded in SQLite |

### Interceptor Pipeline

```
User message ──► [Inbound Scan] ──► Policy Check ──► MCP Tool Call
                     │                                      │
                  BLOCK / MASK / WARN           [Outbound Scan]
                                                      │
                                               BLOCK / MASK / WARN
                                                      │
                                              Response to caller
```

**Scanners** (both run per call):

| Scanner | Location | Detects |
|---|---|---|
| `RegexScanner` | In-process Node.js | SSN, IBAN, credit cards, email, phone, prompt injection patterns |
| `PresidioScanner` | HTTP → `localhost:5001` | Same + extensible to NER entities (PERSON, ORG, LOC) with spaCy |

**Rule actions**: `block` (403), `mask` (replace matched spans with `[REDACTED: TYPE]`), `warn` (pass + log), `allow`.

**Demo rules configured on `banking-vs`**:

| Priority | Rule | Scanner | Action | Score threshold |
|---|---|---|---|---|
| 100 | Block Prompt Injection | regex | block | ≥ 0.5 |
| 80 | Mask PII — SSN, Cards, IBAN | regex | mask | ≥ 0.7 |
| 60 | Mask Named Entities (Presidio) | presidio | mask | ≥ 0.6 |
| 10 | Audit Low-Confidence Flags | * | warn | ≥ 0.3 |

### OBO Token Flow

```
Frontend user AT  (aud: api://banking)
        │
        └──► Warden OBO exchange (RFC 8693, Okta)
                    │
                    └──► MCP OBO token  (aud: api://banking-mcp)
                                │
                                └──► Banking MCP server (/mcp)
                                     decodes sub → getOrCreateUser()
```

---

## Dual Auth Model (Banking Backend)

| Path | Auth | Middleware |
|---|---|---|
| `GET/POST /api/*` | Full Okta JWT verification (JWKS) | `verifyToken` → extracts `sub`, `email`, `groups`, `scp` |
| `POST /mcp` | Trusts gateway; base64-decodes JWT payload only | `decodeMcpToken` → `getOrCreateUser(db, sub)` |

The MCP endpoint trusts Warden as the trust boundary. No crypto verification — the OBO exchange already validated the token upstream.

---

## Environment Variables

### Banking Backend (`banking-app/backend/.env`)

| Variable | Default | Purpose |
|---|---|---|
| `OKTA_ISSUER` | — | Okta authorization server URL |
| `OKTA_AUDIENCE` | `api://banking` | Expected token audience |
| `FRONTEND_URL` | `http://localhost:5173` | CORS allowed origin |
| `DB_PATH` | `banking.db` | SQLite file location |
| `PORT` | `3001` | Server port |

### Warden (`mcp-virtual-server/.env`)

| Variable | Purpose |
|---|---|
| `PORT` | Gateway port (default 3003) |
| `REDIS_URL` | Redis connection (optional — falls back gracefully) |
| `ADMIN_API_TOKEN` | Bearer token for Warden admin API |
| `JWT_SECRET` / Okta vars | Token verification config |

### Python Agent (`agent/.env`)

| Variable | Purpose |
|---|---|
| `PG_GATEWAY_URL` | Warden base URL |
| `PG_GATEWAY_TOKEN` | Warden API token |
| `PG_VIRTUAL_SERVER_ID` | Virtual server ID |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `USER_TOKEN` | Pre-set Okta user token (skips interactive login) |

---

## Project Structure

```
.
├── banking-app/
│   ├── backend/          # Express + MCP server (Node.js ESM)
│   │   ├── src/
│   │   │   ├── mcp/server.js        # MCP tool definitions
│   │   │   ├── routes/              # REST API routes
│   │   │   ├── middleware/auth.js   # Okta JWT verification
│   │   │   ├── db.js                # node:sqlite wrapper
│   │   │   └── seed.js              # Demo data seeder
│   │   └── index.js                 # Express app + MCP endpoint
│   └── frontend/         # React + Vite + Okta PKCE
│       └── src/
│           ├── oktaConfig.js
│           ├── services/api.js      # REST client
│           └── services/mcpProxy.js # In-browser MCP demo
├── mcp-virtual-server/   # Warden gateway (Node.js CJS)
│   └── src/
│       ├── routes/proxy.js          # Main proxy endpoint
│       ├── services/
│       │   ├── oboService.js        # RFC 8693 OBO exchange
│       │   ├── tokenCache.js        # Redis-backed token cache
│       │   ├── policyEngine.js      # Cedar-style evaluator
│       │   └── mcpClient.js         # Per-user MCP session manager
│       └── interceptors/
│           ├── InterceptorPipeline.js
│           ├── ActionEngine.js      # Rule evaluator + mask applier
│           └── scanners/
│               ├── RegexScanner.js  # Pattern-based PII + injection
│               └── PresidioScanner.js # Local HTTP PII analyzer
├── presidio-server/
│   └── server.py         # Local PII analyzer (regex, no Docker/spaCy)
├── agent/                # Python Claude agent
│   ├── agent.py
│   └── token_helper.py   # Okta PKCE flow
└── CLAUDE.md             # Claude Code guidance
```

---

## Known Constraints

- **Python 3.14 + spaCy**: spaCy's Cython extensions overflow on Python 3.14's integer representation. The local Presidio server uses pure regex — it detects structured PII (SSN, IBAN, credit cards) but not free-text locations or person names. spaCy NER requires Python 3.11 or 3.12.
- **Redis optional**: If Redis is unavailable, OBO tokens are fetched live on every call (~200 ms overhead). Set `reconnectStrategy: false` to prevent startup hangs.
- **No external AI safety APIs**: The interceptor stack is fully self-hosted by design — no Azure Content Safety, Lakera Guard, or OpenAI Moderation API.
- **MCP session isolation**: Sessions are keyed by `url + sha256(oboToken[:16])` — each user gets their own MCP session bound to their database identity.
