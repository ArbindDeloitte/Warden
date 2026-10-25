# SecureBank — Banking Application with OBO Identity Delegation

A full-stack banking application demonstrating **OAuth 2.0 On-Behalf-Of (OBO) token exchange** via the PointGuardAI MCP Gateway. An AI agent operates on behalf of a signed-in user without ever holding that user's credentials.

## Architecture

```
User → Banking Frontend (React/Okta) ─────────────────────→ Banking Backend (Express/SQLite)
                │                                                       ↑
                │ (copies access token)                                 │ (OBO-exchanged token)
                ↓                                                       │
           Python Agent ──→ PointGuardAI MCP Gateway ──→ Banking MCP Server
                              (OBO exchange via Okta)
```

### Components

| Component | Location | Port | Description |
|-----------|----------|------|-------------|
| Banking Backend + MCP | `banking-app/backend/` | 3001 | Express API + MCP server (SQLite) |
| Banking Frontend | `banking-app/frontend/` | 5173 | React + Okta OIDC |
| Python Agent | `agent/` | — | CLI agent using PointGuardAI Gateway |

### Token Flow (OBO)

1. **User signs in** to the banking frontend via Okta (Authorization Code + PKCE)
2. **Frontend** gets an access token (`aud: api://banking`) and calls the banking API directly
3. **Agent** gets the user's access token (PKCE flow or manual paste)
4. **Agent → PointGuardAI Gateway**: sends MCP tool call with:
   - `Authorization: Bearer <PG_GATEWAY_TOKEN>` — gateway auth
   - `x-user-token: Bearer <user_access_token>` — user's identity for OBO
   - `X-Agent-Token: banking-agent` — agent identity for policy enforcement
5. **Gateway → Okta**: performs RFC 8693 token exchange (OBO) → new access token with user's identity
6. **Gateway → Banking MCP Server**: calls with OBO-exchanged token
7. **MCP Server** validates token, executes tool **as the user**, returns result

## Quick Start

### Prerequisites
- Node.js 22.5+ (for built-in `node:sqlite`)
- Python 3.11+
- An Okta developer org (see [OKTA_SETUP.md](./OKTA_SETUP.md))
- A PointGuardAI MCP Gateway instance (see [OKTA_SETUP.md](./OKTA_SETUP.md))

### 1. Backend

```bash
cd banking-app/backend
cp .env.example .env
# Edit .env: set OKTA_ISSUER, OKTA_AUDIENCE, FRONTEND_URL
npm install
npm start
# → http://localhost:3001
```

### 2. Frontend

```bash
cd banking-app/frontend
cp .env.example .env
# Edit .env: set VITE_OKTA_CLIENT_ID (from Okta setup)
npm install
npm run dev
# → http://localhost:5173
```

### 3. Python Agent

```bash
cd agent
pip install -r requirements.txt
cp .env.example .env
# Edit .env: set PG_GATEWAY_URL, PG_GATEWAY_TOKEN, PG_VIRTUAL_SERVER_ID
# Set USER_TOKEN or OKTA_CLIENT_ID for PKCE flow
python agent.py
```

## Okta Configuration

See **[OKTA_SETUP.md](./OKTA_SETUP.md)** for step-by-step instructions to configure:
- Custom scopes (banking permissions)
- Groups claim
- User-facing OIDC app (frontend + agent)
- API Services app (PointGuardAI Gateway OBO client)
- Access policies

### Scopes

| Scope | Description |
|-------|-------------|
| `accounts:read` | List and view accounts |
| `accounts:balance:read` | View account balances |
| `accounts:transactions:read` | View transaction history |
| `accounts:statements:read` | View account statements |
| `accounts:write` | Update account settings |
| `payments:initiate` | Create new payments |
| `payments:approve` | Approve pending payments |
| `payments:read` | View payment history |
| `standing-orders:manage` | Create/update/cancel standing orders |
| `transfers:external:create` | Create external (IBAN) transfers |

## MCP Tools

The banking MCP server exposes these tools (called by the agent via the gateway):

| Tool | Required Scope | Description |
|------|---------------|-------------|
| `get_accounts` | accounts:read | List user's accounts |
| `get_account_balance` | accounts:balance:read | Get account balance |
| `get_transactions` | accounts:transactions:read | List transactions |
| `get_statements` | accounts:statements:read | Get statements |
| `list_payments` | payments:read | List payments |
| `initiate_payment` | payments:initiate | Create a payment |
| `approve_payment` | payments:approve | Approve payment |
| `create_standing_order` | standing-orders:manage | Create standing order |
| `manage_standing_order` | standing-orders:manage | Update/cancel order |
| `create_external_transfer` | transfers:external:create | External IBAN transfer |

## PointGuardAI Gateway Setup

Follow the onboarding doc (§3.5) to configure the gateway:

1. **Step 1**: Create a gateway API token
2. **Step 2**: Add the banking MCP server with a one-time access token at `http://localhost:3001/mcp`
3. **Step 3**: Switch to OBO (Token Exchange) with your Okta credentials
4. **Step 4**: Create virtual server `banking-agent`
5. **Step 5**: Write access rules (no user token → deny, undeclared agents → deny)

## Security Notes

- The banking backend validates **every** JWT against Okta's JWKS — no shared secrets
- The MCP server and REST API share the same JWT validation; the OBO-exchanged token and the user's direct token both carry the user's `sub`
- `fallback_to_client_credentials` is **false** — the gateway never calls the banking server as itself
- Agent identity (`X-Agent-Token`) is enforced by the PointGuardAI policy engine

## Development Notes

- First run seeds the SQLite database with demo data (1 user, 3 accounts, 30 transactions, etc.)
- Real users are created on first login: the backend reads the Okta `sub` claim and creates a user record with fresh accounts
- The demo user (seed data) uses `okta_sub = 'demo-user-seed'` and is only visible if you hit the API without a token (for development inspection)
