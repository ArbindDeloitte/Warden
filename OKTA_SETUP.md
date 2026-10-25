# Okta Setup for SecureBank

Okta org: **demo-arbind-lochan-mishra.okta.com**

---

## Overview

This setup uses **two separate custom authorization servers** with trust established between them. This is the production-grade pattern: the user's auth server and the MCP exchange server are isolated, and the exchange server only accepts tokens that Auth Server A vouches for.

```
Frontend Login (Auth Code + PKCE)
  └─→ Auth Server A  →  access token (aud: api://banking)
                                │
                                │ (copied to x-user-token)
                                ↓
          PointGuardAI Gateway (OBO exchange)
                                │
                                │ presents user token to Auth Server B
                                ↓
                         Auth Server B  ←─ trusts Auth Server A
                                │  →  OBO token (aud: api://banking-mcp, sub: same user)
                                ↓
                     Banking MCP Server (validates Auth Server B token)
```

| | Auth Server A | Auth Server B |
|---|---|---|
| **Name** | `SecureBank-UserAuth` | `SecureBank-MCPExchange` |
| **Audience** | `api://banking` | `api://banking-mcp` |
| **Scopes** | All 10 banking scopes | All 10 banking scopes |
| **Used by** | Frontend sign-in, Agent PKCE | PointGuardAI Gateway (Token Exchange) |
| **Validates tokens** | Banking REST API | Banking MCP server |
| **Trust** | — | Trusts Auth Server A |

---

## What you will create

| # | Item | Purpose |
|---|------|---------|
| A | Auth Server A — `SecureBank-UserAuth` | Issues user tokens for the frontend |
| B | Auth Server B — `SecureBank-MCPExchange` | Performs OBO exchange for the PG Gateway |
| C | Trust: Server B trusts Server A | Allows Server B to accept Server A tokens in exchanges |
| D | Banking scopes on BOTH servers | Granular permissions |
| E | Groups claim on BOTH servers | User group membership in tokens |
| F | OIDC SPA app — `SecureBank Frontend` | Frontend + agent PKCE login |
| G | API Services app — `PointGuardAI Gateway` | OBO exchange client (registered on Server B) |
| H | Access policy on Server A (for app F) | Allows end-users to sign in |
| I | Access policy on Server B (for app G) | Allows gateway to exchange tokens |

---

## Step 1 — Create Auth Server A (User / Frontend)

**Security → API → Authorization Servers → Add Authorization Server**

| Field | Value |
|-------|-------|
| Name | `SecureBank-UserAuth` |
| Audience | `api://banking` |
| Description | Issues access tokens for the SecureBank frontend and agent |

Click **Save**. Note the server's:
- **Issuer**: `https://demo-arbind-lochan-mishra.okta.com/oauth2/{serverA-id}` → goes in `OKTA_ISSUER` (backend) and `VITE_OKTA_ISSUER` (frontend)
- **Metadata URI** (to find the JWKS URL)

---

## Step 2 — Create Auth Server B (MCP / Exchange)

**Security → API → Authorization Servers → Add Authorization Server**

| Field | Value |
|-------|-------|
| Name | `SecureBank-MCPExchange` |
| Audience | `api://banking-mcp` |
| Description | Performs OBO token exchange for the PointGuardAI MCP Gateway |

Click **Save**. Note the server's:
- **Issuer**: `https://demo-arbind-lochan-mishra.okta.com/oauth2/{serverB-id}` → goes in `OKTA_MCP_ISSUER` (backend)
- **Token endpoint**: `https://demo-arbind-lochan-mishra.okta.com/oauth2/{serverB-id}/v1/token` → goes in PG Gateway OBO config `token_url`

---

## Step 3 — Establish Trust: Server B trusts Server A

This is what allows Server B to accept a user token from Server A in an OBO exchange.

1. In the Okta admin console, open **Security → API**, click on **`SecureBank-MCPExchange`** (Server B).
2. Click the **Trusted Servers** tab.
3. Click **Add Server**, find `SecureBank-UserAuth` (Server A), select it, click **Add**.
4. Click **Done**.

> **Why this matters:** When the PointGuardAI Gateway sends a user's Auth Server A token to Server B's `/v1/token` endpoint for OBO exchange, Server B will validate the incoming token against Server A's JWKS before issuing the exchanged token.

---

## Step 4 — Add banking scopes to BOTH servers

Do this on **Auth Server A** and **Auth Server B** separately.

For each server: **Scopes tab → Add Scope** for all 10 scopes below.

| Scope | Description |
|-------|-------------|
| `accounts:balance:read` | View account balances |
| `accounts:read` | List and view accounts |
| `accounts:statements:read` | View account statements |
| `accounts:transactions:read` | View transaction history |
| `accounts:write` | Update account settings |
| `payments:approve` | Approve pending payments |
| `payments:initiate` | Create new payments |
| `payments:read` | View payment history |
| `standing-orders:manage` | Create/update/cancel standing orders |
| `transfers:external:create` | Create external (IBAN) transfers |

Leave **User consent**: Optional for all. Tick **Include in public metadata**.

---

## Step 5 — Add Groups claim to BOTH servers

Do this on **Auth Server A** and **Auth Server B** separately.

For each server: **Claims tab → Add Claim**

| Field | Value |
|-------|-------|
| Name | `groups` |
| Include in token type | Access Token |
| Value type | Groups |
| Filter | Matches regex → `.*` |
| Include in | Any scope |

Click **Create**.

---

## Step 6 — Create the OIDC SPA app (SecureBank Frontend)

This app is used by the React banking frontend and by the Python agent's PKCE flow. It signs users in against **Auth Server A**.

**Applications → Applications → Create App Integration → OIDC — OpenID Connect → Single-Page Application**

| Field | Value |
|-------|-------|
| App integration name | `SecureBank Frontend` |
| Grant type | Authorization Code (PKCE automatic for SPA) |
| Sign-in redirect URIs | `http://localhost:5173/login/callback` |
|  | `http://localhost:8765/callback` (Python agent) |
| Sign-out redirect URIs | `http://localhost:5173` |
| Controlled access | Allow everyone in your organization |

Click **Save**. Copy the **Client ID** — you need it in `frontend/.env` and `agent/.env`.

---

## Step 7 — Create the API Services app (PointGuardAI Gateway)

The gateway uses this app to authenticate when performing OBO exchanges at **Auth Server B**.

**Applications → Applications → Create App Integration → API Services**

| Field | Value |
|-------|-------|
| App integration name | `PointGuardAI Gateway` |

Click **Save**. Then:

1. **General → General Settings → Edit**
2. Under **Grant type**, click **Advanced** and tick **Token Exchange**.
3. Leave **Client authentication** on **Client secret**.
4. Click **Save**.
5. Copy the **Client ID** and **Client secret** → these are `#13` in the onboarding doc.

> ⚠️ **NHI subscription required.** Okta's Token Exchange grant for OBO requires an NHI Authentication Token subscription purchased or renewed on or after 14 August 2026. Confirm with your Okta account team before proceeding. Without it, step 9 will fail with `unauthorized_client`.

> ⚠️ Create this as an **API Services** app. An ordinary OIDC web app with Token Exchange enabled uses a different Okta flow that requires an `actor_token` the gateway does not send.

---

## Step 8 — Access policy on Auth Server A (for frontend users)

**Security → API → `SecureBank-UserAuth` → Access Policies → Add New Access Policy**

| Field | Value |
|-------|-------|
| Policy name | `Users to SecureBank` |
| Assign to | `SecureBank Frontend` (app F) |

Click **Go to Rule**, then **Add Rule**:

| Field | Value |
|-------|-------|
| Rule name | `Auth Code login` |
| IF Grant type is | Authorization Code |
| AND User is | Any user assigned to the app |
| AND Scopes requested include | `openid`, `profile`, `email`, plus any of the 10 banking scopes |
| Token lifetime | Access token: 1 hour |

Click **Create Rule**, then **Create Policy**.

---

## Step 9 — Access policy on Auth Server B (for the gateway OBO exchange)

**Security → API → `SecureBank-MCPExchange` → Access Policies → Add New Access Policy**

| Field | Value |
|-------|-------|
| Policy name | `Gateway OBO Exchange` |
| Assign to | `PointGuardAI Gateway` (app G) |

Click **Go to Rule**, then **Add Rule**:

| Field | Value |
|-------|-------|
| Rule name | `Token Exchange` |
| IF Grant type is | (click Advanced) → Token Exchange |
| AND User is | Any user assigned to the app (or the groups that may use the agents) |
| AND Scopes requested include | The 10 banking scopes |
| Token lifetime | Access token: 1 hour |

Click **Create Rule**, then **Create Policy**.

---

## Step 10 — Verify the OBO exchange manually

Use this curl to confirm Auth Server B accepts a token from Auth Server A.

Get a fresh access token for a test user from the banking frontend (or DevTools), then:

```bash
export SERVER_B_TOKEN_URL="https://demo-arbind-lochan-mishra.okta.com/oauth2/{serverB-id}/v1/token"
export GW_CLIENT_ID="{gatewayAppClientId}"
export GW_CLIENT_SECRET="{gatewayAppClientSecret}"
export USER_TOKEN="{access token from Auth Server A}"

curl -s -X POST "$SERVER_B_TOKEN_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "subject_token=$USER_TOKEN" \
  --data-urlencode "client_id=$GW_CLIENT_ID" \
  --data-urlencode "client_secret=$GW_CLIENT_SECRET" \
  --data-urlencode "audience=api://banking-mcp" \
  --data-urlencode "scope=accounts:read accounts:balance:read accounts:transactions:read payments:read"
```

**Expected response:**
```json
{
  "token_type": "Bearer",
  "expires_in": 3600,
  "access_token": "eyJ...",
  "scope": "accounts:read ...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

Decode the new `access_token` and verify:

| Claim | Expected |
|-------|----------|
| `iss` | `https://demo-arbind-lochan-mishra.okta.com/oauth2/{serverB-id}` |
| `aud` | `api://banking-mcp` |
| `sub` | **the test user's ID** (not the gateway app's client ID) |
| `cid` | the gateway app's client ID |
| `scp` | the scopes you requested |

---

## PointGuardAI Gateway Configuration

Follow the onboarding doc §3.5 steps 1–5.

### Step PG-1: Create gateway API token
**Organization → API Tokens → Create token** → copy it → set as `PG_GATEWAY_TOKEN` in `agent/.env`.

### Step PG-2: Add the banking MCP server (one-time token first)
**MCP → MCP Servers → Add MCP server**

| Field | Value |
|-------|-------|
| Name | `banking` |
| URL | `http://localhost:3001/mcp` (or your public URL) |
| Transport | Streamable HTTP |
| Authentication Type | Bearer Token |
| Token | A one-time access token from Auth Server **B** for a test user |

Save and verify tools appear under **MCP → Tools**.

### Step PG-3: Switch to OBO (Token Exchange)
Edit the same server:

| Field | Value |
|-------|-------|
| Authentication Type | OAuth 2.0 |
| Grant Type | Token Exchange (RFC 8693, On-Behalf-Of User) |
| Issuer URL | Auth Server **A** issuer: `https://demo-arbind-lochan-mishra.okta.com/oauth2/{serverA-id}` |
| Client ID | PointGuardAI Gateway app client ID |
| Client Secret | PointGuardAI Gateway app client secret |
| Token URL | Auth Server **B** token endpoint: `https://demo-arbind-lochan-mishra.okta.com/oauth2/{serverB-id}/v1/token` |
| Fall back to Client Credentials | ☐ **Unchecked** |

Leave **Requested Token Type** and **Subject Token Type** empty (PointGuardAI sets these).

**PointGuardAI applies these additional settings** (tell them after you save):
- `subject_token_source: x-user-token`
- `audience: api://banking-mcp` (Auth Server B's audience)
- `scopes`: the 10 banking scopes
- Token types: `access_token` for both subject and requested

### Step PG-4: Create virtual server
**MCP → Virtual Servers → Create virtual server**

| Field | Value |
|-------|-------|
| Name | `banking-agent` |
| MCP Servers | `banking` (from PG-2) |
| Associated Tools | All tools |

Copy the virtual server ID → set as `PG_VIRTUAL_SERVER_ID` in `agent/.env`.

### Step PG-5: Write access rules
**Extensions → Policies → Access Rules → New rule**

| Rule name | Effect | Condition |
|-----------|--------|-----------|
| No human, no action | Deny | User token present = false |
| Refuse undeclared agents | Deny | Agent is not one of `banking-agent` |

---

## Environment Variable Reference

### `banking-app/backend/.env`

| Variable | Okta value | Source |
|----------|-----------|--------|
| `OKTA_ISSUER` | Auth Server **A** issuer URL | Step 1 |
| `OKTA_AUDIENCE` | `api://banking` | Step 1 (audience you set) |
| `OKTA_MCP_ISSUER` | Auth Server **B** issuer URL | Step 2 |
| `OKTA_MCP_AUDIENCE` | `api://banking-mcp` | Step 2 (audience you set) |

### `banking-app/frontend/.env`

| Variable | Okta value | Source |
|----------|-----------|--------|
| `VITE_OKTA_ISSUER` | Auth Server **A** issuer URL | Step 1 |
| `VITE_OKTA_CLIENT_ID` | `SecureBank Frontend` client ID | Step 6 |

### `agent/.env`

| Variable | Okta value | Source |
|----------|-----------|--------|
| `OKTA_ISSUER` | Auth Server **A** issuer URL | Step 1 |
| `OKTA_CLIENT_ID` | `SecureBank Frontend` client ID | Step 6 |
| `PG_GATEWAY_URL` | PointGuardAI gateway URL | Step PG-1 |
| `PG_GATEWAY_TOKEN` | PointGuardAI API token | Step PG-1 |
| `PG_VIRTUAL_SERVER_ID` | Virtual server ID | Step PG-4 |
| `PG_AGENT_NAME` | `banking-agent` | Step PG-4 |

> **Note on `USER_TOKEN`:** The token the agent puts in `x-user-token` is an **Auth Server A** access token (obtained via PKCE sign-in). The PointGuardAI Gateway then exchanges it at Auth Server B to get the MCP-scoped token. You never need to manually obtain an Auth Server B token — the gateway does that exchange for you.
