# Broker-mode demo

Shows the Credential Vault's **broker** mode: an agent uses a payments API key it never holds. Warden injects the
key (and a webhook secret) after checking a vault policy, and strips both from the upstream's reply.

Everything is created in your Warden under `demo-…` names and removed by `teardown.js`.

```bash
cd mcp-virtual-server
node demo/broker/setup.js      # creates the demo agents, secrets, virtual server, MCP server and policies
node demo/broker/server.js     # fake Payments API + demo page  ->  http://localhost:3050
node demo/broker/teardown.js   # removes everything the demo created
```

Warden must be running with the vault (restart it after pulling the vault code). Use `WARDEN_URL=...` if it is not
on `http://localhost:3003`, and `DEMO_PORT=...` to move the demo off 3050.

## Walkthrough (about 3 minutes)

1. **Run as report-agent**: the request holds only `vault://` names. Warden injects the real values; the upstream
   echoes them back and Warden redacts them before the agent sees the reply.
2. **Try to reveal the secret**: refused. Broker permission is not reveal permission.
3. **Run as rogue-agent / with no identity**: refused before the upstream is contacted.
4. **① Provider rotates its key, then run**: fails (the upstream rejects the stale key). **② Admin updates the vault,
   then run**: the identical request works. No agent or config changed.
5. **Disable the policy (or the webhook secret), then run**: refused on the very next call.
6. Read the **audit trail** at the bottom: every use is recorded, and no value ever is.

## What it creates

| Kind | Name |
|---|---|
| Agents | `demo-report-agent` (permitted), `demo-rogue-agent` (no policy) |
| Vault secrets | `demo-payments-api-key`, `demo-webhook-secret` |
| Virtual server | `demo-payments-vs` (no JWKS, so an unsigned dev token works; policy feature only) |
| MCP server | `demo-payments-api`, auth `X-Payments-Key = vault://demo-payments-api-key` |
| Vault policy | `demo-report-agent` may `broker` on `demo-payments-vs` (nothing else) |

The demo server binds to localhost, keeps the demo agents' tokens in `demo/broker/.state.json` (git-ignored), and
never sends a token or a full secret value to the browser.

`node demo/broker/test-demo.js` runs the whole demo against a throwaway Warden and checks it end to end.
