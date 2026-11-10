'use strict';

// Creates the demo objects in the Warden at WARDEN_URL (default http://localhost:3003).
// Idempotent: safe to run again. Everything is named "demo-…"; `node demo/broker/teardown.js` removes it all.
//   node demo/broker/setup.js

const L = require('./lib');

async function expectOk(r, what) {
  if (r.status >= 400 || !r.json) throw new Error(`${what} failed (HTTP ${r.status}): ${r.text.slice(0, 200)}`);
  return r.json;
}

async function setup({ log = console.log } = {}) {
  const meta = await L.warden('GET', '/api/vault/meta').catch(e => ({ status: 0, text: e.message }));
  if (meta.status !== 200) {
    throw new Error(`Cannot use the Credential Vault at ${L.WARDEN_URL} (HTTP ${meta.status}). Is Warden running, and was it restarted after the vault was added?`);
  }
  const prev = L.readState() || {};
  const paymentsKey = prev.paymentsKey || L.newPaymentsKey();
  const hookSecret = prev.hookSecret || L.newWebhookSecret();

  // agents (an existing demo agent gets a fresh token, since a token is only shown once)
  const agents = (await expectOk(await L.warden('GET', '/api/agents'), 'list agents'));
  const ensureAgent = async (name) => {
    const found = agents.find(a => a.name === name);
    if (found) {
      const r = await expectOk(await L.warden('POST', `/api/agents/${found.id}/rotate-token`), 'rotate agent token');
      return { id: found.id, token: r.token };
    }
    const r = await expectOk(await L.warden('POST', '/api/agents', { name, description: 'Broker-mode demo agent' }), 'create agent');
    return { id: r.id, token: r.token };
  };
  const report = await ensureAgent(L.NAMES.reportAgent);
  const rogue = await ensureAgent(L.NAMES.rogueAgent);
  log(`agents:        ${L.NAMES.reportAgent}, ${L.NAMES.rogueAgent}`);

  // vault secrets
  const secrets = await expectOk(await L.warden('GET', '/api/vault/secrets'), 'list secrets');
  const ensureSecret = async (name, type, value) => {
    const found = secrets.find(s => s.name === name);
    if (found) {
      await expectOk(await L.warden('POST', `/api/vault/secrets/${found.id}/rotate`, { value }), 'rotate secret');
      if (!found.is_active) await L.warden('PUT', `/api/vault/secrets/${found.id}`, { is_active: true });
      return found.id;
    }
    return (await expectOk(await L.warden('POST', '/api/vault/secrets', { name, type, value, description: 'Broker-mode demo' }), 'create secret')).id;
  };
  const keySecretId = await ensureSecret(L.NAMES.keySecret, 'api_key', paymentsKey);
  const hookSecretId = await ensureSecret(L.NAMES.hookSecret, 'generic', hookSecret);
  log(`vault secrets: ${L.NAMES.keySecret}, ${L.NAMES.hookSecret}`);

  // virtual server (no JWKS, so the demo can use an unsigned dev token) with only the policy feature on
  const vsList = await expectOk(await L.warden('GET', '/api/virtual-servers'), 'list virtual servers');
  const vsId = vsList.find(v => v.name === L.NAMES.vs)?.id
    || (await expectOk(await L.warden('POST', '/api/virtual-servers', { name: L.NAMES.vs, description: 'Broker-mode demo', require_obo: 0, allow_anonymous: true, features_enabled: ['policy'], vault_enabled: true }), 'create virtual server')).id;

  // the fake Payments API, registered with its OWN credential as a vault reference (never plaintext)
  const mcpUrl = `http://127.0.0.1:${L.DEMO_PORT}/mcp`;
  const mcpBody = { name: L.NAMES.mcp, url: mcpUrl, description: 'Broker-mode demo upstream', auth_type: 'apikey', auth_config: { header: 'X-Payments-Key', key: `vault://${L.NAMES.keySecret}` } };
  const mcpList = await expectOk(await L.warden('GET', '/api/mcp'), 'list MCP servers');
  const existingMcp = mcpList.find(m => m.name === L.NAMES.mcp || m.url === mcpUrl);
  let mcpId;
  if (existingMcp) { mcpId = existingMcp.id; await expectOk(await L.warden('PUT', `/api/mcp/${mcpId}`, mcpBody), 'update MCP server'); }
  else mcpId = (await expectOk(await L.warden('POST', '/api/mcp', mcpBody), 'register MCP server')).id;
  await L.warden('POST', `/api/virtual-servers/${vsId}/tools`, { mcp_server_id: mcpId, tool_name: '*' }); // 409 if already assigned
  log(`MCP server:    ${L.NAMES.mcp} -> ${mcpUrl}  (auth: X-Payments-Key = vault://${L.NAMES.keySecret})`);

  // tool policy (lets calls through) and the vault policy (who may broker what, where)
  const toolPols = await expectOk(await L.warden('GET', `/api/token-policies/virtual-server/${vsId}`), 'list tool policies');
  let toolPolicyId = toolPols.find(p => p.name === L.NAMES.toolPolicy)?.id;
  if (!toolPolicyId) {
    toolPolicyId = (await expectOk(await L.warden('POST', '/api/token-policies', {
      virtual_server_id: vsId, name: L.NAMES.toolPolicy, effect: 'permit', policy_json: { actions: [{ mcp_server_id: '*', tool: '*' }], conditions: [] },
    }), 'create tool policy')).id;
  }
  const vaultPols = await expectOk(await L.warden('GET', '/api/vault/policies'), 'list vault policies');
  const vp = { name: L.NAMES.vaultPolicy, effect: 'permit', caller_type: 'agent', caller_value: report.id, secret_id: '*', virtual_server_id: vsId, operations: ['broker'], is_active: true };
  let vaultPolicyId = vaultPols.find(p => p.name === L.NAMES.vaultPolicy)?.id;
  if (vaultPolicyId) await expectOk(await L.warden('PUT', `/api/vault/policies/${vaultPolicyId}`, vp), 'update vault policy');
  else vaultPolicyId = (await expectOk(await L.warden('POST', '/api/vault/policies', vp), 'create vault policy')).id;
  log(`vault policy:  ${L.NAMES.reportAgent} may BROKER on ${L.NAMES.vs} (nothing else)`);

  const state = {
    wardenUrl: L.WARDEN_URL, paymentsKey, hookSecret, vaultKey: paymentsKey,
    agents: { report, rogue },
    ids: { vs: vsId, mcp: mcpId, keySecret: keySecretId, hookSecret: hookSecretId, vaultPolicy: vaultPolicyId, toolPolicy: toolPolicyId },
  };
  L.writeState(state);
  return state;
}

if (require.main === module) {
  setup().then(() => {
    console.log(`\nDone. Now run:  node demo/broker/server.js   and open  http://localhost:${L.DEMO_PORT}`);
    console.log(`(State with the demo agent tokens is saved to demo/broker/.state.json, which is git-ignored.)`);
  }).catch(e => { console.error(`\nSetup failed: ${e.message}`); process.exit(1); });
}

module.exports = { setup };
