'use strict';

// Broker-mode demo server: a fake "Payments API" MCP server that insists on its own API key, a tiny agent
// runner that calls Warden as the demo agents, admin actions, and the demo page. Binds to localhost only.
//   node demo/broker/server.js     (after: node demo/broker/setup.js)

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const L = require('./lib');

function createDemo() {
  let state = null;
  let stateMtime = 0;
  let validKey = L.newPaymentsKey(); // the key the fake Payments API currently accepts
  let lastUpstream = null;
  let upstreamCalls = 0;
  // Picks up setup.js (or teardown.js) having run since the server started, including rotated agent tokens.
  const refreshState = () => {
    let mtime = 0;
    try { mtime = fs.statSync(L.STATE_FILE).mtimeMs; } catch { /* no state file */ }
    if (mtime === stateMtime) return;
    stateMtime = mtime;
    state = mtime ? L.readState() : null;
    if (state) validKey = state.paymentsKey;
  };
  const persist = () => {
    if (!state) return;
    L.writeState(state);
    try { stateMtime = fs.statSync(L.STATE_FILE).mtimeMs; } catch { /* ignore */ }
  };

  const app = express();
  app.use(express.json());

  // ── the fake upstream: a Payments API MCP server ───────────────────────────────────────────────
  app.post('/mcp', (req, res) => {
    refreshState();
    const m = req.body || {};
    const ok = (result, headers = {}) => { res.set(headers); res.json({ jsonrpc: '2.0', id: m.id, result }); };
    if (m.method === 'initialize') return ok({ protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'demo-payments-api', version: '1.0.0' } }, { 'mcp-session-id': `demo-${crypto.randomBytes(4).toString('hex')}` });
    if (m.method === 'notifications/initialized') return res.status(202).end();
    if (m.method === 'tools/list') return ok({ tools: [{ name: 'get_report', description: 'Payments report for an account', inputSchema: { type: 'object', properties: { account: { type: 'string' }, webhook_secret: { type: 'string' } } } }] });
    if (m.method === 'tools/call') {
      upstreamCalls++;
      const key = req.headers['x-payments-key'];
      const args = m.params?.arguments || {};
      lastUpstream = {
        keyMasked: L.mask(key) || '(no key sent)', keyValid: key === validKey,
        webhookMasked: L.mask(args.webhook_secret) || '(none)', webhookPlaceholderReplaced: typeof args.webhook_secret === 'string' && !args.webhook_secret.startsWith('vault://'),
      };
      if (key !== validKey) return ok({ isError: true, content: [{ type: 'text', text: 'HTTP 401 - missing or invalid X-Payments-Key' }] });
      // Deliberately sloppy: echoes the credentials it received, to show Warden keeps them from the agent.
      return ok({ content: [{ type: 'text', text: `Report for ${args.account}: 3 payments totalling $1,240.00. (authenticated with ${key}; webhook secret ${args.webhook_secret})` }] });
    }
    res.status(400).json({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'Method not found' } });
  });

  // ── demo API (used by the page) ────────────────────────────────────────────────────────────────
  const needSetup = (res) => { if (!state) { res.status(409).json({ error: 'Demo is not set up. Run: node demo/broker/setup.js' }); return true; } return false; };
  const handle = (fn) => async (req, res) => {
    try { refreshState(); await fn(req, res); } catch (e) { res.status(500).json({ error: e.message }); }
  };

  app.get('/api/state', handle(async (_req, res) => {
    if (!state) return res.json({ setupDone: false, wardenUrl: L.WARDEN_URL, agentRequest: L.AGENT_REQUEST });
    let reachable = true, secrets = [], policies = [];
    try {
      const [s, p] = await Promise.all([L.warden('GET', '/api/vault/secrets'), L.warden('GET', '/api/vault/policies')]);
      if (s.status !== 200 || p.status !== 200) throw new Error('bad status');
      secrets = s.json; policies = p.json;
    } catch { reachable = false; }
    const keySecret = secrets.find(s => s.name === L.NAMES.keySecret), hookSecret = secrets.find(s => s.name === L.NAMES.hookSecret);
    const policy = policies.find(p => p.name === L.NAMES.vaultPolicy);
    res.json({
      setupDone: true, wardenUrl: L.WARDEN_URL, wardenReachable: reachable, agentRequest: L.AGENT_REQUEST,
      agents: [{ key: 'report', name: L.NAMES.reportAgent }, { key: 'rogue', name: L.NAMES.rogueAgent }],
      upstream: { acceptsMasked: L.mask(validKey), calls: upstreamCalls },
      vault: {
        holdsMasked: L.mask(state.vaultKey), inSync: state.vaultKey === validKey,
        keySecretVersion: keySecret?.version ?? null, keySecretActive: keySecret ? !!keySecret.is_active : null,
        hookSecretActive: hookSecret ? !!hookSecret.is_active : null, policyActive: policy ? !!policy.is_active : null,
      },
    });
  }));

  // The agent calls the tool through Warden. who: report | rogue | anonymous
  app.post('/api/run', handle(async (req, res) => {
    if (needSetup(res)) return;
    const who = req.body?.who;
    const agent = who === 'report' ? state.agents.report : who === 'rogue' ? state.agents.rogue : who === 'anonymous' ? null : undefined;
    if (agent === undefined) return res.status(400).json({ error: 'who must be report, rogue or anonymous' });
    lastUpstream = null;
    const r = await L.warden('POST', `/api/proxy/${state.ids.vs}`,
      { mcp_server_id: state.ids.mcp, tool_name: L.AGENT_REQUEST.tool, arguments: L.AGENT_REQUEST.arguments },
      { Authorization: `Bearer ${L.devUserJwt()}`, ...(agent ? { 'X-Agent-Token': agent.token } : {}) });
    const text = r.json?.result?.content?.[0]?.text;
    const upstreamRejected = typeof text === 'string' && /^HTTP 401/.test(text);
    res.json({
      who, sentAs: agent ? (who === 'report' ? L.NAMES.reportAgent : L.NAMES.rogueAgent) : '(no agent identity)',
      httpStatus: r.status, allowed: r.status === 200 && !upstreamRejected, upstreamRejected,
      reply: text ?? r.json?.reason ?? r.json?.error ?? r.text.slice(0, 300),
      upstreamSaw: lastUpstream,
    });
  }));

  // The permitted agent tries to simply ask the vault for the secret. Broker permission is not reveal permission.
  app.post('/api/reveal-attempt', handle(async (_req, res) => {
    if (needSetup(res)) return;
    const r = await L.warden('POST', '/api/vault/checkout', { secret: L.NAMES.keySecret, virtual_server_id: state.ids.vs }, { 'X-Agent-Token': state.agents.report.token });
    res.json({ httpStatus: r.status, allowed: r.status === 200, message: r.json?.error || null });
  }));

  const sync = async () => {
    const r = await L.warden('POST', `/api/vault/secrets/${state.ids.keySecret}/rotate`, { value: validKey });
    if (r.status !== 200) throw new Error(`Vault rotate failed (HTTP ${r.status})`);
    state.vaultKey = validKey; state.paymentsKey = validKey; persist();
    return r.json.version;
  };

  app.post('/api/provider-rotate', handle(async (_req, res) => { // the Payments provider issues a new key
    if (needSetup(res)) return;
    validKey = L.newPaymentsKey();
    res.json({ ok: true });
  }));
  app.post('/api/vault-sync', handle(async (_req, res) => { // an admin puts the new key into the vault
    if (needSetup(res)) return;
    res.json({ ok: true, version: await sync() });
  }));
  app.post('/api/toggle-policy', handle(async (req, res) => {
    if (needSetup(res)) return;
    const r = await L.warden('PUT', `/api/vault/policies/${state.ids.vaultPolicy}`, { is_active: !!req.body?.active });
    res.status(r.status === 200 ? 200 : 502).json({ ok: r.status === 200 });
  }));
  app.post('/api/toggle-secret', handle(async (req, res) => {
    if (needSetup(res)) return;
    const r = await L.warden('PUT', `/api/vault/secrets/${state.ids.hookSecret}`, { is_active: !!req.body?.active });
    res.status(r.status === 200 ? 200 : 502).json({ ok: r.status === 200 });
  }));
  app.post('/api/reset', handle(async (_req, res) => {
    if (needSetup(res)) return;
    await L.warden('PUT', `/api/vault/policies/${state.ids.vaultPolicy}`, { is_active: true });
    await L.warden('PUT', `/api/vault/secrets/${state.ids.hookSecret}`, { is_active: true });
    validKey = L.newPaymentsKey();
    await sync();
    lastUpstream = null;
    res.json({ ok: true });
  }));

  // The vault's own audit trail for the demo's secrets/agents. Values are never in it.
  app.get('/api/audit', handle(async (_req, res) => {
    const r = await L.warden('GET', '/api/vault/activity?limit=300');
    if (r.status !== 200) return res.status(502).json({ error: 'Could not read the vault activity log' });
    const rows = r.json
      .filter(e => String(e.data?.secret_name || '').startsWith('demo-') || String(e.data?.agent_name || '').startsWith('demo-'))
      .filter(e => ['broker', 'reveal', 'rotate', 'update'].includes(e.data?.operation))
      .slice(0, 14)
      .map(e => ({
        time: new Date(e.created_at.replace(' ', 'T') + 'Z').toISOString(), level: e.level, summary: e.summary,
        operation: e.data.operation, via: e.data.via || null, principal: e.data.principal, agent: e.data.agent_name || null,
        secret: e.data.secret_name || null, decision: e.data.decision || null, reason: e.data.reason || null,
      }));
    res.json(rows);
  }));

  app.use(express.static(path.join(__dirname, 'public')));
  return app;
}

function start(port = L.DEMO_PORT) {
  const app = createDemo();
  return new Promise((resolve, reject) => {
    const server = app.listen(port, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
}

if (require.main === module) {
  start().then(() => {
    const configured = !!L.readState();
    console.log(`\nBroker demo running:  http://localhost:${L.DEMO_PORT}`);
    console.log(`Warden:               ${L.WARDEN_URL}`);
    if (!configured) console.log('\nNot set up yet. Run in another terminal:  node demo/broker/setup.js   (then reload the page)');
  }).catch(e => { console.error(e.code === 'EADDRINUSE' ? `Port ${L.DEMO_PORT} is in use (set DEMO_PORT).` : e.message); process.exit(1); });
}

module.exports = { createDemo, start };
