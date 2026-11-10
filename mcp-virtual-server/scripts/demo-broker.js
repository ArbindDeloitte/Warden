'use strict';

// Live demo of Credential Vault BROKER mode. Boots Warden on a THROWAWAY database plus a fake "Payments API"
// upstream that insists on its own API key, then shows an agent using that key without ever holding it.
//   node scripts/demo-broker.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-broker-demo-'));
Object.assign(process.env, {
  SQLITE_PATH: path.join(tmp, 'demo.db'), PORT: process.env.DEMO_PORT || '3021', NODE_ENV: 'development',
  JWKS_URI: '', REDIS_URL: 'redis://127.0.0.1:1',
});
delete process.env.WARDEN_SECRETS_KEY;
const W = `http://127.0.0.1:${process.env.PORT}`;

const c = { dim: s => `\x1b[2m${s}\x1b[0m`, bold: s => `\x1b[1m${s}\x1b[0m`, green: s => `\x1b[32m${s}\x1b[0m`, red: s => `\x1b[31m${s}\x1b[0m`, cyan: s => `\x1b[36m${s}\x1b[0m`, yellow: s => `\x1b[33m${s}\x1b[0m` };
const sleep = ms => new Promise(r => setTimeout(r, ms));
let held = 0; const broken = [];
const expect = (name, cond) => { if (cond) { held++; console.log(`  ${c.green('✓')} ${name}`); } else { broken.push(name); console.log(`  ${c.red('✗')} ${name}`); } };
const scene = (n, t) => console.log(`\n${c.bold(c.cyan(`── Scene ${n}: ${t}`))}`);
const show = (label, v) => console.log(`  ${c.dim(label.padEnd(26))} ${typeof v === 'string' ? v : JSON.stringify(v)}`);

async function api(method, p, body, headers = {}) {
  const r = await fetch(W + p, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: r.status, json, text };
}

// ── the fake upstream: a "Payments API" MCP server that requires X-Payments-Key ─────────────────────
let validKey = 'sk_live_payments_7Hq29xKd41Za';
let lastUpstreamRequest = null;
const upstream = http.createServer((req, res) => {
  let body = ''; req.on('data', d => { body += d; });
  req.on('end', () => {
    let m = {}; try { m = JSON.parse(body || '{}'); } catch {}
    const ok = (result, extra = {}) => { res.writeHead(200, { 'content-type': 'application/json', ...extra }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result })); };
    if (m.method === 'initialize') return ok({ protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'payments-api', version: '1' } }, { 'mcp-session-id': 's-' + crypto.randomBytes(3).toString('hex') });
    if (m.method === 'notifications/initialized') { res.writeHead(202); return res.end(); }
    if (m.method === 'tools/call') {
      const key = req.headers['x-payments-key'];
      lastUpstreamRequest = { header: key, args: m.params.arguments };
      if (key !== validKey) return ok({ isError: true, content: [{ type: 'text', text: 'HTTP 401 - missing or invalid X-Payments-Key' }] });
      // A sloppy upstream that echoes the credentials it received. Warden must not let them reach the agent.
      return ok({ content: [{ type: 'text', text: `Report for ${m.params.arguments.account}: 3 payments, $1,240.00. (authenticated with ${key}; webhook secret ${m.params.arguments.webhook_secret})` }] });
    }
    res.writeHead(400); res.end('{}');
  });
});

async function main() {
  await new Promise(r => upstream.listen(0, '127.0.0.1', r));
  const UP = `http://127.0.0.1:${upstream.address().port}/mcp`;
  process.chdir(tmp);
  const app = require(path.join(__dirname, '..', 'src', 'app.js'));
  for (let i = 0; i < 80; i++) { try { if ((await fetch(W + '/api/health')).ok) break; } catch {} await sleep(100); }

  console.log(c.bold('\nCredential Vault — BROKER mode demo'));
  console.log(c.dim('Throwaway Warden + fake Payments API. Nothing here touches your real Warden or database.'));

  // ── setup (what an admin does once, in the Warden UI) ─────────────────────────────────────────────
  const agent = async name => { const r = await api('POST', '/api/agents', { name }); return { id: r.json.id, token: r.json.token, name }; };
  const reportAgent = await agent('report-agent'), rogueAgent = await agent('rogue-agent');
  const vs = (await api('POST', '/api/virtual-servers', { name: 'payments-vs', require_obo: 0, allow_anonymous: true, features_enabled: ['policy'] })).json.id;
  const SECRET_KEY = validKey, SECRET_HOOK = 'whsec_9fA3kLm2Qp7Xw5Zr';
  const keyId = (await api('POST', '/api/vault/secrets', { name: 'payments-api-key', type: 'api_key', value: SECRET_KEY })).json.id;
  await api('POST', '/api/vault/secrets', { name: 'webhook-secret', type: 'generic', value: SECRET_HOOK });
  // The upstream's own credential is wired in as a vault reference — never as plaintext.
  const mcp = (await api('POST', '/api/mcp', { name: 'payments-api', url: UP, auth_type: 'apikey', auth_config: { header: 'X-Payments-Key', key: 'vault://payments-api-key' } })).json.id;
  await api('POST', `/api/virtual-servers/${vs}/tools`, { mcp_server_id: mcp, tool_name: '*' });
  await api('POST', '/api/token-policies', { virtual_server_id: vs, name: 'allow-tools', effect: 'permit', policy_json: { actions: [{ mcp_server_id: '*', tool: '*' }], conditions: [] } });
  const pol = (await api('POST', '/api/vault/policies', { name: 'report-agent may broker on payments-vs', effect: 'permit', caller_type: 'agent', caller_value: reportAgent.id, secret_id: '*', virtual_server_id: vs, operations: ['broker'] })).json.id;
  const secretsList = (await api('GET', '/api/vault/secrets')).json;
  const hookId = secretsList.find(s => s.name === 'webhook-secret').id;

  const userJwt = ['{"alg":"none"}', '{"sub":"user-1"}'].map(j => Buffer.from(j).toString('base64url')).join('.') + '.sig';
  const callTool = (ag, args) => api('POST', `/api/proxy/${vs}`, { mcp_server_id: mcp, tool_name: 'get_report', arguments: args },
    { Authorization: `Bearer ${userJwt}`, ...(ag ? { 'X-Agent-Token': ag.token } : {}) });
  const REQ = { account: 'ACME-001', webhook_secret: 'vault://webhook-secret' };
  const leaks = text => [SECRET_KEY, SECRET_HOOK, validKey].some(s => text.includes(s));

  // ═════════════════════════════════════════════════════════════════════════════════════════════════
  scene(1, 'What the agent has');
  show('agent holds', 'only its Warden agent token (no API keys, no secrets, no .env credentials)');
  show('request it sends', { tool: 'get_report', arguments: REQ });
  console.log(`  ${c.dim('→ "vault://webhook-secret" is just a name. The payments API key is not in the request at all.')}`);

  scene(2, 'Brokered call: Warden injects the credentials');
  const r1 = await callTool(reportAgent, REQ);
  const reply = r1.json?.result?.content?.[0]?.text || r1.text;
  show('HTTP status', String(r1.status));
  show('what the agent received', reply);
  show('upstream saw header', c.yellow(`X-Payments-Key: ${lastUpstreamRequest.header}`) + c.dim('   (visible only because we run the fake upstream)'));
  show('upstream saw argument', c.yellow(`webhook_secret: ${lastUpstreamRequest.args.webhook_secret}`));
  expect('call succeeded', r1.status === 200 && /3 payments/.test(reply));
  expect('upstream received the real API key header, injected by Warden', lastUpstreamRequest.header === SECRET_KEY);
  expect('upstream received the real webhook secret in place of the placeholder', lastUpstreamRequest.args.webhook_secret === SECRET_HOOK);
  expect('the upstream echoed both secrets, yet the agent only sees [REDACTED:…]', !leaks(r1.text) && /REDACTED:vault:\/\/payments-api-key/.test(reply) && /REDACTED:vault:\/\/webhook-secret/.test(reply));

  scene(3, 'Brokering is not revealing: the agent cannot fetch the secret itself');
  const co = await api('POST', '/api/vault/checkout', { secret: 'payments-api-key', virtual_server_id: vs }, { 'X-Agent-Token': reportAgent.token });
  show('checkout attempt', `HTTP ${co.status} — ${co.json?.error}`);
  expect('"broker" permission does not allow "reveal"', co.status === 403 && !leaks(co.text));

  scene(4, 'An agent without a policy is refused, and the upstream is never contacted');
  lastUpstreamRequest = null;
  const rogue = await callTool(rogueAgent, REQ);
  show('rogue-agent call', `HTTP ${rogue.status} — ${rogue.json?.reason}`);
  const anon = await callTool(null, REQ);
  show('no agent identity', `HTTP ${anon.status} — ${anon.json?.reason}`);
  expect('rogue-agent denied', rogue.status === 403);
  expect('anonymous caller denied', anon.status === 403);
  expect('upstream was never called for either', lastUpstreamRequest === null);

  scene(5, 'Rotate the secret: the agent changes nothing, the next call just works');
  validKey = 'sk_live_payments_ROTATED_55bT8wQe9L';
  const stale = await callTool(reportAgent, REQ);
  show('provider rotated its key', c.dim('vault still holds the old one →') + ' ' + (stale.json?.result?.content?.[0]?.text || stale.text));
  expect('before rotating the vault, the old key is rejected by the upstream', /401/.test(stale.text));
  const rot = await api('POST', `/api/vault/secrets/${keyId}/rotate`, { value: validKey });
  show('admin rotates in the vault', `version ${rot.json.version}`);
  const r5 = await callTool(reportAgent, REQ);
  show('same agent, same request', r5.json?.result?.content?.[0]?.text || r5.text);
  expect('after the vault rotation the identical request succeeds', r5.status === 200 && /3 payments/.test(r5.text) && lastUpstreamRequest.header === validKey);
  expect('the new key is still redacted from the reply', !leaks(r5.text));

  scene(6, 'Kill switch: disable the secret and brokering stops immediately');
  await api('PUT', `/api/vault/secrets/${hookId}`, { is_active: false });
  lastUpstreamRequest = null;
  const r6 = await callTool(reportAgent, REQ);
  show('after disabling webhook-secret', `HTTP ${r6.status} — ${r6.json?.reason}`);
  expect('call fails closed (no partial call with a missing credential)', r6.status === 403 && lastUpstreamRequest === null);
  await api('PUT', `/api/vault/secrets/${hookId}`, { is_active: true });
  await api('PUT', `/api/vault/policies/${pol}`, { is_active: false });
  const r6b = await callTool(reportAgent, REQ);
  show('after disabling the policy', `HTTP ${r6b.status} — ${r6b.json?.reason}`);
  expect('revoking the policy cuts access on the very next call (brokering is never cached)', r6b.status === 403);

  scene(7, 'The audit trail: every use is recorded, and no value is ever logged');
  const act = (await api('GET', '/api/vault/activity?limit=500')).json.reverse().filter(e => ['broker', 'reveal'].includes(e.data.operation));
  for (const e of act.slice(0, 12)) console.log(`  ${c.dim(e.created_at)}  ${e.level === 'warn' ? c.red('DENY ') : c.green('allow')}  ${e.summary.padEnd(46)} ${c.dim(`via ${e.data.via}`)}${e.data.reason ? c.dim(' — ' + e.data.reason) : ''}`);
  const everything = JSON.stringify(act);
  expect('allows and denies are all recorded', act.some(e => e.data.decision === 'allow') && act.some(e => e.data.decision === 'deny'));
  expect('no secret value (current or previous) appears anywhere in the audit log', ![SECRET_KEY, SECRET_HOOK, validKey].some(s => everything.includes(s)));

  console.log(`\n${broken.length ? c.red(`${held} expectations held, ${broken.length} BROKEN:`) : c.green(c.bold(`All ${held} expectations held.`))}`);
  if (broken.length) console.log(broken.map(b => ` - ${b}`).join('\n'));
  return broken.length;
}

function done(code) {
  try { upstream.close(); } catch {}
  setTimeout(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} process.exit(code ? 1 : 0); }, 300);
}
main().then(done, e => { console.error('\nDEMO ERROR:', e); done(1); });
