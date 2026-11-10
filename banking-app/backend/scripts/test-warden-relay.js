// End-to-end test for the Warden relay: browser -> banking backend (/api/warden) -> Warden -> upstream.
// Boots the real Warden on a THROWAWAY database and key file, a fake upstream MCP server and a fake A2A
// agent, then drives the real relay code. Also boots the real backend index.js to check the wiring.
//   node scripts/test-warden-relay.js

import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import crypto from 'crypto';
import { spawn } from 'child_process';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import express from 'express';

const here = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.join(here, '..');
const wardenDir = path.join(backendDir, '..', '..', 'mcp-virtual-server');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-relay-test-'));
const WARDEN_PORT = 3016, RELAY_PORT = 3017, REAL_PORT = 3018, INTRUDER_PORT = 3019;
Object.assign(process.env, {
  SQLITE_PATH: path.join(tmp, 'warden.db'), PORT: String(WARDEN_PORT), NODE_ENV: 'development',
  JWKS_URI: '', REDIS_URL: 'redis://127.0.0.1:1',
});
delete process.env.WARDEN_SECRETS_KEY;
process.chdir(tmp); // keep Warden's dotenv from reading a real .env

const W = `http://127.0.0.1:${WARDEN_PORT}`;
const { createVaultClient, WardenVaultError } = await import('../src/services/wardenVault.js');
const { createWardenGateway, loadWardenConfig } = await import('../src/services/wardenGateway.js');
const { createWardenRouter } = await import('../src/routes/warden.js');

let passed = 0; const failures = [];
function check(name, cond, detail) {
  if (cond) { passed++; console.log(`  ok   ${name}`); }
  else { failures.push(name); console.log(`  FAIL ${name}${detail !== undefined ? '  -> ' + (typeof detail === 'string' ? detail : JSON.stringify(detail)) : ''}`); }
}
const section = (t) => console.log(`\n== ${t}`);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const userJwt = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'user-1', email: 'u@example.com' })}.sig`;

async function call(base, method, p, body, headers = {}) {
  const res = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text, headers: res.headers };
}
const warden = (m, p, b) => call(W, m, p, b);
const authed = { Authorization: `Bearer ${userJwt}` };

// ── fake upstream MCP + fake A2A agent ─────────────────────────────────────────
const upstreamCalls = [];
const mcp = http.createServer((req, res) => {
  let body = ''; req.on('data', c => { body += c; });
  req.on('end', () => {
    let msg = {}; try { msg = JSON.parse(body || '{}'); } catch {}
    upstreamCalls.push(msg);
    const ok = (result, extra = {}) => { res.writeHead(200, { 'content-type': 'application/json', ...extra }); res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result })); };
    if (msg.method === 'initialize') return ok({ protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'fake', version: '1' } }, { 'mcp-session-id': 's-' + crypto.randomBytes(3).toString('hex') });
    if (msg.method === 'notifications/initialized') { res.writeHead(202); return res.end(); }
    if (msg.method === 'tools/call') return ok({ content: [{ type: 'text', text: JSON.stringify({ args: msg.params.arguments, accounts: [{ id: 'acc-1' }] }) }] });
    res.writeHead(400); res.end('{}');
  });
});
const a2a = http.createServer((req, res) => {
  let body = ''; req.on('data', c => { body += c; });
  req.on('end', () => {
    const msg = JSON.parse(body || '{}');
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { task: { id: 'task-1', status: { state: 'TASK_STATE_COMPLETED' }, artifacts: [{ parts: [{ text: 'here are your cards' }, { data: { cards: [{ last4: '1111' }] } }] }] } } }));
  });
});
const listen = (srv, port = 0) => new Promise(r => srv.listen(port, '127.0.0.1', r));

let relayServer, intruderServer, realProc;
async function main() {
  await listen(mcp); await listen(a2a);
  const MCP_URL = `http://127.0.0.1:${mcp.address().port}/mcp`, A2A_URL = `http://127.0.0.1:${a2a.address().port}/rpc`;

  const require = createRequire(import.meta.url);
  require(path.join(wardenDir, 'src', 'app.js'));
  for (let i = 0; i < 60; i++) { try { if ((await fetch(W + '/api/health')).ok) break; } catch {} await sleep(100); }
  const wdb = require(path.join(wardenDir, 'src', 'db', 'database.js'));

  // ── Warden fixtures (mirrors production: API key required, agents allowlisted, creds only in the vault) ──
  const mkAgent = async (name) => { const r = await warden('POST', '/api/agents', { name }); return { id: r.json.id, token: r.json.token, name }; };
  // exactly the two real agents (plus an unrelated one used only to prove denials)
  const bank = await mkAgent('bank-agent'), card = await mkAgent('a2a-agent'), intruder = await mkAgent('intruder');
  const vsTools = (await warden('POST', '/api/virtual-servers', { name: 'banking-vs', require_obo: 0, features_enabled: ['policy'], require_agent_token: 1 })).json.id;
  const vsA2a = (await warden('POST', '/api/virtual-servers', { name: 'a2a-vs', protocol: 'a2a', features_enabled: [] })).json.id;
  const chatVs = (await warden('POST', '/api/virtual-servers', { name: 'chat-vs', features_enabled: ['interceptors'], require_obo: 0, allow_anonymous: true })).json.id;
  await warden('POST', `/api/interceptors/${chatVs}/rules`, { name: 'mask pii', scanner: '*', category: 'pii', score_min: 0.5, action: 'mask', priority: 5 });
  await warden('POST', `/api/virtual-servers/${vsTools}/agents`, { agent_id: bank.id });
  const apiKey = (await warden('POST', '/api/keys', { name: 'frontend', virtual_server_ids: [vsTools, vsA2a] })).json.key;
  const mcpId = (await warden('POST', '/api/mcp', { name: 'bank-mcp', url: MCP_URL })).json.id;
  await warden('POST', `/api/virtual-servers/${vsTools}/tools`, { mcp_server_id: mcpId, tool_name: '*' });
  await warden('POST', '/api/token-policies', { virtual_server_id: vsTools, name: 'allow-all', effect: 'permit', policy_json: { actions: [{ mcp_server_id: '*', tool: '*' }], conditions: [] } });
  const target = (await warden('POST', '/api/a2a-agents', { name: 'credit-card-agent', card_json: { name: 'credit-card-agent', description: 'cards', supportedInterfaces: [{ protocolBinding: 'JSONRPC', url: A2A_URL }], skills: [{ id: 'card-details', name: 'Card details' }] } })).json.id;
  await warden('POST', `/api/virtual-servers/${vsA2a}/a2a-agents`, { a2a_agent_id: target });
  const a2aPol = (await warden('POST', '/api/a2a-policies', { virtual_server_id: vsA2a, name: 'card-agent-ok', effect: 'permit', caller_type: 'agent', caller_value: card.id, target_type: 'any' })).json.id;

  // The vault holds the shared Warden API key. Each real agent may reveal it (and nothing else) under its
  // own policy; an agent's own token is its identity, so it is never stored in the vault.
  const secret = async (name, value) => (await warden('POST', '/api/vault/secrets', { name, value, type: 'api_key' })).json.id;
  const keyId = await secret('warden-api-key', apiKey);
  await secret('decoy-secret', 'decoy-value-should-never-leak');
  for (const a of [bank, card]) await warden('POST', '/api/vault/policies', { name: `${a.name}-reveal-api-key`, effect: 'permit', caller_type: 'agent', caller_value: a.id, secret_id: keyId, operations: ['reveal'], max_ttl_seconds: 300 });
  const SECRETS = [apiKey, bank.token, card.token, 'decoy-value-should-never-leak'];

  const env = {
    WARDEN_URL: W,
    WARDEN_VIRTUAL_SERVER_ID: vsTools, WARDEN_MCP_SERVER_ID: mcpId, WARDEN_AGENT_TOKEN: bank.token,
    WARDEN_A2A_VS_ID: vsA2a, WARDEN_A2A_TARGET_ID: target, WARDEN_A2A_AGENT_TOKEN: card.token, WARDEN_CHAT_VS_ID: chatVs,
    WARDEN_API_KEY_SECRET: 'warden-api-key',
  };
  const fakeAuth = (req, res, next) => (req.headers.authorization === `Bearer ${userJwt}` ? next() : res.status(401).json({ success: false, error: 'Invalid or expired token' }));
  const buildRelay = async (port, cfgEnv) => {
    const cfg = loadWardenConfig(cfgEnv);
    const gw = createWardenGateway({ config: cfg });
    const app = express(); app.use(express.json());
    app.use('/api/warden', createWardenRouter({ gateway: gw, authMiddleware: fakeAuth }));
    app.use((err, _req, res, _next) => { console.error('unhandled', err); res.status(500).json({ error: 'internal' }); });
    const srv = http.createServer(app); await listen(srv, port); return srv;
  };
  relayServer = await buildRelay(RELAY_PORT, env);
  const R = `http://127.0.0.1:${RELAY_PORT}`;
  const relay = (m, p, b, h = authed) => call(R, m, p, b, h);

  // ═══ 1. auth + config ═════════════════════════════════════════════════════
  section('1. relay authentication and config');
  check('no token -> 401', (await relay('GET', '/api/warden/config', undefined, {})).status === 401);
  check('wrong token -> 401', (await relay('POST', '/api/warden/tool', { tool_name: 'x' }, { Authorization: 'Bearer nope' })).status === 401);
  const cfgRes = await relay('GET', '/api/warden/config');
  check('config reports tools + A2A configured', cfgRes.json.toolsConfigured === true && cfgRes.json.a2aConfigured === true, cfgRes.text);
  check('config response carries no credentials', !SECRETS.some(s => cfgRes.text.includes(s)));

  // ═══ 2. tool calls ════════════════════════════════════════════════════════
  section('2. MCP tool calls through the relay');
  const direct = await call(W, 'POST', `/api/proxy/${vsTools}`, { mcp_server_id: mcpId, tool_name: 'echo', arguments: {} }, { ...authed, 'X-Agent-Token': bank.token });
  check('control: Warden itself rejects a call that lacks the API key (so success below proves the vault key was used)', direct.status === 401, direct.text);
  const t1 = await relay('POST', '/api/warden/tool', { tool_name: 'get_accounts', arguments: { q: 'hi' } });
  check('tool call succeeds end-to-end', t1.status === 200 && JSON.parse(t1.json.result.content[0].text).args.q === 'hi', t1.text);
  check('upstream MCP server actually received the call', upstreamCalls.some(c => c.method === 'tools/call' && c.params.name === 'get_accounts'));
  const lastProxy = () => JSON.parse(wdb.prepare("SELECT data FROM event_log WHERE log_type='proxy_call' ORDER BY rowid DESC LIMIT 1").get().data);
  check('Warden attributes the call to the existing bank-agent identity (policies/scoring keep working)', lastProxy().agent_name === 'bank-agent', lastProxy());
  const t2 = await relay('POST', '/api/warden/tool', { tool_name: 'get_accounts', arguments: {} }, { ...authed, 'X-Agent-Token': intruder.token, 'X-API-Key': 'wrd_bogus', 'x-user-token': 'Bearer evil' });
  check('credential headers supplied by the browser are ignored', t2.status === 200 && lastProxy().agent_name === 'bank-agent', t2.text);
  check('responses never contain any Warden credential', ![t1, t2].some(r => SECRETS.some(s => r.text.includes(s))));
  const leases = wdb.prepare('SELECT COUNT(*) n FROM vault_leases').get().n;
  check('API key checkout is cached across calls (3 tool calls so far -> exactly 1 lease)', leases === 1, `leases=${leases}`);
  const vaultReads = wdb.prepare("SELECT json_extract(data,'$.agent_name') a, json_extract(data,'$.secret_name') s FROM event_log WHERE log_type='vault_access' AND json_extract(data,'$.decision')='allow'").all();
  check('the vault read is attributed to bank-agent itself (no extra identity)', vaultReads.length === 1 && vaultReads[0].a === 'bank-agent' && vaultReads[0].s === 'warden-api-key', vaultReads);

  // approval passthrough
  const apId = crypto.randomUUID();
  wdb.prepare('INSERT INTO policies (id, virtual_server_id, name, effect, priority, policy_json) VALUES (?,?,?,?,?,?)')
    .run(apId, vsTools, 'needs-approval', 'approval', 100, JSON.stringify({ actions: [{ mcp_server_id: '*', tool: 'initiate_payment' }], conditions: [], approval_config: { ttl_minutes: 5, timeout_action: 'deny' } }));
  const pend = await relay('POST', '/api/warden/tool', { tool_name: 'initiate_payment', arguments: { amount: 5 } });
  check('202 pending_approval is passed through intact', pend.status === 202 && pend.json.status === 'pending_approval' && !!pend.json.ticket_id && /^\/api\/approvals\//.test(pend.json.poll_url), pend.text);
  wdb.prepare('DELETE FROM policies WHERE id = ?').run(apId);

  const bad = [
    ['path-traversal tool_name', { tool_name: '../admin' }], ['empty tool_name', { tool_name: '' }], ['missing tool_name', {}],
    ['array arguments', { tool_name: 'x', arguments: [1] }], ['string arguments', { tool_name: 'x', arguments: 'a' }],
  ];
  for (const [label, body] of bad) check(`validation: ${label} -> 400`, (await relay('POST', '/api/warden/tool', body)).status === 400);

  // ═══ 3. A2A ═══════════════════════════════════════════════════════════════
  section('3. A2A (Credit Card Agent) through the relay');
  const a1 = await relay('POST', '/api/warden/a2a', { question: 'show my cards', skillId: 'card-details', contextId: 'ctx-1' });
  const task = a1.json?.result?.task;
  check('A2A succeeds end-to-end and returns Warden\'s JSON-RPC result', a1.status === 200 && task?.id === 'task-1' && task.artifacts[0].parts[0].text === 'here are your cards', a1.text);
  const lastA2a = () => JSON.parse(wdb.prepare("SELECT data FROM event_log WHERE log_type='a2a_call' ORDER BY rowid DESC LIMIT 1").get().data);
  check('Warden attributes the A2A call to a2a-agent', lastA2a().agent_name === 'a2a-agent', lastA2a());
  check('A2A response carries no credentials', !SECRETS.some(s => a1.text.includes(s)));
  check('A2A path read the API key as a2a-agent (its own identity and lease)', wdb.prepare("SELECT COUNT(*) n FROM event_log WHERE log_type='vault_access' AND json_extract(data,'$.agent_name')='a2a-agent' AND json_extract(data,'$.decision')='allow'").get().n === 1 && wdb.prepare('SELECT COUNT(*) n FROM vault_leases').get().n === 2);
  await warden('DELETE', `/api/a2a-policies/${a2aPol}`);
  const a2 = await relay('POST', '/api/warden/a2a', { question: 'show my cards' });
  check('Warden policy denial passes through with its status and JSON-RPC error', a2.status === 403 && !!a2.json?.error?.message, a2.text);
  for (const [label, body] of [['empty question', { question: '  ' }], ['oversized question', { question: 'x'.repeat(10001) }], ['bad skillId', { question: 'q', skillId: 'a b;' }], ['bad contextId', { question: 'q', contextId: '../' }]]) {
    check(`validation: ${label} -> 400`, (await relay('POST', '/api/warden/a2a', body)).status === 400);
  }

  // ═══ 4. failure modes ═════════════════════════════════════════════════════
  section('4. failure modes fail closed and leak nothing');
  intruderServer = await buildRelay(INTRUDER_PORT, { ...env, WARDEN_AGENT_TOKEN: intruder.token });
  const vDeny = await call(`http://127.0.0.1:${INTRUDER_PORT}`, 'POST', '/api/warden/tool', { tool_name: 'get_accounts' }, authed);
  check('agent with no vault policy -> 502, no credentials, no call to Warden', vDeny.status === 502 && /vault/i.test(vDeny.json.error) && !SECRETS.some(s => vDeny.text.includes(s)), vDeny.text);
  const vault = (token, secretName) => call(W, 'POST', '/api/vault/checkout', { secret: secretName }, { 'X-Agent-Token': token });
  check('least privilege: bank-agent cannot read any other secret', (await vault(bank.token, 'decoy-secret')).status === 403);
  check('least privilege: a2a-agent cannot read any other secret', (await vault(card.token, 'decoy-secret')).status === 403);
  check('each real agent can read the API key (and the agent tokens are not in the vault at all)', (await vault(bank.token, 'warden-api-key')).status === 200 && (await vault(card.token, 'warden-api-key')).status === 200 && (await vault(bank.token, 'bank-agent-token')).status === 403);
  const noKeyCfg = await buildRelay(INTRUDER_PORT + 1, { ...env, WARDEN_API_KEY_SECRET: '' });
  const leasesBefore = wdb.prepare('SELECT COUNT(*) n FROM vault_leases').get().n;
  const noKey = await call(`http://127.0.0.1:${INTRUDER_PORT + 1}`, 'POST', '/api/warden/tool', { tool_name: 'x' }, authed);
  check('no API-key secret configured -> vault is not contacted; Warden\'s own 401 passes through', noKey.status === 401 && /API.?Key/i.test(noKey.json.error) && wdb.prepare('SELECT COUNT(*) n FROM vault_leases').get().n === leasesBefore, noKey.text);
  noKeyCfg.close();
  const unconf = await buildRelay(INTRUDER_PORT + 2, { WARDEN_URL: W });
  const uTool = await call(`http://127.0.0.1:${INTRUDER_PORT + 2}`, 'POST', '/api/warden/tool', { tool_name: 'x' }, authed);
  const uA2a = await call(`http://127.0.0.1:${INTRUDER_PORT + 2}`, 'POST', '/api/warden/a2a', { question: 'q' }, authed);
  const uCfg = await call(`http://127.0.0.1:${INTRUDER_PORT + 2}`, 'GET', '/api/warden/config', undefined, authed);
  check('unconfigured relay -> 503 for tools and A2A, config says so', uTool.status === 503 && uA2a.status === 503 && uCfg.json.toolsConfigured === false && uCfg.json.a2aConfigured === false);
  unconf.close();
  const down = await buildRelay(INTRUDER_PORT + 3, { ...env, WARDEN_URL: 'http://127.0.0.1:1' });
  const dRes = await call(`http://127.0.0.1:${INTRUDER_PORT + 3}`, 'POST', '/api/warden/tool', { tool_name: 'x' }, authed);
  check('Warden unreachable -> 502 (no hang, no leak)', dRes.status === 502 && !SECRETS.some(s => dRes.text.includes(s)), dRes.text);
  down.close();

  // ═══ 5. vault client unit behaviour (fake fetch + clock) ══════════════════
  section('5. vault client: caching, single-flight, expiry, errors');
  let clock = 1_000_000, fetches = 0, mode = 'ok';
  const fakeFetch = async (_url, init) => {
    fetches++; await sleep(15);
    if (mode === 'down') throw new Error('ECONNREFUSED');
    if (mode === 'deny') return new Response(JSON.stringify({ error: 'Vault access denied' }), { status: 403 });
    if (mode === 'junk') return new Response('not json', { status: 200 });
    return new Response(JSON.stringify({ value: `v${fetches}`, ttl_seconds: 100 }), { status: 200 });
  };
  const vc = createVaultClient({ baseUrl: 'http://x', agentToken: 'wag_t', fetchImpl: fakeFetch, now: () => clock });
  const five = await Promise.all([1, 2, 3, 4, 5].map(() => vc.getSecret('s')));
  check('concurrent callers share a single checkout (single-flight)', fetches === 1 && new Set(five).size === 1);
  await vc.getSecret('s'); check('cache hit within the lease', fetches === 1);
  clock += 93_000; await vc.getSecret('s'); check('still cached just before the 5s safety skew (93s of 100s lease)', fetches === 1);
  clock += 3_000; const v2 = await vc.getSecret('s'); check('refetches inside the skew window (96s of 100s) and serves the new value', fetches === 2 && v2 === 'v2');
  vc.invalidate('s'); await vc.getSecret('s'); check('invalidate forces a fresh checkout', fetches === 3);
  mode = 'deny'; vc.invalidate();
  let e1; try { await vc.getSecret('s'); } catch (e) { e1 = e; }
  check('vault denial -> WardenVaultError(403) with the vault message', e1 instanceof WardenVaultError && e1.status === 403 && /denied/.test(e1.message));
  mode = 'down'; let e2; try { await vc.getSecret('s'); } catch (e) { e2 = e; }
  check('unreachable vault -> WardenVaultError', e2 instanceof WardenVaultError && /reach/.test(e2.message));
  mode = 'junk'; let e3; try { await vc.getSecret('s'); } catch (e) { e3 = e; }
  check('malformed vault response -> WardenVaultError', e3 instanceof WardenVaultError);
  mode = 'ok'; const before = fetches; const v4 = await vc.getSecret('s');
  check('failures are not cached (next call succeeds)', fetches === before + 1 && typeof v4 === 'string');

  // ═══ 5b. chat scan + approval status: the browser never talks to Warden ═════
  section('5b. message scan and approval status through the relay, with Warden in SECURE mode');
  const ADMIN = 'adm-' + crypto.randomBytes(16).toString('hex');
  process.env.WARDEN_ADMIN_TOKEN = ADMIN; // Warden (in this process) now requires credentials on its admin API
  const wardenDirect = (m, p, b) => call(W, m, p, b);
  check('Warden itself now refuses an unauthenticated browser: scan -> 401', (await wardenDirect('POST', `/api/interceptors/${chatVs}/scan`, { text: 'hi' })).status === 401);
  check('...and an unauthenticated ticket lookup -> 401', (await wardenDirect('GET', '/api/approvals/some-ticket-id/status')).status === 401);
  check('...and the admin API -> 401', (await wardenDirect('GET', '/api/agents')).status === 401);
  const latestScan = () => JSON.parse(wdb.prepare("SELECT data FROM event_log WHERE log_type='interceptor' ORDER BY rowid DESC LIMIT 1").get().data);
  const s1 = await relay('POST', '/api/warden/scan', { text: 'hello there', direction: 'inbound', agent: 'mcp' });
  check('the relay scans a chat message as the banking agent', s1.status === 200 && s1.json.action === 'allow', s1.text);
  check('the finding is attributed to the banking agent (identity comes from its token)', latestScan().agent_id === bank.id, latestScan());
  const s2 = await relay('POST', '/api/warden/scan', { text: 'hello there', direction: 'outbound', agent: 'a2a' });
  check('selecting the Credit Card Agent scans as the A2A agent', s2.status === 200 && latestScan().agent_id === card.id, latestScan());
  const pii = await relay('POST', '/api/warden/scan', { text: 'my card is 4111 1111 1111 1111 thanks', direction: 'outbound' });
  check('a PII message is really masked by the Warden interceptors, through the relay', pii.status === 200 && pii.json.action === 'mask' && !pii.text.includes('4111 1111 1111 1111'), pii.text);
  check('scan: empty text -> 400', (await relay('POST', '/api/warden/scan', { text: '  ' })).status === 400);
  check('scan: oversized text -> 400', (await relay('POST', '/api/warden/scan', { text: 'x'.repeat(10001) })).status === 400);
  check('scan: bad direction -> 400', (await relay('POST', '/api/warden/scan', { text: 'x', direction: 'sideways' })).status === 400);
  check('scan: bad agent -> 400', (await relay('POST', '/api/warden/scan', { text: 'x', agent: 'admin' })).status === 400);
  check('scan: no Okta token -> 401 from the relay itself', (await relay('POST', '/api/warden/scan', { text: 'x' }, {})).status === 401);
  check('scan responses carry no credentials', ![s1, s2].some(r => SECRETS.some(s => r.text.includes(s))));
  const mkTicket = (agentId, agentName) => { const id = crypto.randomUUID(); wdb.prepare('INSERT INTO approval_tickets (id, virtual_server_id, mcp_server_id, tool_name, status, agent_id, agent_name, expires_at) VALUES (?,?,?,?,?,?,?,?)').run(id, vsTools, 'x', 'get_accounts', 'pending', agentId, agentName, new Date(Date.now() + 600000).toISOString()); return id; };
  const bankTicket = mkTicket(bank.id, 'bank-agent'), cardTicket = mkTicket(card.id, 'a2a-agent');
  const st1 = await relay('GET', `/api/warden/approvals/${bankTicket}/status?kind=mcp`);
  check('the relay reads a banking-agent ticket as the banking agent', st1.status === 200 && st1.json.status === 'pending', st1.text);
  const st2 = await relay('GET', `/api/warden/approvals/${cardTicket}/status?kind=a2a`);
  check('...and a Credit Card Agent ticket as the A2A agent', st2.status === 200 && st2.json.status === 'pending', st2.text);
  const wrongKind = await relay('GET', `/api/warden/approvals/${cardTicket}/status?kind=mcp`);
  const unknown = await relay('GET', `/api/warden/approvals/${crypto.randomUUID()}/status?kind=mcp`);
  check('asking for a ticket as the wrong agent looks exactly like asking for one that does not exist', wrongKind.status === 404 && unknown.status === 404 && wrongKind.text === unknown.text, [wrongKind.text, unknown.text]);
  check('status: a malformed ticket id -> 400', (await relay('GET', '/api/warden/approvals/%2e%2e%2fagents/status')).status === 400);
  check('status: no Okta token -> 401', (await relay('GET', `/api/warden/approvals/${bankTicket}/status`, undefined, {})).status === 401);
  const noScan = await buildRelay(INTRUDER_PORT + 4, { ...env, WARDEN_CHAT_VS_ID: '' });
  const ns = await call(`http://127.0.0.1:${INTRUDER_PORT + 4}`, 'POST', '/api/warden/scan', { text: 'x' }, authed);
  const nsCfg = await call(`http://127.0.0.1:${INTRUDER_PORT + 4}`, 'GET', '/api/warden/config', undefined, authed);
  check('without WARDEN_CHAT_VS_ID the relay says so (503) and reports scanConfigured: false', ns.status === 503 && nsCfg.json.scanConfigured === false, [ns.status, nsCfg.text]);
  noScan.close();
  check('config reports scanConfigured: true when set', (await relay('GET', '/api/warden/config')).json.scanConfigured === true);
  delete process.env.WARDEN_ADMIN_TOKEN;

  // ═══ 6. the real backend index.js wiring ══════════════════════════════════
  section('6. real backend wiring (index.js)');
  const envLocal = path.join(backendDir, '.env.local');
  const hadEnvLocal = fs.existsSync(envLocal);
  if (hadEnvLocal) { check('(skipped .env.local load test: file already exists)', true); }
  else fs.writeFileSync(envLocal, `WARDEN_AGENT_TOKEN=wag_from_env_local_a\nWARDEN_A2A_AGENT_TOKEN=wag_from_env_local_b\n`);
  let out = '';
  realProc = spawn(process.execPath, ['src/index.js'], {
    cwd: backendDir, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PORT: String(REAL_PORT), DB_PATH: path.join(tmp, 'banking.db'), NODE_ENV: 'development', FRONTEND_URL: 'http://localhost:5173' },
  });
  realProc.stdout.on('data', d => { out += d; }); realProc.stderr.on('data', d => { out += d; });
  const B = `http://127.0.0.1:${REAL_PORT}`;
  for (let i = 0; i < 80; i++) { try { if ((await fetch(B + '/api/health')).ok) break; } catch {} await sleep(150); }
  if (!hadEnvLocal) { try { fs.unlinkSync(envLocal); } catch {} }
  check('backend boots and /api/health still works', (await call(B, 'GET', '/api/health')).status === 200, out.slice(-400));
  check('/api/warden/config requires a verified Okta token', (await call(B, 'GET', '/api/warden/config')).status === 401);
  check('/api/warden/tool requires a verified Okta token', (await call(B, 'POST', '/api/warden/tool', { tool_name: 'x' })).status === 401);
  check('/api/warden/a2a requires a verified Okta token', (await call(B, 'POST', '/api/warden/a2a', { question: 'q' })).status === 401);
  check('a forged/unsigned bearer token is rejected', (await call(B, 'POST', '/api/warden/tool', { tool_name: 'x' }, authed)).status === 401);
  const pre = await fetch(B + '/api/warden/tool', { method: 'OPTIONS', headers: { Origin: 'http://localhost:5173', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization,content-type,x-id-token' } });
  check('CORS preflight allows the X-Id-Token header', /x-id-token/i.test(pre.headers.get('access-control-allow-headers') || ''), pre.headers.get('access-control-allow-headers'));
  check('startup log reports relay state without printing secrets', /Warden relay:/.test(out) && !/wag_from_env_local/.test(out), out.match(/Warden relay:.*/)?.[0]);
  if (!hadEnvLocal) check('.env.local is loaded (both agent tokens picked up -> tools and A2A configured)', /tools configured, A2A configured/.test(out), out.match(/Warden relay:.*/)?.[0]);

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length) console.log('Failed:\n - ' + failures.join('\n - '));
  return failures.length;
}

function cleanup(code) {
  for (const s of [mcp, a2a, relayServer, intruderServer]) { try { s?.close(); } catch {} }
  try { realProc?.kill(); } catch {}
  setTimeout(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} process.exit(code ? 1 : 0); }, 400);
}
main().then(n => cleanup(n), e => { console.error('\nTEST HARNESS ERROR:', e); cleanup(1); });
