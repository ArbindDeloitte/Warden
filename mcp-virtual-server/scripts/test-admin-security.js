'use strict';

// Security regression test: admin authentication, the data-plane exemptions, user-token audience/issuer checks,
// rate limiting and the loopback bind. Boots Warden on a THROWAWAY database; never touches data/virtual-server.db.
//   node scripts/test-admin-security.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-admin-sec-'));
Object.assign(process.env, { SQLITE_PATH: path.join(tmp, 'test.db'), PORT: process.env.TEST_PORT || '3042', NODE_ENV: 'development', JWKS_URI: '', REDIS_URL: 'redis://127.0.0.1:1' });
delete process.env.WARDEN_SECRETS_KEY; delete process.env.WARDEN_ADMIN_TOKEN; delete process.env.WARDEN_RATE_LIMIT_PER_MIN;
process.chdir(tmp);
const BASE = `http://127.0.0.1:${process.env.PORT}`;

let passed = 0; const failures = [];
function check(name, cond, detail) {
  if (cond) { passed++; console.log(`  ok   ${name}`); }
  else { failures.push(name); console.log(`  FAIL ${name}${detail !== undefined ? '  -> ' + (typeof detail === 'string' ? detail : JSON.stringify(detail)) : ''}`); }
}
const section = (t) => console.log(`\n== ${t}`);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function call(method, p, body, headers = {}) {
  const res = await fetch(BASE + p, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text, headers: res.headers };
}
const ADMIN = 'a'.repeat(8) + crypto.randomBytes(16).toString('hex');
const asAdmin = { 'X-Admin-Token': ADMIN };
const isAdminDenied = (r) => r.status === 401 && r.json?.code === 'admin_auth_required';

// ── helpers for the JWKS / user-token tests ──────────────────────────────────────────────────────
const keyA = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const keyB = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = 'test-key-1', ISS = 'https://idp.test/oauth2/serverA', AUD = 'api://banking';
const userJwt = (claims = {}, { key = keyA.privateKey, alg = 'RS256', expiresIn = 600 } = {}) => {
  const opts = { algorithm: alg, keyid: KID, expiresIn };
  if (claims.iss === undefined) opts.issuer = ISS;   // unless the test sets its own iss / aud claim
  if (claims.aud === undefined) opts.audience = AUD;
  return jwt.sign({ sub: 'user-1', ...claims }, key, opts);
};

async function main() {
  // JWKS endpoint + fake MCP upstream + fake A2A 1.0 agent
  const jwks = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ keys: [{ ...keyA.publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' }] })); });
  const mcp = http.createServer((req, res) => {
    let b = ''; req.on('data', d => { b += d; });
    req.on('end', () => {
      const m = JSON.parse(b || '{}'); const ok = (result, h = {}) => { res.writeHead(200, { 'content-type': 'application/json', ...h }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result })); };
      if (m.method === 'initialize') return ok({ protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'f', version: '1' } }, { 'mcp-session-id': 's' + Math.random() });
      if (m.method === 'notifications/initialized') { res.writeHead(202); return res.end(); }
      if (m.method === 'tools/call') return ok({ content: [{ type: 'text', text: '{"ok":true}' }] });
      res.writeHead(400); res.end('{}');
    });
  });
  const a2aAgent = http.createServer((req, res) => {
    let b = ''; req.on('data', d => { b += d; });
    req.on('end', () => { const m = JSON.parse(b || '{}'); res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { task: { id: 't-' + Math.random(), status: { state: 'TASK_STATE_COMPLETED' }, artifacts: [{ parts: [{ text: 'ok' }] }] } } })); });
  });
  await Promise.all([jwks, mcp, a2aAgent].map(s => new Promise(r => s.listen(0, '127.0.0.1', r))));
  const JWKS_URL = `http://127.0.0.1:${jwks.address().port}/jwks`, MCP_URL = `http://127.0.0.1:${mcp.address().port}/mcp`, A2A_URL = `http://127.0.0.1:${a2aAgent.address().port}/rpc`;

  const app = require('../src/app');
  const db = require('../src/db/database');
  for (let i = 0; i < 60; i++) { try { if ((await fetch(BASE + '/api/health')).ok) break; } catch {} await sleep(100); }

  // ═══ 1. open mode (WARDEN_ADMIN_TOKEN unset) is unchanged ═════════════════
  section('1. open mode: nothing changes until a token is set');
  check('status says authentication is not required', (await call('GET', '/api/auth/status')).json.authRequired === false);
  check('the admin API works without credentials, as before', (await call('GET', '/api/agents')).status === 200 && (await call('GET', '/api/keys')).status === 200);
  check('login in open mode is a harmless no-op', (await call('POST', '/api/auth/login', { token: 'x' })).json.ok === true);

  // fixtures created while open (the admin API is open here)
  const mkAgent = async (name) => { const r = await call('POST', '/api/agents', { name }); return { id: r.json.id, token: r.json.token, name }; };
  const alice = await mkAgent('alice'), bob = await mkAgent('bob');
  const chatVs = (await call('POST', '/api/virtual-servers', { name: 'chat-vs', features_enabled: ['interceptors'], require_obo: 0, allow_anonymous: true })).json.id;
  const keyChat = (await call('POST', '/api/keys', { name: 'chat-key', virtual_server_ids: [chatVs] })).json.key;
  const mcpId = (await call('POST', '/api/mcp', { name: 'm', url: MCP_URL })).json.id;
  const bankVs = (await call('POST', '/api/virtual-servers', { name: 'bank-vs', require_obo: 0, features_enabled: ['policy'], require_agent_token: 1, jwks_uri: JWKS_URL, user_token_audience: AUD, user_token_issuer: ISS })).json.id;
  const looseVs = (await call('POST', '/api/virtual-servers', { name: 'loose-vs', require_obo: 0, allow_anonymous: true, features_enabled: ['policy'], jwks_uri: JWKS_URL })).json.id;
  const keyBank = (await call('POST', '/api/keys', { name: 'bank-key', virtual_server_ids: [bankVs] })).json.key;
  for (const v of [bankVs, looseVs]) {
    await call('POST', `/api/virtual-servers/${v}/tools`, { mcp_server_id: mcpId, tool_name: '*' });
    await call('POST', '/api/token-policies', { virtual_server_id: v, name: 'allow', effect: 'permit', policy_json: { actions: [{ mcp_server_id: '*', tool: '*' }], conditions: [] } });
  }
  await call('POST', `/api/virtual-servers/${bankVs}/agents`, { agent_id: alice.id });
  const a2aId = (await call('POST', '/api/a2a-agents', { name: 'card-agent', card_json: { name: 'card-agent', supportedInterfaces: [{ url: A2A_URL, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }], skills: [] } })).json.id;
  const a2aVs = (await call('POST', '/api/virtual-servers', { name: 'a2a-vs', protocol: 'a2a', features_enabled: [], jwks_uri: JWKS_URL, user_token_audience: AUD, user_token_issuer: ISS })).json.id;
  await call('POST', `/api/virtual-servers/${a2aVs}/a2a-agents`, { a2a_agent_id: a2aId });
  await call('POST', '/api/a2a-policies', { virtual_server_id: a2aVs, name: 'needs user', effect: 'permit', caller_type: 'agent', caller_value: alice.id, target_type: 'any', require_user: 1 });
  const ticketId = crypto.randomUUID();
  db.prepare("INSERT INTO approval_tickets (id, virtual_server_id, mcp_server_id, tool_name, status, agent_id, agent_name, expires_at) VALUES (?,?,?,?,?,?,?,?)")
    .run(ticketId, bankVs, 'm', 'get_accounts', 'pending', alice.id, 'alice', new Date(Date.now() + 600000).toISOString());
  check('(fixtures created)', !!alice.token && !!keyBank && !!a2aId);
  const openScan = await call('POST', `/api/interceptors/${chatVs}/scan`, { text: 'hello', agent_name: 'bob' });
  check('open mode: scan works with no credentials and accepts a caller-chosen agent_name (legacy)', openScan.status === 200);
  const openScanTok = await call('POST', `/api/interceptors/${chatVs}/scan`, { text: 'hello', agent_name: 'bob' }, { 'X-Agent-Token': alice.token });
  const openEv = JSON.parse(db.prepare("SELECT data FROM event_log WHERE log_type='interceptor' ORDER BY rowid DESC LIMIT 1").get().data);
  check('open mode: a valid agent token still identifies the caller (the banking relay relies on this)', openScanTok.status === 200 && openEv.agent_id === alice.id, openEv);
  const openScanBad = await call('POST', `/api/interceptors/${chatVs}/scan`, { text: 'hello' }, { 'X-Agent-Token': 'wag_not_real' });
  check('open mode: an invalid agent token is ignored, not an error (legacy callers keep working)', openScanBad.status === 200);
  check('open mode: ticket status readable without credentials (legacy)', (await call('GET', `/api/approvals/${ticketId}/status`)).status === 200);

  // ═══ 2. secure mode: the gate ═════════════════════════════════════════════
  process.env.WARDEN_ADMIN_TOKEN = ADMIN;
  section('2. secure mode: the admin API requires the token');
  check('status now says authentication is required, and you are not authenticated', (await call('GET', '/api/auth/status')).json.authRequired === true && (await call('GET', '/api/auth/status')).json.authenticated === false);
  const sample = [['GET', '/api/agents'], ['GET', '/api/keys'], ['POST', '/api/keys'], ['GET', '/api/virtual-servers'], ['GET', '/api/mcp'], ['GET', '/api/vault/secrets'],
    ['POST', '/api/vault/policies'], ['GET', '/api/approvals'], ['POST', `/api/approvals/${ticketId}/decide`], ['GET', '/api/audit'], ['GET', '/api/scoring/defaults'],
    ['GET', '/api/a2a-agents'], ['POST', '/api/a2a-policies'], ['GET', '/api/warden-functions'], ['GET', '/api/agent-groups'], ['GET', `/api/interceptors/${chatVs}/rules`],
    ['GET', `/api/token-policies/virtual-server/${bankVs}`], ['DELETE', `/api/agents/${bob.id}`], ['GET', '/api/vault/activity'], ['POST', `/api/agents/${bob.id}/rotate-token`]];
  const denied = [];
  for (const [m, p] of sample) { const r = await call(m, p, m === 'GET' || m === 'DELETE' ? undefined : {}); if (!isAdminDenied(r)) denied.push(`${m} ${p} -> ${r.status}`); }
  check(`${sample.length} representative admin routes return 401 admin_auth_required with no credentials`, denied.length === 0, denied);
  check('the agent really was not deleted by the unauthenticated DELETE', db.prepare('SELECT COUNT(*) n FROM agents WHERE id = ?').get(bob.id).n === 1);
  check('a wrong token (X-Admin-Token) is refused', isAdminDenied(await call('GET', '/api/agents', undefined, { 'X-Admin-Token': 'wrong' })));
  check('a wrong token (Bearer) is refused', isAdminDenied(await call('GET', '/api/agents', undefined, { Authorization: 'Bearer wrong' })));
  check('a near-miss token (same length) is refused', isAdminDenied(await call('GET', '/api/agents', undefined, { 'X-Admin-Token': ADMIN.slice(0, -1) + (ADMIN.endsWith('0') ? '1' : '0') })));
  check('the right token works as X-Admin-Token', (await call('GET', '/api/agents', undefined, asAdmin)).status === 200);
  check('the right token works as a Bearer token', (await call('GET', '/api/agents', undefined, { Authorization: `Bearer ${ADMIN}` })).status === 200);
  check('minting an API key needs the token, and works with it', (await call('POST', '/api/keys', { name: 'x', virtual_server_ids: [chatVs] })).status === 401 && (await call('POST', '/api/keys', { name: 'x', virtual_server_ids: [chatVs] }, asAdmin)).status === 201);
  check('the UI itself (static files) is still served so the login screen can load', (await fetch(BASE + '/')).status === 200);
  check('/api/health stays public', (await call('GET', '/api/health')).status === 200);
  check('an unknown /api route is also behind the gate (nothing to probe)', isAdminDenied(await call('GET', '/api/does-not-exist')));

  // every route that is registered under /api, with no credentials
  section('3. sweep: every registered /api route is gated unless it is a known data-plane route');
  const { exempt } = require('../src/middleware/adminAuth');
  const routes = [];
  const toPath = (re) => { const m = re.source.match(/^\^\\\/(.+?)\\\/\?\(\?=\\\/\|\$\)$/); return m ? '/' + m[1].replace(/\(\?:\(\[\^\\\/\]\+\?\)\)/g, 'x').replace(/\\\//g, '/') : null; };
  (function walk(stack, prefix) {
    for (const l of stack) {
      if (l.route) for (const m of Object.keys(l.route.methods)) routes.push([m.toUpperCase(), (prefix + l.route.path).replace(/:[A-Za-z]+/g, 'x')]);
      else if (l.name === 'router' && l.handle.stack) { const p = toPath(l.regexp); if (p !== null) walk(l.handle.stack, prefix + p); }
    }
  })(app._router.stack, '');
  const apiRoutes = routes.filter(([, p]) => p.startsWith('/api/') && !p.startsWith('/api/auth/'));
  check(`the sweep found the API surface (${apiRoutes.length} routes)`, apiRoutes.length > 100, apiRoutes.length);
  const leaks = []; let probed = 0;
  for (const [m, p] of apiRoutes) {
    if (exempt({ method: m, path: p.slice('/api'.length) })) continue;
    probed++;
    const r = await call(m, p, ['GET', 'DELETE'].includes(m) ? undefined : {});
    if (!isAdminDenied(r)) leaks.push(`${m} ${p} -> ${r.status}`);
  }
  check(`all ${probed} non-exempt routes answer 401 admin_auth_required without credentials`, leaks.length === 0, leaks.slice(0, 8));
  check('the only exempt routes are the intended data-plane ones', apiRoutes.filter(([m, p]) => exempt({ method: m, path: p.slice(4) })).every(([m, p]) => /^\/api\/(health|proxy\/|vault\/(checkout|sign|validate)|interceptors\/x\/scan|approvals\/x\/status)/.test(p)), apiRoutes.filter(([m, p]) => exempt({ method: m, path: p.slice(4) })).map(([m, p]) => `${m} ${p}`));

  // ═══ 4. login / cookie session ════════════════════════════════════════════
  section('4. sign-in for the UI (session cookie)');
  const bad = await call('POST', '/api/auth/login', { token: 'nope' });
  check('a wrong token is refused and sets no cookie', bad.status === 401 && !bad.headers.get('set-cookie'));
  check('a missing token is refused', (await call('POST', '/api/auth/login', {})).status === 401);
  const good = await call('POST', '/api/auth/login', { token: ADMIN });
  const setCookie = good.headers.get('set-cookie') || '';
  check('the right token signs in', good.status === 200 && good.json.ok === true);
  check('the cookie is HttpOnly, SameSite=Strict, site-wide, and expires', /HttpOnly/i.test(setCookie) && /SameSite=Strict/i.test(setCookie) && /Path=\//.test(setCookie) && /Max-Age=\d+/.test(setCookie), setCookie);
  check('the cookie never contains the admin token', !decodeURIComponent(setCookie).includes(ADMIN));
  const cookie = setCookie.split(';')[0];
  const withCookie = { Cookie: cookie };
  check('the cookie authenticates admin requests', (await call('GET', '/api/agents', undefined, withCookie)).status === 200 && (await call('GET', '/api/auth/status', undefined, withCookie)).json.authenticated === true);
  const [cv, cMac] = decodeURIComponent(cookie.split('=').slice(1).join('=')).split('.');
  check('a tampered cookie is refused', isAdminDenied(await call('GET', '/api/agents', undefined, { Cookie: `warden_admin=${cv}.${cMac.slice(0, -2)}00` })));
  check('a cookie with a changed expiry is refused', isAdminDenied(await call('GET', '/api/agents', undefined, { Cookie: `warden_admin=${Number(cv) + 999999}.${cMac}` })));
  check('an expired cookie is refused', isAdminDenied(await call('GET', '/api/agents', undefined, { Cookie: `warden_admin=1000.${crypto.createHash('sha256').update('x').digest('hex')}` })));
  const out = await call('POST', '/api/auth/logout', {}, withCookie);
  check('logout clears the cookie', /Max-Age=0/.test(out.headers.get('set-cookie') || ''));
  const oldToken = process.env.WARDEN_ADMIN_TOKEN;
  process.env.WARDEN_ADMIN_TOKEN = 'rotated-' + crypto.randomBytes(12).toString('hex');
  check('rotating the token invalidates existing sessions', isAdminDenied(await call('GET', '/api/agents', undefined, withCookie)));
  process.env.WARDEN_ADMIN_TOKEN = oldToken;
  // brute force
  let throttled = null;
  for (let i = 0; i < 14; i++) { const r = await call('POST', '/api/auth/login', { token: 'guess-' + i }); if (r.status === 429) { throttled = r; break; } }
  check('repeated wrong guesses are throttled (429 with Retry-After)', !!throttled && Number(throttled.headers.get('retry-after')) > 0, throttled?.status);
  check('while throttled even the right token is refused (no guessing around it)', (await call('POST', '/api/auth/login', { token: ADMIN })).status === 429);
  check('API requests carrying the right header still work during a login throttle', (await call('GET', '/api/agents', undefined, asAdmin)).status === 200);

  // ═══ 5. data-plane endpoints keep their own credentials ═══════════════════
  section('5. data-plane routes are not behind the admin token, but are not open either');
  const proxyBody = { mcp_server_id: mcpId, tool_name: 'get_accounts', arguments: {} };
  const proxy = (vs, headers) => call('POST', `/api/proxy/${vs}`, proxyBody, headers);
  const noKey = await proxy(bankVs, {});
  check('the proxy is not gated by the admin token; it asks for its own API key', noKey.status === 401 && /API.?Key/i.test(noKey.json.error) && noKey.json.code !== 'admin_auth_required', noKey.text);
  check('vault checkout asks for an agent token, not the admin token', (await call('POST', '/api/vault/checkout', { secret: 'x' })).json.error === 'Agent identity required');
  check('A2A discovery stays public', (await call('GET', `/a2a/${a2aVs}/${a2aId}/.well-known/agent-card.json`)).status === 200);

  // scan
  section('6. message scanning and approval status need an agent in secure mode');
  const scan = (headers, body = { text: 'hello', direction: 'inbound' }) => call('POST', `/api/interceptors/${chatVs}/scan`, body, headers);
  check('scan with no credentials -> 401', (await scan({})).status === 401);
  check('scan with an unknown agent token -> 401', (await scan({ 'X-Agent-Token': 'wag_nope', 'X-API-Key': keyChat })).status === 401);
  check('scan with a valid agent but no API key (the VS has one) -> 401', (await scan({ 'X-Agent-Token': alice.token })).status === 401);
  check('scan with a valid agent and the wrong API key -> 401', (await scan({ 'X-Agent-Token': alice.token, 'X-API-Key': 'wrd_x' })).status === 401);
  const evBefore = db.prepare("SELECT COUNT(*) n FROM event_log WHERE log_type='interceptor'").get().n;
  const okScan = await scan({ 'X-Agent-Token': alice.token, 'X-API-Key': keyChat }, { text: 'hello', direction: 'inbound', agent_name: 'bob' });
  check('scan with agent + API key works', okScan.status === 200, okScan.text);
  const ev = db.prepare("SELECT data FROM event_log WHERE log_type='interceptor' ORDER BY rowid DESC LIMIT 1").get();
  check('the finding is attributed to the token\'s agent, not to the agent_name the caller claimed', db.prepare("SELECT COUNT(*) n FROM event_log WHERE log_type='interceptor'").get().n > evBefore && JSON.parse(ev.data).agent_id === alice.id, ev && JSON.parse(ev.data));
  check('an admin can scan without an agent (the UI test tool)', (await scan(asAdmin)).status === 200);
  await call('PATCH', `/api/agents/${bob.id}/toggle`, undefined, asAdmin);
  check('a disabled agent cannot scan', (await scan({ 'X-Agent-Token': bob.token, 'X-API-Key': keyChat })).status === 403);
  await call('PATCH', `/api/agents/${bob.id}/toggle`, undefined, asAdmin);

  const status = (headers) => call('GET', `/api/approvals/${ticketId}/status`, undefined, headers);
  check('ticket status with no credentials -> 401', (await status({})).status === 401);
  const notMine = await status({ 'X-Agent-Token': bob.token, 'X-API-Key': keyBank });
  const missing = await call('GET', `/api/approvals/${crypto.randomUUID()}/status`, undefined, { 'X-Agent-Token': bob.token, 'X-API-Key': keyBank });
  check("another agent's ticket looks exactly like a ticket that does not exist (404, same body)", notMine.status === 404 && missing.status === 404 && notMine.text === missing.text, [notMine.text, missing.text]);
  check('the owner agent without the VS API key is refused', (await status({ 'X-Agent-Token': alice.token })).status === 401);
  const mine = await status({ 'X-Agent-Token': alice.token, 'X-API-Key': keyBank });
  check('the owner agent with the API key reads its own ticket', mine.status === 200 && mine.json.status === 'pending', mine.text);
  check('an admin can read any ticket', (await status(asAdmin)).status === 200);

  // ═══ 7. user-token audience / issuer ══════════════════════════════════════
  section('7. the user token must be meant for this application (audience / issuer)');
  const callBank = (token, vs = bankVs) => proxy(vs, { 'X-API-Key': vs === bankVs ? keyBank : '', 'X-Agent-Token': alice.token, Authorization: `Bearer ${token}` });
  const good2 = await callBank(userJwt());
  check('a token with the expected audience and issuer is accepted', good2.status === 200, good2.text);
  const wrongAud = await callBank(userJwt({ aud: 'api://some-other-app' }));
  check('a validly-signed token for ANOTHER audience is refused (and the reason is not leaked)', wrongAud.status === 401 && wrongAud.json?.error === 'Invalid or expired token' && !('detail' in wrongAud.json), wrongAud.text);
  const wrongIss = await callBank(userJwt({ iss: 'https://evil.example/oauth2/x' }));
  check('a validly-signed token from another issuer is refused (and the reason is not leaked)', wrongIss.status === 401 && wrongIss.json?.error === 'Invalid or expired token' && !('detail' in wrongIss.json), wrongIss.text);
  check('an expired token is refused', (await callBank(userJwt({}, { expiresIn: -60 }))).status === 401);
  check('a token signed with a different key is refused', (await callBank(userJwt({}, { key: keyB.privateKey }))).status === 401);
  const forgedHs = jwt.sign({ sub: 'x', aud: AUD, iss: ISS }, 'secret', { algorithm: 'HS256', keyid: KID });
  check('an HS256 token (algorithm confusion) is refused', (await callBank(forgedHs)).status === 401);
  const loose = await proxy(looseVs, { 'X-Agent-Token': alice.token, Authorization: `Bearer ${userJwt({ aud: 'api://anything-else' })}` });
  check('a virtual server with no expected audience configured behaves as before (backward compatible)', loose.status === 200, loose.text);
  const vsRow = (await call('GET', `/api/virtual-servers/${bankVs}`, undefined, asAdmin)).json;
  check('the expected audience and issuer are stored and returned', vsRow.user_token_audience === AUD && vsRow.user_token_issuer === ISS);
  await call('PUT', `/api/virtual-servers/${bankVs}`, { name: 'bank-vs', require_obo: 0, require_agent_token: 1, features_enabled: ['policy'], jwks_uri: JWKS_URL }, asAdmin);
  check('an update that omits the fields cannot drop the checks (older clients are safe)', (await call('GET', `/api/virtual-servers/${bankVs}`, undefined, asAdmin)).json.user_token_audience === AUD);
  const a2aCall = (token) => call('POST', `/a2a/${a2aVs}/${a2aId}`, { jsonrpc: '2.0', id: 1, method: 'SendMessage', params: { message: { messageId: 'm', role: 'ROLE_USER', parts: [{ text: 'hi' }] } } }, { 'X-Agent-Token': alice.token, 'X-User-Token': `Bearer ${token}` });
  check('A2A applies the same audience check to the delegated user token (right audience accepted)', (await a2aCall(userJwt())).status === 200);
  const a2aBad = await a2aCall(userJwt({ aud: 'api://other' }));
  check('A2A: a token for another audience is not accepted as the user (policy requires one -> 401)', a2aBad.status === 401, a2aBad.text);
  await call('PUT', `/api/virtual-servers/${bankVs}`, { name: 'bank-vs', require_obo: 0, require_agent_token: 1, features_enabled: ['policy'], jwks_uri: JWKS_URL, user_token_audience: '', user_token_issuer: '' }, asAdmin);
  check('empty strings clear the checks', (await call('GET', `/api/virtual-servers/${bankVs}`, undefined, asAdmin)).json.user_token_audience === null);

  // ═══ 8. rate limiting ═════════════════════════════════════════════════════
  section('8. rate limiting');
  process.env.WARDEN_RATE_LIMIT_PER_MIN = '5';
  const rlA = await (async () => { const r = await call('POST', '/api/agents', { name: 'rl-a' }, asAdmin); return { id: r.json.id, token: r.json.token }; })();
  const rlB = await (async () => { const r = await call('POST', '/api/agents', { name: 'rl-b' }, asAdmin); return { id: r.json.id, token: r.json.token }; })();
  const rlC = await (async () => { const r = await call('POST', '/api/agents', { name: 'rl-c' }, asAdmin); return { id: r.json.id, token: r.json.token }; })();
  const rlD = await (async () => { const r = await call('POST', '/api/agents', { name: 'rl-d' }, asAdmin); return { id: r.json.id, token: r.json.token }; })();
  const hammer = async (n, headers) => { const out = []; for (let i = 0; i < n; i++) out.push(await proxy(looseVs, headers)); return out; };
  const aRes = await hammer(8, { 'X-Agent-Token': rlA.token, Authorization: `Bearer ${userJwt()}` });
  check('the 6th call in a minute from one agent gets 429 with Retry-After', aRes.slice(0, 5).every(r => r.status === 200) && aRes.slice(5).every(r => r.status === 429 && Number(r.headers.get('retry-after')) > 0), aRes.map(r => r.status));
  check('the 429 explains itself', /Rate limit exceeded/.test(aRes[5].json.error) && aRes[5].json.retry_after_seconds > 0);
  const bRes = await proxy(looseVs, { 'X-Agent-Token': rlB.token, Authorization: `Bearer ${userJwt()}` });
  check('a different agent is not affected by the first one\'s limit', bRes.status !== 429);
  const rl = [];
  for (let i = 0; i < 7; i++) rl.push(await call('POST', `/a2a/${a2aVs}/${a2aId}`, { jsonrpc: '2.0', id: 'r' + i, method: 'SendMessage', params: {} }, { 'X-Agent-Token': rlC.token }));
  const limited = rl.find(r => r.status === 429);
  check('A2A is limited too, with a JSON-RPC shaped error that keeps the request id', !!limited && limited.json.error.code === -32012 && /^r\d$/.test(limited.json.id) && Number(limited.headers.get('retry-after')) > 0, limited && limited.text);
  const scans = []; for (let i = 0; i < 7; i++) scans.push(await scan({ 'X-Agent-Token': rlD.token, 'X-API-Key': keyChat }));
  check('message scanning is limited per agent', scans.some(r => r.status === 429));
  const co = []; for (let i = 0; i < 7; i++) co.push(await call('POST', '/api/vault/checkout', { secret: 'x' }, { 'X-Agent-Token': rlB.token }));
  check('vault checkout is limited per agent', co.some(r => r.status === 429));
  check('the admin API is not rate limited by this (an admin is never locked out of the UI)', (await Promise.all(Array.from({ length: 12 }, () => call('GET', '/api/agents', undefined, asAdmin)))).every(r => r.status === 200));
  process.env.WARDEN_RATE_LIMIT_PER_MIN = '0';
  check('0 turns the limiter off', (await hammer(10, { 'X-Agent-Token': rlA.token, Authorization: `Bearer ${userJwt()}` })).every(r => r.status !== 429));
  delete process.env.WARDEN_RATE_LIMIT_PER_MIN;

  // ═══ 9. bind address ══════════════════════════════════════════════════════
  section('9. Warden listens on this machine only by default');
  const lan = Object.values(os.networkInterfaces()).flat().find(i => i && i.family === 'IPv4' && !i.internal);
  if (lan) {
    const reachable = await new Promise(resolve => { const s = net.connect({ host: lan.address, port: Number(process.env.PORT), timeout: 1500 }); s.on('connect', () => { s.destroy(); resolve(true); }); s.on('error', () => resolve(false)); s.on('timeout', () => { s.destroy(); resolve(false); }); });
    check(`not reachable on this machine's network address (${lan.address})`, reachable === false);
  } else check('(no non-loopback network interface to probe; skipped)', true);
  check('reachable on loopback', (await call('GET', '/api/health')).status === 200);

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length) console.log('Failed:\n - ' + failures.join('\n - '));
  return failures.length;
}

main().then(n => cleanup(n), e => { console.error('\nTEST HARNESS ERROR:', e); cleanup(1); });
function cleanup(code) { setTimeout(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} process.exit(code ? 1 : 0); }, 300); }
