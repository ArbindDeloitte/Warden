'use strict';

// End-to-end test for the Credential Vault. Boots Warden on a THROWAWAY database and key file plus a
// fake upstream MCP server, so it never touches data/virtual-server.db.
//   node scripts/test-vault.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-vault-test-'));
process.env.SQLITE_PATH = path.join(tmp, 'test.db'); process.env.WARDEN_ADMIN_TOKEN = ''; // explicit empty = open mode, even if Warden's .env has a token
process.env.PORT = process.env.TEST_PORT || '3013';
process.env.NODE_ENV = 'development';
process.env.JWKS_URI = '';      // dev-mode token handling (no JWKS lookups)
process.env.REDIS_URL = 'redis://127.0.0.1:1'; // never reachable; OBO is off in these tests
delete process.env.WARDEN_SECRETS_KEY;

const BASE = `http://127.0.0.1:${process.env.PORT}`;
const jwt = require('jsonwebtoken');

let passed = 0; const failures = [];
function check(name, cond, detail) {
  if (cond) { passed++; console.log(`  ok   ${name}`); }
  else { failures.push(name); console.log(`  FAIL ${name}${detail !== undefined ? '  -> ' + (typeof detail === 'string' ? detail : JSON.stringify(detail)) : ''}`); }
}
const section = (t) => console.log(`\n== ${t}`);

async function api(method, p, body, headers = {}) {
  const res = await fetch(BASE + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json = null; const text = await res.text();
  try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text };
}
const agentHdr = (t) => ({ 'X-Agent-Token': t });
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ── fake upstream MCP server ────────────────────────────────────────────────
const upstreamCalls = [];
const upstream = http.createServer((req, res) => {
  let body = '';
  req.on('data', c => { body += c; });
  req.on('end', () => {
    let msg = {}; try { msg = JSON.parse(body || '{}'); } catch {}
    upstreamCalls.push({ url: req.url, method: msg.method, headers: req.headers, params: msg.params });
    const ok = (result, extra = {}) => {
      res.writeHead(200, { 'content-type': 'application/json', ...extra });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result }));
    };
    if (msg.method === 'initialize') return ok({ protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'fake', version: '1' } }, { 'mcp-session-id': 'sess-' + crypto.randomBytes(4).toString('hex') });
    if (msg.method === 'notifications/initialized') { res.writeHead(202); return res.end(); }
    if (msg.method === 'tools/list') return ok({ tools: [{ name: 'echo', description: 'echo', inputSchema: { type: 'object' } }] });
    if (msg.method === 'tools/call') {
      // Deliberately echoes everything it received, including credentials, to prove Warden redacts them.
      return ok({ content: [{ type: 'text', text: JSON.stringify({ args: msg.params.arguments, auth: req.headers.authorization, upstreamKey: req.headers['x-upstream-key'] }) }] });
    }
    res.writeHead(400); res.end('{}');
  });
});
const toolCalls = (u) => upstreamCalls.filter(c => c.method === 'tools/call' && c.url === u);

async function main() {
  await new Promise(r => upstream.listen(0, '127.0.0.1', r));
  const UP = `http://127.0.0.1:${upstream.address().port}`;

  const app = require('../src/app');
  const db = require('../src/db/database');
  const vault = require('../src/services/vault');
  for (let i = 0; i < 50; i++) { try { if ((await fetch(BASE + '/api/health')).ok) break; } catch {} await sleep(100); }

  // ── fixtures ───────────────────────────────────────────────────────────────
  const mkAgent = async (name) => { const r = await api('POST', '/api/agents', { name }); return { id: r.json.id, token: r.json.token, name }; };
  const alpha = await mkAgent('alpha'), beta = await mkAgent('beta'), gamma = await mkAgent('gamma');
  const grp = (await api('POST', '/api/agent-groups', { name: 'ops' })).json;
  await api('POST', `/api/agent-groups/${grp.id}/members`, { agent_id: alpha.id });
  const mkVs = async (name, extra = {}) => (await api('POST', '/api/virtual-servers', { name, require_obo: 0, allow_anonymous: true, features_enabled: ['policy'], ...extra })).json.id;
  const vs1 = await mkVs('vs1'), vs2 = await mkVs('vs2');
  const mkSecret = async (name, value, extra = {}) => api('POST', '/api/vault/secrets', { name, value, ...extra });
  const permit = async (extra) => (await api('POST', '/api/vault/policies', { name: 'p', effect: 'permit', ...extra })).json;
  const clearPolicies = () => db.exec('DELETE FROM vault_policies');
  const checkout = (agent, secret, extra = {}) => api('POST', '/api/vault/checkout', { secret, ...extra }, agentHdr(agent.token));

  // ═══ A. secret creation + storage ═════════════════════════════════════════
  section('A. secrets: validation and storage');
  const SK = 'sk-live-ABCDEFGH12345678';
  check('bad name rejected', (await mkSecret('bad name!', 'x')).status === 400);
  check('empty value rejected', (await mkSecret('empty', '')).status === 400);
  check('garbage private_key rejected', (await mkSecret('badkey', 'not a pem', { type: 'private_key' })).status === 400);
  const created = await mkSecret('api-secret', SK, { type: 'api_key', description: 'test' });
  check('create secret -> 201 with reference', created.status === 201 && created.json.reference === 'vault://api-secret', created.text);
  check('duplicate name -> 409', (await mkSecret('api-secret', 'other')).status === 409);
  const secretId = created.json.id;
  const lst = await api('GET', '/api/vault/secrets'); const one = await api('GET', `/api/vault/secrets/${secretId}`);
  check('list/get never expose value or value_enc', !lst.text.includes(SK) && !one.text.includes(SK) && !lst.text.includes('value_enc') && !one.text.includes('value_enc'));
  const raw = db.prepare('SELECT value_enc FROM vault_secrets WHERE id = ?').get(secretId).value_enc;
  check('value encrypted at rest (v1: AES-GCM blob, no plaintext)', raw.startsWith('v1:') && !raw.includes(SK));

  // ═══ B. deny by default ═══════════════════════════════════════════════════
  section('B. checkout authentication and deny-by-default');
  check('no agent token -> 401', (await api('POST', '/api/vault/checkout', { secret: 'api-secret' })).status === 401);
  check('unknown agent token -> 401', (await api('POST', '/api/vault/checkout', { secret: 'api-secret' }, agentHdr('wag_nope'))).status === 401);
  check('missing secret field -> 400', (await api('POST', '/api/vault/checkout', {}, agentHdr(alpha.token))).status === 400);
  const denied = await checkout(alpha, 'api-secret');
  const missing = await checkout(alpha, 'does-not-exist');
  check('no policy -> 403 (deny by default)', denied.status === 403, denied.text);
  check('denied vs nonexistent secret are indistinguishable (no name enumeration)', denied.status === missing.status && denied.json.error === missing.json.error, [denied.json, missing.json]);

  // ═══ C. policies ══════════════════════════════════════════════════════════
  section('C. policy evaluation');
  check('policy with unknown agent rejected', (await api('POST', '/api/vault/policies', { name: 'x', caller_type: 'agent', caller_value: 'nope' })).status === 400);
  check('policy with unknown secret rejected', (await api('POST', '/api/vault/policies', { name: 'x', secret_id: 'nope' })).status === 400);
  const pGroup = await permit({ name: 'ops-reveal', caller_type: 'group', caller_value: grp.id, secret_id: secretId, operations: ['reveal'], max_ttl_seconds: 120 });
  const ok1 = await checkout(alpha, 'api-secret');
  check('group member permitted: gets value + lease', ok1.status === 200 && ok1.json.value === SK && ok1.json.lease_id && ok1.json.version === 1, ok1.text);
  check('default lease TTL = policy max (120s)', ok1.json.ttl_seconds === 120);
  check('requested shorter TTL honoured', (await checkout(alpha, 'api-secret', { ttl_seconds: 30 })).json.ttl_seconds === 30);
  check('requested TTL capped by policy max', (await checkout(alpha, 'api-secret', { ttl_seconds: 9999 })).json.ttl_seconds === 120);
  check('non-member still denied', (await checkout(beta, 'api-secret')).status === 403);
  check('response is not cacheable', (await fetch(BASE + '/api/vault/checkout', { method: 'POST', headers: { 'Content-Type': 'application/json', ...agentHdr(alpha.token) }, body: JSON.stringify({ secret: 'api-secret' }) })).headers.get('cache-control') === 'no-store');

  const fb = await permit({ name: 'forbid-alpha-tie', effect: 'forbid', caller_type: 'agent', caller_value: alpha.id, secret_id: secretId, priority: 0 });
  check('forbid beats permit at equal priority', (await checkout(alpha, 'api-secret')).status === 403);
  await api('DELETE', `/api/vault/policies/${fb.id}`);
  check('removing the forbid restores access', (await checkout(alpha, 'api-secret')).status === 200);
  const fbHigh = await permit({ name: 'forbid-high', effect: 'forbid', caller_type: 'agent', caller_value: alpha.id, secret_id: secretId, priority: 50 });
  check('higher-priority forbid wins', (await checkout(alpha, 'api-secret')).status === 403);
  await api('DELETE', `/api/vault/policies/${fbHigh.id}`);
  await api('PUT', `/api/vault/policies/${pGroup.id}`, { priority: 10 });
  const fbLow = await permit({ name: 'forbid-low', effect: 'forbid', caller_type: 'agent', caller_value: alpha.id, secret_id: secretId, priority: 5 });
  check('higher-priority permit beats lower-priority forbid', (await checkout(alpha, 'api-secret')).status === 200);
  await api('DELETE', `/api/vault/policies/${fbLow.id}`);
  await api('PUT', `/api/vault/policies/${pGroup.id}`, { is_active: false });
  check('inactive policy is ignored', (await checkout(alpha, 'api-secret')).status === 403);
  await api('PUT', `/api/vault/policies/${pGroup.id}`, { is_active: true });
  check('operation-restricted policy does not grant sign', (await api('POST', '/api/vault/sign', { secret: 'api-secret' }, agentHdr(alpha.token))).status === 403);

  section('C2. virtual-server scoping');
  clearPolicies();
  await permit({ name: 'vs1-only', caller_type: 'agent', caller_value: alpha.id, secret_id: secretId, virtual_server_id: vs1 });
  check('VS-scoped policy does not match when no VS is named', (await checkout(alpha, 'api-secret')).status === 403);
  check('VS-scoped policy matches its VS', (await checkout(alpha, 'api-secret', { virtual_server_id: vs1 })).status === 200);
  check('VS-scoped policy does not match another VS', (await checkout(alpha, 'api-secret', { virtual_server_id: vs2 })).status === 403);
  check('unknown VS -> 404', (await checkout(alpha, 'api-secret', { virtual_server_id: 'nope' })).status === 404);
  db.prepare('UPDATE virtual_servers SET require_agent_token = 1 WHERE id = ?').run(vs1);
  check('require_agent_token VS: agent not in allowlist -> 403', (await checkout(alpha, 'api-secret', { virtual_server_id: vs1 })).status === 403);
  await api('POST', `/api/virtual-servers/${vs1}/agents`, { agent_id: alpha.id });
  check('require_agent_token VS: allowlisted agent -> 200', (await checkout(alpha, 'api-secret', { virtual_server_id: vs1 })).status === 200);
  db.prepare('UPDATE virtual_servers SET require_agent_token = 0 WHERE id = ?').run(vs1);

  // ═══ D. secret / agent state ══════════════════════════════════════════════
  section('D. secret and agent state');
  clearPolicies();
  await permit({ name: 'alpha-all', caller_type: 'agent', caller_value: alpha.id });
  await permit({ name: 'gamma-all', caller_type: 'agent', caller_value: gamma.id });
  await api('PUT', `/api/vault/secrets/${secretId}`, { is_active: false });
  const dis = await checkout(alpha, 'api-secret');
  check('disabled secret -> 403, same message as unknown secret', dis.status === 403 && dis.json.error === missing.json.error);
  await api('PUT', `/api/vault/secrets/${secretId}`, { is_active: true });
  check('re-enabled secret works', (await checkout(alpha, 'api-secret')).status === 200);
  await api('PUT', `/api/vault/secrets/${secretId}`, { expires_at: new Date(Date.now() - 60000).toISOString() });
  check('expired secret -> 403', (await checkout(alpha, 'api-secret')).status === 403);
  check('bad expires_at rejected', (await api('PUT', `/api/vault/secrets/${secretId}`, { expires_at: 'not-a-date' })).status === 400);
  await api('PUT', `/api/vault/secrets/${secretId}`, { expires_at: new Date(Date.now() + 20000).toISOString() });
  const shortLived = await checkout(alpha, 'api-secret', { ttl_seconds: 3000 });
  check('lease TTL capped by secret expiry', shortLived.status === 200 && shortLived.json.ttl_seconds <= 20, shortLived.json.ttl_seconds);
  await api('PUT', `/api/vault/secrets/${secretId}`, { expires_at: null });
  await api('PATCH', `/api/agents/${gamma.id}/toggle`);
  const gOff = await checkout(gamma, 'api-secret');
  check('disabled agent -> 403', gOff.status === 403, gOff.text);
  await api('PATCH', `/api/agents/${gamma.id}/toggle`);

  // ═══ E. leases + rotation ═════════════════════════════════════════════════
  section('E. leases and rotation');
  const l1 = (await checkout(alpha, 'api-secret')).json;
  const v1 = await api('GET', `/api/vault/validate/${l1.lease_id}`, undefined, agentHdr(alpha.token));
  check('fresh lease validates', v1.status === 200 && v1.json.valid === true, v1.text);
  check('another agent cannot validate this lease', (await api('GET', `/api/vault/validate/${l1.lease_id}`, undefined, agentHdr(beta.token))).status === 404);
  const active = await api('GET', '/api/vault/leases?active=1');
  check('lease listed as active', active.json.some(l => l.id === l1.lease_id && l.state === 'active' && l.agent_name === 'alpha' && l.secret_name === 'api-secret'));
  await api('DELETE', `/api/vault/leases/${l1.lease_id}`);
  const v2 = await api('GET', `/api/vault/validate/${l1.lease_id}`, undefined, agentHdr(alpha.token));
  check('revoked lease no longer validates', v2.json.valid === false && /revoked/i.test(v2.json.reason), v2.text);
  const l2 = (await checkout(alpha, 'api-secret')).json;
  const NEW = 'sk-live-ROTATED-0987654321';
  check('rotate rejects empty value', (await api('POST', `/api/vault/secrets/${secretId}/rotate`, { value: '' })).status === 400);
  const rot = await api('POST', `/api/vault/secrets/${secretId}/rotate`, { value: NEW });
  check('rotate -> version 2 and voids outstanding leases', rot.json.version === 2 && rot.json.leases_revoked >= 1, rot.text);
  const v3 = await api('GET', `/api/vault/validate/${l2.lease_id}`, undefined, agentHdr(alpha.token));
  check('lease invalid after rotation', v3.json.valid === false, v3.text);
  const after = await checkout(alpha, 'api-secret');
  check('checkout returns the rotated value and version', after.json.value === NEW && after.json.version === 2, after.text);

  // ═══ F. sign-on-behalf ════════════════════════════════════════════════════
  section('F. sign-on-behalf');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const keySecret = await mkSecret('okta-key', pem, { type: 'private_key', metadata: { client_id: 'cid123', token_url: 'https://idp.example/oauth2/v1/token', kid: 'kid-1' } });
  check('valid private_key accepted', keySecret.status === 201, keySecret.text);
  clearPolicies();
  await permit({ name: 'alpha-sign', caller_type: 'agent', caller_value: alpha.id, operations: ['sign'] });
  const signed = await api('POST', '/api/vault/sign', { secret: 'okta-key', claims: { exp: 1, scope: 'x' } }, agentHdr(alpha.token));
  check('sign -> 200 with token', signed.status === 200 && !!signed.json.token, signed.text);
  const decoded = jwt.verify(signed.json.token, publicKey, { algorithms: ['RS256'], complete: true });
  check('signature verifies with the public key', !!decoded.payload);
  check('header kid from metadata', decoded.header.kid === 'kid-1');
  check('iss/sub default to metadata.client_id, aud to token_url', decoded.payload.iss === 'cid123' && decoded.payload.sub === 'cid123' && decoded.payload.aud === 'https://idp.example/oauth2/v1/token');
  check('caller cannot override exp (Warden sets iat/exp/jti); custom claims kept', decoded.payload.exp - decoded.payload.iat === 300 && decoded.payload.scope === 'x' && !!decoded.payload.jti);
  const clamped = jwt.decode((await api('POST', '/api/vault/sign', { secret: 'okta-key', expires_in: 999999 }, agentHdr(alpha.token))).json.token);
  check('expires_in clamped to 3600s', clamped.exp - clamped.iat === 3600);
  check('private key never appears in sign response', !signed.text.includes('PRIVATE KEY'));
  check('algorithm "none" rejected', (await api('POST', '/api/vault/sign', { secret: 'okta-key', algorithm: 'none' }, agentHdr(alpha.token))).status === 400);
  check('HS256 rejected (no key-confusion)', (await api('POST', '/api/vault/sign', { secret: 'okta-key', algorithm: 'HS256' }, agentHdr(alpha.token))).status === 400);
  check('sign denied without sign permission (reveal)', (await checkout(alpha, 'okta-key')).status === 403);
  check('non-private_key secret cannot sign -> 400', (await api('POST', '/api/vault/sign', { secret: 'api-secret' }, agentHdr(alpha.token))).status === 400);

  // ═══ G. simulator parity ══════════════════════════════════════════════════
  section('G. simulator matches enforcement');
  clearPolicies();
  const gp = await permit({ name: 'sim-permit', caller_type: 'group', caller_value: grp.id, secret_id: secretId, operations: ['reveal', 'broker'], virtual_server_id: vs1 });
  await permit({ name: 'sim-forbid-broker', effect: 'forbid', caller_type: 'agent', caller_value: alpha.id, secret_id: secretId, operations: ['broker'], priority: 5 });
  const sim = (agent, op, vs) => api('POST', '/api/vault/policies/simulate', { caller_agent_id: agent.id, secret_id: secretId, operation: op, virtual_server_id: vs });
  const cases = [[alpha, 'reveal', vs1], [alpha, 'reveal', vs2], [alpha, 'reveal', undefined], [alpha, 'broker', vs1], [beta, 'reveal', vs1]];
  for (const [agent, op, vs] of cases) {
    const s = await sim(agent, op, vs);
    let actual;
    if (op === 'reveal') actual = (await checkout(agent, 'api-secret', vs ? { virtual_server_id: vs } : {})).status === 200 ? 'allow' : 'deny';
    else actual = (() => { try { vault.access({ agentId: agent.id, agentName: agent.name, vsId: vs }, 'api-secret', op, 'test'); return 'allow'; } catch { return 'deny'; } })();
    check(`simulate(${agent.name}, ${op}, ${vs === vs1 ? 'vs1' : vs === vs2 ? 'vs2' : 'none'}) = ${actual}`, s.json.decision === actual, s.json);
  }
  const trace = (await sim(alpha, 'broker', vs1)).json;
  check('simulator trace marks the deciding policy', trace.trace.some(t => t.decides && t.policyName === 'sim-forbid-broker') && trace.caller.groups.includes('ops'));

  // ═══ H. brokered injection through the proxy ══════════════════════════════
  section('H. brokered mode (proxy)');
  const UPKEY = 'upkey-1234567890', TOOLSEC = 'toolsecret-ABCDEFGH', UPBEARER = 'bearer-XYZ1234567';
  await mkSecret('upstream-key', UPKEY, { type: 'api_key' });
  await mkSecret('tool-secret', TOOLSEC);
  await mkSecret('upstream-bearer', UPBEARER, { type: 'bearer_token' });
  const mcpA = (await api('POST', '/api/mcp', { name: 'mcpA', url: `${UP}/a`, auth_type: 'apikey', auth_config: { header: 'X-Upstream-Key', key: 'vault://upstream-key' } })).json.id;
  const mcpB = (await api('POST', '/api/mcp', { name: 'mcpB', url: `${UP}/b`, auth_type: 'apikey', auth_config: { header: 'X-Upstream-Key', key: 'plain-static-key' } })).json.id;
  const mcpC = (await api('POST', '/api/mcp', { name: 'mcpC', url: `${UP}/c`, auth_type: 'bearer', auth_config: { token: 'vault://upstream-bearer' } })).json.id;
  const list = (await api('GET', '/api/mcp')).json;
  check('MCP list shows vault refs unmasked and masks plain keys', list.find(s => s.id === mcpA).auth_config.key === 'vault://upstream-key' && list.find(s => s.id === mcpB).auth_config.key === '***');
  for (const m of [mcpA, mcpB, mcpC]) await api('POST', `/api/virtual-servers/${vs1}/tools`, { mcp_server_id: m, tool_name: '*' });
  await api('POST', '/api/token-policies', { virtual_server_id: vs1, name: 'allow-all', effect: 'permit', policy_json: { actions: [{ mcp_server_id: '*', tool: '*' }], conditions: [] } });
  clearPolicies();
  await permit({ name: 'ops-broker', caller_type: 'group', caller_value: grp.id, operations: ['broker'], virtual_server_id: vs1 });

  const userTok = jwt.sign({ sub: 'user-1' }, 'x');
  const proxy = (agent, mcp, args, vs = vs1) => api('POST', `/api/proxy/${vs}`, { mcp_server_id: mcp, tool_name: 'echo', arguments: args },
    { Authorization: `Bearer ${userTok}`, ...(agent ? agentHdr(agent.token) : {}) });
  const args = { t: 'vault://tool-secret', nested: { arr: ['vault://tool-secret', 'plain', 'see vault://tool-secret inline'] }, 'vault://tool-secret': 'key-not-substituted' };
  const r1 = await proxy(alpha, mcpA, args);
  check('brokered call -> 200', r1.status === 200, r1.text);
  const seen = toolCalls('/a').at(-1);
  check('upstream received the substituted argument (top-level + nested array)', seen.params.arguments.t === TOOLSEC && seen.params.arguments.nested.arr[0] === TOOLSEC);
  check('embedded vault:// text and object keys are NOT substituted', seen.params.arguments.nested.arr[2] === 'see vault://tool-secret inline' && seen.params.arguments['vault://tool-secret'] === 'key-not-substituted');
  check('upstream auth header injected from vault (apikey)', seen.headers['x-upstream-key'] === UPKEY);
  check('OBO/user Authorization header preserved alongside apikey', seen.headers.authorization === `Bearer ${userTok}`);
  check('brokered secrets are redacted from the response the agent gets', !r1.text.includes(TOOLSEC) && !r1.text.includes(UPKEY) && r1.text.includes('REDACTED'), r1.text);

  const before = toolCalls('/a').length;
  const rBeta = await proxy(beta, mcpA, args);
  check('agent without broker permission -> 403, upstream NOT called', rBeta.status === 403 && toolCalls('/a').length === before, rBeta.text);
  const rAnon = await proxy(null, mcpA, args);
  check('call with no agent identity cannot use vault refs -> 403', rAnon.status === 403, rAnon.text);
  const rB = await proxy(null, mcpB, { q: 'plain' });
  check('plain config + no refs: unchanged behaviour (no agent needed)', rB.status === 200 && toolCalls('/b').at(-1).params.arguments.q === 'plain');
  check('plain static auth_config is NOT injected into tool calls (pre-existing behaviour)', toolCalls('/b').at(-1).headers['x-upstream-key'] === undefined);
  const rC = await proxy(alpha, mcpC, { q: 1 });
  check('bearer vault ref replaces Authorization when OBO is off', rC.status === 200 && toolCalls('/c').at(-1).headers.authorization === `Bearer ${UPBEARER}`);
  const withObo = vault.prepareToolCall({ args: {}, mcpServer: { auth_type: 'bearer', auth_config: JSON.stringify({ token: 'vault://upstream-bearer' }) }, ctx: { agentId: alpha.id, agentName: 'alpha', vsId: vs1 }, hasObo: true });
  check('bearer vault ref does NOT clobber the OBO token when OBO is on', Object.keys(withObo.extraHeaders).length === 0);
  const withOboKey = vault.prepareToolCall({ args: {}, mcpServer: { auth_type: 'apikey', auth_config: JSON.stringify({ header: 'X-K', key: 'vault://upstream-key' }) }, ctx: { agentId: alpha.id, agentName: 'alpha', vsId: vs1 }, hasObo: true });
  check('apikey vault ref still applies when OBO is on', withOboKey.extraHeaders['X-K'] === UPKEY);

  section('H2. no plaintext leaks into logs, tickets, or audit');
  const dump = JSON.stringify([db.prepare('SELECT data, summary FROM event_log').all(), db.prepare('SELECT * FROM audit_log').all(), db.prepare('SELECT * FROM approval_tickets').all(), db.prepare('SELECT * FROM vault_leases').all()]);
  check('no secret value in event_log / audit_log / tickets / leases', ![SK, NEW, TOOLSEC, UPKEY, UPBEARER, 'PRIVATE KEY'].some(s => dump.includes(s)));
  const act = (await api('GET', '/api/vault/activity?limit=500')).json;
  check('vault_access events recorded for allow and deny', act.some(e => e.data.operation === 'broker' && e.data.decision === 'allow' && e.data.agent_name === 'alpha') && act.some(e => e.data.decision === 'deny' && e.data.agent_name === 'beta' && e.level === 'warn'));
  check('activity filter by secret_name', (await api('GET', '/api/vault/activity?secret_name=tool-secret')).json.every(e => e.data.secret_name === 'tool-secret'));
  check('activity filter by level', (await api('GET', '/api/vault/activity?level=warn')).json.every(e => e.level === 'warn'));

  // ═══ I. discovery + system principal ══════════════════════════════════════
  section('I. discovery (system principal)');
  const sync = await api('POST', `/api/mcp/${mcpA}/sync`);
  const listCall = upstreamCalls.filter(c => c.method === 'tools/list' && c.url === '/a').at(-1);
  check('tools/list sent the vault-resolved credential', sync.status < 300 && listCall?.headers['x-upstream-key'] === UPKEY, sync.text);
  check('system access audited with principal=system', (await api('GET', '/api/vault/activity?secret_name=upstream-key')).json.some(e => e.data.principal === 'system' && e.data.via === 'discovery'));
  await api('PUT', `/api/vault/secrets/${(await api('GET', '/api/vault/secrets')).json.find(s => s.name === 'upstream-key').id}`, { is_active: false });
  const sync2 = await api('POST', `/api/mcp/${mcpA}/sync`);
  check('discovery fails closed when the secret is disabled', sync2.status >= 400, sync2.text);
  await api('PUT', `/api/vault/secrets/${(await api('GET', '/api/vault/secrets')).json.find(s => s.name === 'upstream-key').id}`, { is_active: true });
  check('resolveSystemValue passes plain values through', vault.resolveSystemValue('plain') === 'plain');
  check('resolveSystemValue resolves refs', vault.resolveSystemValue('vault://tool-secret') === TOOLSEC);
  let sysErr; try { vault.resolveSystemValue('vault://nope'); } catch (e) { sysErr = e; }
  check('resolveSystemValue throws a descriptive VaultError for a missing ref', sysErr instanceof vault.VaultError && /nope/.test(sysErr.message));

  section('I2. virtual-server OBO client secret refs');
  const vsRef = (await api('POST', '/api/virtual-servers', { name: 'vs-ref', okta_issuer: 'https://idp.example.invalid/oauth2/x', okta_client_secret: 'vault://tool-secret' })).json.id;
  const vsPlain = (await api('POST', '/api/virtual-servers', { name: 'vs-plain', okta_issuer: 'https://idp.example.invalid/oauth2/x', okta_client_secret: 'hunter2-plain' })).json.id;
  check('VS shows a vault ref unmasked', (await api('GET', `/api/virtual-servers/${vsRef}`)).json.okta_client_secret === 'vault://tool-secret');
  check('VS still masks a plain client secret', (await api('GET', `/api/virtual-servers/${vsPlain}`)).json.okta_client_secret === '***');

  // ═══ J. approval flow ═════════════════════════════════════════════════════
  section('J. approval flow keeps placeholders, resolves at execution');
  const apId = crypto.randomUUID();
  db.prepare(`INSERT INTO policies (id, virtual_server_id, name, effect, priority, policy_json) VALUES (?,?,?,?,?,?)`)
    .run(apId, vs1, 'needs-approval', 'approval', 100, JSON.stringify({ actions: [{ mcp_server_id: '*', tool: 'echo' }], conditions: [], approval_config: { ttl_minutes: 5, timeout_action: 'deny' } }));
  const pend = await proxy(alpha, mcpA, { t: 'vault://tool-secret' });
  check('approval-gated call -> 202 ticket', pend.status === 202 && !!pend.json.ticket_id, pend.text);
  const ticket = db.prepare('SELECT * FROM approval_tickets WHERE id = ?').get(pend.json.ticket_id);
  check('ticket stores the placeholder, not the secret, and the agent identity', ticket.tool_arguments.includes('vault://tool-secret') && !ticket.tool_arguments.includes(TOOLSEC) && ticket.agent_id === alpha.id);
  const callsBefore = toolCalls('/a').length;
  await api('POST', `/api/approvals/${pend.json.ticket_id}/decide`, { action: 'approve', decided_by: 'tester' });
  let done; for (let i = 0; i < 40; i++) { await sleep(100); done = db.prepare('SELECT * FROM approval_tickets WHERE id = ?').get(pend.json.ticket_id); if (done.status === 'executed' || done.exec_error) break; }
  check('approved ticket executed', done.status === 'executed' && !done.exec_error, done.exec_error);
  check('upstream received the resolved secret at execution time', toolCalls('/a').length === callsBefore + 1 && toolCalls('/a').at(-1).params.arguments.t === TOOLSEC);
  check('stored ticket result is redacted', !done.result.includes(TOOLSEC) && done.result.includes('REDACTED'));
  // A second ticket whose agent loses access before approval must fail closed.
  const pend2 = await proxy(alpha, mcpA, { t: 'vault://tool-secret' });
  clearPolicies();
  await api('POST', `/api/approvals/${pend2.json.ticket_id}/decide`, { action: 'approve' });
  await sleep(600);
  const done2 = db.prepare('SELECT * FROM approval_tickets WHERE id = ?').get(pend2.json.ticket_id);
  check('policy revoked before approval -> execution fails closed (no upstream call)', !!done2.exec_error && done2.status !== 'executed', done2);
  db.prepare('DELETE FROM policies WHERE id = ?').run(apId);

  // ═══ K. deletion semantics ════════════════════════════════════════════════
  section('K. deletion');
  await permit({ name: 'ops-broker', caller_type: 'group', caller_value: grp.id, operations: ['broker'], virtual_server_id: vs1 });
  const upId = (await api('GET', '/api/vault/secrets')).json.find(s => s.name === 'upstream-key').id;
  const del1 = await api('DELETE', `/api/vault/secrets/${upId}`);
  check('delete of an in-use secret -> 409 listing usage', del1.status === 409 && del1.json.usage.mcp_servers.some(m => m.id === mcpA), del1.text);
  const specific = await permit({ name: 'for-upstream-key', caller_type: 'any', secret_id: upId });
  check('delete with ?force=true succeeds', (await api('DELETE', `/api/vault/secrets/${upId}?force=true`)).status === 200);
  check('policies targeting the deleted secret are removed', !(await api('GET', '/api/vault/policies')).json.some(p => p.id === specific.id));
  const rGone = await proxy(alpha, mcpA, { q: 1 });
  check('dangling vault ref fails closed (403, never calls upstream without credential)', rGone.status === 403, rGone.text);
  const vs3 = await mkVs('vs3');
  const scoped = await permit({ name: 'vs3-scoped', virtual_server_id: vs3 });
  await api('DELETE', `/api/virtual-servers/${vs3}`);
  check('deleting a VS removes policies scoped to it', !(await api('GET', '/api/vault/policies')).json.some(p => p.id === scoped.id));

  section('M. per-virtual-server vault switch');
  const M_SECRET = 'msecret-ABCDEFGH1234', M_KEY = 'mkey-1234567890';
  await mkSecret('m-secret', M_SECRET); await mkSecret('m-key', M_KEY, { type: 'api_key' });
  const mcpPlain = (await api('POST', '/api/mcp', { name: 'mPlain', url: `${UP}/m1` })).json.id;
  const mcpVault = (await api('POST', '/api/mcp', { name: 'mVault', url: `${UP}/m2`, auth_type: 'apikey', auth_config: { header: 'X-Upstream-Key', key: 'vault://m-key' } })).json.id;
  const vsOff = await mkVs('vs-off', { vault_enabled: false }), vsOn = await mkVs('vs-on', { vault_enabled: true }), vsDef = await mkVs('vs-default');
  for (const v of [vsOff, vsOn, vsDef]) {
    for (const m of [mcpPlain, mcpVault]) await api('POST', `/api/virtual-servers/${v}/tools`, { mcp_server_id: m, tool_name: '*' });
    await api('POST', '/api/token-policies', { virtual_server_id: v, name: 'allow-all', effect: 'permit', policy_json: { actions: [{ mcp_server_id: '*', tool: '*' }], conditions: [] } });
  }
  await permit({ name: 'm-alpha-all', caller_type: 'agent', caller_value: alpha.id, operations: ['broker', 'reveal'] });
  const vsRow = async (id) => (await api('GET', `/api/virtual-servers/${id}`)).json;
  check('the column is exposed: off=0, on=1', (await vsRow(vsOff)).vault_enabled === 0 && (await vsRow(vsOn)).vault_enabled === 1);
  check('omitting the field on create keeps the old behaviour (on)', (await vsRow(vsDef)).vault_enabled === 1);
  const vaultEvents = () => db.prepare("SELECT COUNT(*) n FROM event_log WHERE log_type='vault_access'").get().n;
  const refArgs = { v: 'vault://m-secret' };

  const evBefore = vaultEvents();
  const offPlain = await proxy(alpha, mcpPlain, refArgs, vsOff);
  check('vault OFF: the call succeeds and vault:// text passes through untouched', offPlain.status === 200 && toolCalls('/m1').at(-1).params.arguments.v === 'vault://m-secret', offPlain.text);
  check('vault OFF: the vault is never consulted (no vault_access events at all)', vaultEvents() === evBefore);
  const m2Before = toolCalls('/m2').length;
  const offCred = await proxy(alpha, mcpVault, {}, vsOff);
  check('vault OFF + an MCP server that needs a vault credential: refused with a clear error', offCred.status === 403 && offCred.json?.code === 'vault_disabled' && /disabled/i.test(offCred.json?.reason), offCred.text);
  check('vault OFF: the upstream is never called without its credential', toolCalls('/m2').length === m2Before);
  check('vault OFF: the refusal is audited for admins', db.prepare("SELECT COUNT(*) n FROM event_log WHERE log_type='vault_access' AND level='warn' AND json_extract(data,'$.reason') LIKE '%disabled on this virtual server%'").get().n === 1);
  const offCheckout = await api('POST', '/api/vault/checkout', { secret: 'm-secret', virtual_server_id: vsOff }, { 'X-Agent-Token': alpha.token });
  check('vault OFF: runtime checkout naming that virtual server is refused too', offCheckout.status === 403 && /disabled/i.test(offCheckout.json?.error), offCheckout.text);

  const onArg = await proxy(alpha, mcpPlain, refArgs, vsOn);
  check('vault ON: the argument placeholder is resolved', onArg.status === 200 && toolCalls('/m1').at(-1).params.arguments.v === M_SECRET, onArg.text);
  const onCred = await proxy(alpha, mcpVault, {}, vsOn);
  check('vault ON: the MCP server credential is injected from the vault', onCred.status === 200 && toolCalls('/m2').at(-1).headers['x-upstream-key'] === M_KEY, onCred.text);
  const defCred = await proxy(alpha, mcpVault, {}, vsDef);
  check('a virtual server created without the field still brokers (backward compatible)', defCred.status === 200 && toolCalls('/m2').at(-1).headers['x-upstream-key'] === M_KEY);

  const putVs = (id, extra) => api('PUT', `/api/virtual-servers/${id}`, { name: 'vs-off', require_obo: 0, allow_anonymous: true, features_enabled: ['policy'], ...extra });
  await putVs(vsOff, { vault_enabled: true });
  const nowOn = await proxy(alpha, mcpVault, {}, vsOff);
  check('toggling ON in place takes effect on the very next call', (await vsRow(vsOff)).vault_enabled === 1 && nowOn.status === 200);
  await putVs(vsOff, { vault_enabled: false });
  check('toggling OFF in place takes effect on the very next call', (await vsRow(vsOff)).vault_enabled === 0 && (await proxy(alpha, mcpVault, {}, vsOff)).status === 403);
  await putVs(vsOn, {});
  check('an update that omits the field cannot flip it (older clients are safe)', (await vsRow(vsOn)).vault_enabled === 1);

  let oboErr; try { await require('../src/services/oboService').exchangeForOboToken('tok-m', { vault_enabled: 0, okta_issuer: 'https://idp.example', okta_client_id: 'cid', okta_client_secret: 'vault://m-key' }); } catch (e) { oboErr = e; }
  check('vault OFF + a vault:// Okta client secret: a clear configuration error, no vault read', /disabled/i.test(oboErr?.message || '') && vaultEvents() === db.prepare("SELECT COUNT(*) n FROM event_log WHERE log_type='vault_access'").get().n);

  section('L. misc');
  const meta = (await api('GET', '/api/vault/meta')).json;
  check('meta lists types, operations, algorithms', meta.types.includes('private_key') && meta.operations.length === 3 && meta.sign_algorithms.includes('RS256'));
  check('unknown API route still JSON 404 (router mounted without shadowing)', (await api('GET', '/api/vault/nope')).status === 404);

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length) console.log('Failed:\n - ' + failures.join('\n - '));
  return failures.length;
}

main().then(n => cleanup(n), e => { console.error('\nTEST HARNESS ERROR:', e); cleanup(1); });

function cleanup(code) {
  try { upstream.close(); } catch {}
  setTimeout(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} process.exit(code ? 1 : 0); }, 200);
}
