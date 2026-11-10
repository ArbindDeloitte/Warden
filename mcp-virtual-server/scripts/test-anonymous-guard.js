'use strict';

// Guards for virtual servers that identify nobody or cannot verify who is calling:
//   - require_obo = 0 AND require_agent_token = 0 is refused unless acknowledged (allow_anonymous)
//   - require_obo on with no issuer / jwks_uri is refused, and unverified token claims never act as an identity
// Runs against a THROWAWAY Warden (never your real one):  node scripts/test-anonymous-guard.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'anon-guard-test-'));
const DB_FILE = path.join(tmp, 'test.db');
const PORT = process.env.TEST_PORT || '3036';
Object.assign(process.env, { SQLITE_PATH: DB_FILE, PORT, NODE_ENV: 'development', JWKS_URI: '', REDIS_URL: 'redis://127.0.0.1:1', WARDEN_ADMIN_TOKEN: '' });
const BASE = `http://127.0.0.1:${PORT}`;
const SRC = path.join(__dirname, '..', 'src');

let passed = 0; const failures = [];
function check(name, cond, detail) {
  if (cond) { passed++; console.log(`  ok   ${name}`); }
  else { failures.push(name); console.log(`  FAIL ${name}${detail !== undefined ? '  -> ' + (typeof detail === 'string' ? detail : JSON.stringify(detail)) : ''}`); }
}
const section = (t) => console.log(`\n== ${t}`);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
async function api(method, p, body, headers = {}) {
  const res = await fetch(BASE + p, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text };
}
const post = (b) => api('POST', '/api/virtual-servers', b);
const put = (id, b) => api('PUT', `/api/virtual-servers/${id}`, b);
const get = async (id) => (await api('GET', `/api/virtual-servers/${id}`)).json;
const count = async () => (await api('GET', '/api/virtual-servers')).json.length;

async function main() {
  require(path.join(SRC, 'app.js'));
  for (let i = 0; i < 80; i++) { try { if ((await fetch(BASE + '/api/health')).ok) break; } catch {} await sleep(100); }
  const db = require(path.join(SRC, 'db', 'database.js'));

  section('1. create');
  const n0 = await count();
  const r1 = await post({ name: 'anon-no-ack', require_obo: 0, features_enabled: ['policy'] });
  check('mcp + OBO off + agent token off, no acknowledgement -> 400 anonymous_virtual_server', r1.status === 400 && r1.json?.code === 'anonymous_virtual_server', r1);
  check('the refusal says how to fix it', /require_agent_token/.test(r1.json?.hint || '') && /allow_anonymous/.test(r1.json?.hint || ''));
  check('nothing was created', (await count()) === n0);
  const r2 = await post({ name: 'anon-ack', require_obo: 0, allow_anonymous: true });
  check('with allow_anonymous: true -> 201', r2.status === 201, r2);
  const v2 = await get(r2.json.id);
  check('the acknowledgement is stored', v2.allow_anonymous === 1 && v2.require_obo === 0 && v2.require_agent_token === 0, v2);
  const ev = db.prepare(`SELECT * FROM event_log WHERE vs_id = ? AND log_type = 'config'`).all(r2.json.id);
  check('saving it anonymously is written to the event log (warn)', ev.length === 1 && ev[0].level === 'warn', ev);
  const r3 = await post({ name: 'secure', require_obo: 0, require_agent_token: 1 });
  check('require_agent_token on -> 201 with no acknowledgement', r3.status === 201);
  check('and no acknowledgement is recorded', (await get(r3.json.id)).allow_anonymous === 0);
  const r4 = await post({ name: 'obo-default', okta_issuer: 'https://idp.example.invalid/oauth2/x' });
  check('OBO left on (default) -> 201', r4.status === 201 && (await get(r4.json.id)).require_obo === 1);
  const r5 = await post({ name: 'a2a-anon', protocol: 'a2a', require_obo: 0 });
  check('A2A-only virtual server is exempt', r5.status === 201 && (await get(r5.json.id)).allow_anonymous === 0);
  const r6 = await post({ name: 'both-anon', protocol: 'both', require_obo: 0 });
  check('protocol "both" (it proxies tools too) is not exempt', r6.status === 400 && r6.json?.code === 'anonymous_virtual_server');
  const r7 = await post({ name: 'truthy-string', require_obo: 0, allow_anonymous: 'yes' });
  check('only a real true/1 counts as acknowledgement (string "yes" does not)', r7.status === 400);
  const r8 = await post({ name: 'obo-false-bool', require_obo: false });
  check('require_obo: false is treated like 0', r8.status === 400);

  section('2. update');
  const sec = r3.json.id;
  const u1 = await put(sec, { name: 'secure', require_obo: 0, require_agent_token: 0 });
  check('turning the agent-token requirement off (no ack) -> 400', u1.status === 400 && u1.json?.code === 'anonymous_virtual_server', u1);
  const afterU1 = await get(sec);
  check('and nothing changed (still requires an agent token)', afterU1.require_agent_token === 1 && afterU1.allow_anonymous === 0);
  const u2 = await put(sec, { name: 'secure', require_obo: 0 });
  check('an older client that omits require_agent_token can no longer silently downgrade a VS', u2.status === 400);
  check('and the VS is untouched', (await get(sec)).require_agent_token === 1);
  const u3 = await put(sec, { name: 'secure', require_obo: 0, require_agent_token: 0, allow_anonymous: true });
  check('with allow_anonymous: true the downgrade is allowed', u3.status === 200);
  const afterU3 = await get(sec);
  check('and recorded', afterU3.allow_anonymous === 1 && afterU3.require_agent_token === 0);
  check('an event-log entry marks it', db.prepare(`SELECT COUNT(*) c FROM event_log WHERE vs_id = ? AND log_type = 'config'`).get(sec).c === 1);
  const u4 = await put(sec, { name: 'secure renamed', description: 'edited', require_obo: 0 });
  check('editing an already-acknowledged VS (flag omitted) keeps working', u4.status === 200 && (await get(sec)).allow_anonymous === 1);
  check('and does not log a second acknowledgement', db.prepare(`SELECT COUNT(*) c FROM event_log WHERE vs_id = ? AND log_type = 'config'`).get(sec).c === 1);
  const u5 = await put(sec, { name: 'secure renamed', require_obo: 0, require_agent_token: 1 });
  check('securing it again works', u5.status === 200);
  check('and clears the acknowledgement', (await get(sec)).allow_anonymous === 0);
  const u6 = await put(sec, { name: 'secure renamed', require_obo: 0, require_agent_token: 0 });
  check('the old acknowledgement cannot be reused: going anonymous again needs a new one', u6.status === 400);
  const u7 = await put(sec, { name: 'secure renamed', require_obo: 0, require_agent_token: 0, allow_anonymous: false });
  check('allow_anonymous: false does not acknowledge', u7.status === 400);
  const u8 = await put(sec, { name: 'secure renamed', require_obo: 1, require_agent_token: 0, okta_issuer: 'https://idp.example.invalid/oauth2/x' });
  check('turning OBO back on satisfies the guard', u8.status === 200);
  const u9 = await put(sec, { name: 'secure renamed', require_obo: 0, require_agent_token: 0, protocol: 'a2a' });
  check('switching the protocol to a2a is what the guard evaluates (exempt)', u9.status === 200);
  const u10 = await put(sec, { name: 'secure renamed', require_obo: 0, require_agent_token: 0, protocol: 'mcp' });
  check('switching it back to mcp while anonymous is refused', u10.status === 400);
  const u11 = await put(sec, { name: 'secure renamed', require_obo: 0, require_agent_token: 0 });
  check('an update that omits protocol on an a2a VS keeps it exempt', u11.status === 200 && (await get(sec)).protocol === 'a2a');
  check('a2a VS never carries the flag', (await get(sec)).allow_anonymous === 0);
  check('404 for an unknown VS still comes first', (await put('nope', { name: 'x', require_obo: 0 })).status === 404);

  section('3. the guard does not touch what is already secured');
  const calls = (await api('POST', '/api/virtual-servers', { name: 'bank-like', require_obo: 1, jwks_uri: 'https://example.invalid/keys' })).status;
  check('a normal OBO virtual server saves as before', calls === 201);

  section('3b. OBO on without any way to verify the user is refused at save time');
  const IDP = 'https://idp.example.invalid/oauth2/x';
  const i1 = await post({ name: 'obo-no-idp' });
  check('require_obo on (default), no issuer, no jwks_uri -> 400 obo_without_idp', i1.status === 400 && i1.json?.code === 'obo_without_idp', i1);
  check('the refusal tells you what to set', /issuer/.test(i1.json?.hint || '') && /require_obo/.test(i1.json?.hint || ''));
  check('with an issuer -> 201', (await post({ name: 'obo-issuer', okta_issuer: IDP })).status === 201);
  check('with only a jwks_uri -> 201', (await post({ name: 'obo-jwks', jwks_uri: IDP + '/keys' })).status === 201);
  check('blank/whitespace issuer does not count', (await post({ name: 'obo-blank', okta_issuer: '   ', jwks_uri: '' })).status === 400);
  process.env.JWKS_URI = IDP + '/keys';
  check('a global JWKS_URI counts as a way to verify', (await post({ name: 'obo-global-jwks' })).status === 201);
  process.env.JWKS_URI = '';
  check('A2A-only VS is exempt', (await post({ name: 'a2a-no-idp', protocol: 'a2a' })).status === 201);
  check('OBO off (with an agent token) needs no IdP', (await post({ name: 'agent-only', require_obo: 0, require_agent_token: 1 })).status === 201);
  const oboVs = (await post({ name: 'to-edit', okta_issuer: IDP })).json.id;
  const e1 = await put(oboVs, { name: 'to-edit', require_obo: 1 });
  check('an update that drops the issuer from an OBO VS is refused', e1.status === 400 && e1.json?.code === 'obo_without_idp', e1);
  check('and the VS is unchanged', (await get(oboVs)).okta_issuer === IDP);
  check('an update that keeps the issuer works', (await put(oboVs, { name: 'to-edit', require_obo: 1, okta_issuer: IDP })).status === 200);

  section('3c. unverified claims never act as an identity');
  const http = require('http'); const crypto = require('crypto'); const jwt = require(path.join(__dirname, '..', 'node_modules', 'jsonwebtoken'));
  const upstreamCalls = [];
  const upstream = http.createServer((req, res) => {
    let body = ''; req.on('data', c => { body += c; });
    req.on('end', () => {
      let msg = {}; try { msg = JSON.parse(body || '{}'); } catch {}
      upstreamCalls.push(msg.method);
      const ok = (result, extra = {}) => { res.writeHead(200, { 'content-type': 'application/json', ...extra }); res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result })); };
      if (msg.method === 'initialize') return ok({ protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'fake', version: '1' } }, { 'mcp-session-id': 'sess-' + crypto.randomBytes(4).toString('hex') });
      if (msg.method === 'notifications/initialized') { res.writeHead(202); return res.end(); }
      if (msg.method === 'tools/call') return ok({ content: [{ type: 'text', text: 'ran' }] });
      ok({});
    });
  });
  await new Promise(r => upstream.listen(0, '127.0.0.1', r));
  const mcp = (await api('POST', '/api/mcp', { name: 'fake-up', url: `http://127.0.0.1:${upstream.address().port}/` })).json.id;
  const agent = (await api('POST', '/api/agents', { name: 'ops-agent' })).json;
  const agentVs = (await post({ name: 'agent-only-vs', require_obo: 0, require_agent_token: 1, features_enabled: ['policy'] })).json.id;
  await api('POST', `/api/virtual-servers/${agentVs}/agents`, { agent_id: agent.id });
  await api('POST', `/api/virtual-servers/${agentVs}/tools`, { mcp_server_id: mcp, tool_name: '*' });
  const addPolicy = (vs, name, conditions) => { const id = crypto.randomUUID(); db.prepare(`INSERT INTO policies (id, virtual_server_id, name, effect, priority, policy_json) VALUES (?,?,?,?,?,?)`).run(id, vs, name, 'permit', 10, JSON.stringify({ actions: [{ mcp_server_id: '*', tool: 'echo' }], conditions })); return id; };
  const dropPolicy = (id) => db.prepare('DELETE FROM policies WHERE id = ?').run(id);
  const forged = jwt.sign({ sub: 'root', groups: ['admins'], scp: ['bank:admin'] }, 'attacker-key');
  const callAs = (vs, token) => api('POST', `/api/proxy/${vs}`, { mcp_server_id: mcp, tool_name: 'echo', arguments: {} }, { Authorization: `Bearer ${token}`, 'X-Agent-Token': agent.token });
  const lastAudit = (vs) => JSON.parse(db.prepare(`SELECT data FROM event_log WHERE vs_id = ? AND log_type = 'tool_call' ORDER BY rowid DESC LIMIT 1`).get(vs)?.data || db.prepare(`SELECT data FROM event_log WHERE vs_id = ? ORDER BY rowid DESC LIMIT 1`).get(vs).data);
  const toolCallsSeen = () => upstreamCalls.filter(m => m === 'tools/call').length;

  for (const [label, conds] of [
    ['group', [{ type: 'group_contains', value: 'admins' }]],
    ['scope', [{ type: 'scope_contains', value: 'bank:admin' }]],
    ['subject', [{ type: 'sub_equals', value: 'root' }]],
  ]) {
    const pid = addPolicy(agentVs, `needs-${label}`, conds);
    const before = toolCallsSeen();
    const r = await callAs(agentVs, forged);
    check(`a forged token claiming ${label} "${label === 'group' ? 'admins' : label === 'scope' ? 'bank:admin' : 'root'}" does NOT satisfy a ${label} policy (403)`, r.status === 403, [r.status, r.text.slice(0, 160)]);
    check(`  ...and the tool is never called upstream`, toolCallsSeen() === before);
    const a = lastAudit(agentVs);
    check(`  ...and the audit entry does not record the attacker's claims`, a.decision === 'deny' && !a.user_sub && (a.user_groups || []).length === 0 && (a.user_scopes || []).length === 0, a);
    dropPolicy(pid);
  }
  const pidAgent = addPolicy(agentVs, 'agent-rule', [{ type: 'agent_is', value: 'ops-agent' }]);
  const before = toolCallsSeen();
  const okCall = await callAs(agentVs, forged);
  check('control: an agent-based policy still allows the call (the VS is not just blocked)', okCall.status === 200 && toolCallsSeen() === before + 1, [okCall.status, okCall.text.slice(0, 160)]);
  const noTok = await api('POST', `/api/proxy/${agentVs}`, { mcp_server_id: mcp, tool_name: 'echo', arguments: {} }, { 'X-Agent-Token': agent.token });
  check('control: with no user token at all the agent-only call also works', noTok.status === 200);
  dropPolicy(pidAgent);

  section('3d. a VS that wants OBO but has no IdP fails closed, not on unverified claims');
  // such a VS can no longer be saved, so simulate one left over from an older version
  const legacyId = crypto.randomUUID();
  db.prepare(`INSERT INTO virtual_servers (id, name, require_obo, require_agent_token, protocol, features_enabled) VALUES (?,?,?,?,?,?)`).run(legacyId, 'legacy-obo-no-idp', 1, 0, 'mcp', JSON.stringify(['policy']));
  db.prepare(`INSERT INTO virtual_server_tools (id, virtual_server_id, mcp_server_id, tool_name) VALUES (?,?,?,?)`).run(crypto.randomUUID(), legacyId, mcp, '*');
  addPolicy(legacyId, 'permit-all-ish', []);
  const before2 = toolCallsSeen();
  const lg = await callAs(legacyId, forged);
  check('call -> 401 no_idp_configured', lg.status === 401 && lg.json?.code === 'no_idp_configured', [lg.status, lg.text.slice(0, 200)]);
  check('the tool is not called upstream', toolCallsSeen() === before2);
  const lgAudit = JSON.parse(db.prepare(`SELECT data FROM event_log WHERE vs_id = ? ORDER BY rowid DESC LIMIT 1`).get(legacyId).data);
  check('the refusal is audited as a deny without the forged identity', lgAudit.decision === 'deny' && /No identity provider/.test(lgAudit.reason) && !lgAudit.user_sub, lgAudit);
  await new Promise(r => upstream.close(r));

  section('4. upgrade: existing anonymous virtual servers are grandfathered, once');
  // simulate a Warden from before this feature: drop the column, add rows of each kind, then boot the code against it
  const child = (code) => execFileSync(process.execPath, ['-e', code], { env: { ...process.env, SQLITE_PATH: DB_FILE }, encoding: 'utf8' }).trim();
  const legacy = ['gf-anon-mcp', 'gf-anon-both', 'gf-anon-a2a', 'gf-agent', 'gf-obo'];
  db.close();
  const { DatabaseSync } = require('node:sqlite');
  const raw = new DatabaseSync(DB_FILE);
  raw.exec('ALTER TABLE virtual_servers DROP COLUMN allow_anonymous');
  const ins = raw.prepare(`INSERT INTO virtual_servers (id, name, require_obo, require_agent_token, protocol, features_enabled) VALUES (?,?,?,?,?,?)`);
  ins.run('gf1', legacy[0], 0, 0, 'mcp', '[]'); ins.run('gf2', legacy[1], 0, 0, 'both', '[]'); ins.run('gf3', legacy[2], 0, 0, 'a2a', '[]');
  ins.run('gf4', legacy[3], 0, 1, 'mcp', '[]'); ins.run('gf5', legacy[4], 1, 0, 'mcp', '[]');
  raw.close();
  const out = child(`const db=require(${JSON.stringify(path.join(SRC, 'db', 'database.js'))});
    const r=db.prepare("SELECT name, allow_anonymous a FROM virtual_servers WHERE name LIKE 'gf-%' ORDER BY name").all();
    console.log(JSON.stringify(Object.fromEntries(r.map(x=>[x.name,x.a]))));`);
  const m = JSON.parse(out);
  check('anonymous mcp and "both" VSes are grandfathered (behaviour unchanged)', m['gf-anon-mcp'] === 1 && m['gf-anon-both'] === 1, m);
  check('a2a, agent-token and OBO VSes are not flagged', m['gf-anon-a2a'] === 0 && m['gf-agent'] === 0 && m['gf-obo'] === 0, m);
  // an admin later revokes the flag; the next boot must not re-approve it
  const raw2 = new DatabaseSync(DB_FILE); raw2.exec(`UPDATE virtual_servers SET allow_anonymous = 0 WHERE name = 'gf-anon-mcp'`); raw2.close();
  const out2 = child(`const db=require(${JSON.stringify(path.join(SRC, 'db', 'database.js'))});
    console.log(db.prepare("SELECT allow_anonymous a FROM virtual_servers WHERE name='gf-anon-mcp'").get().a);`);
  check('the migration runs only once: a later boot never re-approves a VS', out2 === '0', out2);

  section('5. the Warden UI');
  const html = await (await fetch(BASE + '/')).text();
  const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(x => x[1]);
  let syntaxOk = scripts.length > 0; for (const s of scripts) { try { new Function(s); } catch { syntaxOk = false; } }
  check('page scripts still parse', syntaxOk);
  check('the Edit dialog asks for confirmation before saving an anonymous virtual server', /wouldBeAnonymous/.test(html) && /allow_anonymous = 1/.test(html));
  check('the card shows an Anonymous badge', /⚠ Anonymous/.test(html));

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length) console.log('Failed:\n - ' + failures.join('\n - '));
  return failures.length;
}

main().then(n => finish(n), e => { console.error('\nTEST HARNESS ERROR:', e); finish(1); });
function finish(code) { setTimeout(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} process.exit(code ? 1 : 0); }, 300); }
