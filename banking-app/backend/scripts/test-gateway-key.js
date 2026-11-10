// End-to-end test of the brokered gateway key for the banking MCP endpoint. Boots a THROWAWAY Warden and the
// REAL banking backend (index.js, own temp DB), then enables, uses, rotates and rolls back the key.
//   node scripts/test-gateway-key.js

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { spawn } from 'child_process';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.join(here, '..');
const wardenDir = path.join(backendDir, '..', '..', 'mcp-virtual-server');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gateway-key-test-'));
const WARDEN_PORT = 3026, BACKEND_PORT = 3027;
Object.assign(process.env, { SQLITE_PATH: path.join(tmp, 'warden.db'), PORT: String(WARDEN_PORT), NODE_ENV: 'development', JWKS_URI: '', REDIS_URL: 'redis://127.0.0.1:1' });
delete process.env.WARDEN_SECRETS_KEY; process.env.WARDEN_ADMIN_TOKEN = ''; // the throwaway Warden is open; never send a real token to it
process.chdir(tmp);

const W = `http://127.0.0.1:${WARDEN_PORT}`, B = `http://127.0.0.1:${BACKEND_PORT}`;
const { enable, rollback, status, SECRET_NAME, ENV_KEY } = await import('./gateway-key.js');

let passed = 0; const failures = [];
function check(name, cond, detail) {
  if (cond) { passed++; console.log(`  ok   ${name}`); }
  else { failures.push(name); console.log(`  FAIL ${name}${detail !== undefined ? '  -> ' + (typeof detail === 'string' ? detail : JSON.stringify(detail)) : ''}`); }
}
const section = (t) => console.log(`\n== ${t}`);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const userJwt = `${b64({ alg: 'none' })}.${b64({ sub: 'test-user', email: 't@example.com' })}.sig`;

async function call(base, method, p, body, headers = {}) {
  const res = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text };
}
const warden = (m, p, b) => call(W, m, p, b);

// ── the real banking backend, started and stopped on demand ───────────────────────────────────────
let backend = null; const procs = new Set();
function startBackend(hash) {
  return new Promise(async (resolve, reject) => {
    const proc = spawn(process.execPath, ['src/index.js'], {
      cwd: backendDir, stdio: ['ignore', 'pipe', 'pipe'],
      // empty string (not unset) so dotenv cannot pull a real value from the repo's .env.local
      env: { ...process.env, PORT: String(BACKEND_PORT), DB_PATH: path.join(tmp, 'banking.db'), NODE_ENV: 'development', MCP_GATEWAY_KEY_SHA256: hash ?? '' },
    });
    procs.add(proc); let out = '';
    proc.stdout.on('data', d => { out += d; }); proc.stderr.on('data', d => { out += d; });
    proc.exited = new Promise(r => proc.on('exit', code => r(code))); proc.output = () => out;
    for (let i = 0; i < 80; i++) { try { if ((await fetch(B + '/api/health')).ok) return resolve(proc); } catch {} await sleep(150); }
    reject(new Error('backend did not start: ' + out.slice(-400)));
  });
}
async function stopBackend() { if (!backend) return; backend.kill(); await backend.exited; procs.delete(backend); backend = null; await sleep(150); }
const readHash = (file) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '').split(/\r?\n/).find(l => l.startsWith(`${ENV_KEY}=`))?.slice(ENV_KEY.length + 1) || '';

// A raw MCP request straight to the banking backend, carrying a forged user token (what an attacker would send).
const mcpInit = (headers = {}) => call(B, 'POST', '/mcp', { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'attacker', version: '1' } } },
  { Authorization: `Bearer ${userJwt}`, Accept: 'application/json, text/event-stream', ...headers });

async function main() {
  const require = createRequire(import.meta.url);
  require(path.join(wardenDir, 'src', 'app.js'));
  for (let i = 0; i < 80; i++) { try { if ((await fetch(W + '/api/health')).ok) break; } catch {} await sleep(100); }
  const wdb = require(path.join(wardenDir, 'src', 'db', 'database.js'));

  // ── Warden fixtures: the banking MCP server (no auth yet), one virtual server, an allowlisted agent ──
  const mkAgent = async (name) => { const r = await warden('POST', '/api/agents', { name }); return { id: r.json.id, token: r.json.token, name }; };
  const bank = await mkAgent('banking-chatbot-agent'), rogue = await mkAgent('rogue-agent'), noPolicy = await mkAgent('allowlisted-but-no-policy');
  const vsId = (await warden('POST', '/api/virtual-servers', { name: 'banking-vs', require_obo: 0, features_enabled: ['policy'], require_agent_token: 1 })).json.id;
  await warden('POST', `/api/virtual-servers/${vsId}/agents`, { agent_id: bank.id });
  const mcpId = (await warden('POST', '/api/mcp', { name: 'bank-mcp', url: `${B}/mcp`, description: 'banking MCP', auth_type: 'none' })).json.id;
  await warden('POST', `/api/virtual-servers/${vsId}/tools`, { mcp_server_id: mcpId, tool_name: '*' });
  await warden('POST', '/api/token-policies', { virtual_server_id: vsId, name: 'allow-all', effect: 'permit', policy_json: { actions: [{ mcp_server_id: '*', tool: '*' }], conditions: [] } });
  const envFile = path.join(tmp, '.env.local'), backupFile = path.join(tmp, 'backup.json');
  const opts = { wardenUrl: W, vsId, mcpId, envFile, backupFile };
  const logs = []; const log = (l) => logs.push(l);
  const viaWarden = (agent) => call(W, 'POST', `/api/proxy/${vsId}`, { mcp_server_id: mcpId, tool_name: 'get_accounts', arguments: {} }, { Authorization: `Bearer ${userJwt}`, 'X-Agent-Token': agent.token });
  const toolOk = (r) => r.status === 200 && Array.isArray(r.json?.result?.content) && !r.json.result.isError;

  // ═══ 1. before: the backend is open ═══════════════════════════════════════
  section('1. before: /mcp trusts any caller');
  backend = await startBackend(null);
  check('startup log says the gateway key is not required', /not required/.test(backend.output()), backend.output().slice(-300));
  check('status reports OPEN', (await (async () => { const l = []; await status({ ...opts, log: x => l.push(x) }); return l.join('\n'); })()).includes('OPEN'));
  check('a forged token sent STRAIGHT to the backend is accepted (the hole this closes)', (await mcpInit()).status === 200);
  check('the banking tool works through Warden as the allowlisted agent', toolOk(await viaWarden(bank)));

  // ═══ 2. enable ════════════════════════════════════════════════════════════
  section('2. enable');
  const en = await enable({ ...opts, log });
  check('enable succeeds and covers the virtual server\'s allowlisted agent', en.callers.length === 1 && en.callers[0] === 'banking-chatbot-agent' && en.rotated === false, en);
  const mcp = (await warden('GET', `/api/mcp/${mcpId}`)).json;
  check('Warden now sends X-Gateway-Key = vault://banking-mcp-gateway-key (a reference, not a value)', mcp.auth_type === 'apikey' && mcp.auth_config.header === 'X-Gateway-Key' && mcp.auth_config.key === `vault://${SECRET_NAME}`, mcp.auth_config);
  const h1 = readHash(envFile);
  check('the env file gets only a SHA-256 hash', /^[0-9a-f]{64}$/.test(h1) && !fs.readFileSync(envFile, 'utf8').includes('bgk_'));
  check('the original auth settings were saved for rollback', JSON.parse(fs.readFileSync(backupFile, 'utf8')).auth_type === 'none');
  check('safe ordering: Warden injects the key while the old backend is still open, so nothing breaks', toolOk(await viaWarden(bank)));

  // fetch the key once, as a test-only reader, so the backend's behaviour can be checked with the real value
  const reader = await mkAgent('test-key-reader');
  const secretId = (await warden('GET', '/api/vault/secrets')).json.find(s => s.name === SECRET_NAME).id;
  await warden('POST', '/api/vault/policies', { name: 'test reader', effect: 'permit', caller_type: 'agent', caller_value: reader.id, secret_id: secretId, operations: ['reveal'] });
  const KEY1 = (await call(W, 'POST', '/api/vault/checkout', { secret: SECRET_NAME }, { 'X-Agent-Token': reader.token })).json.value;
  check('the stored key hashes to the value saved for the backend', crypto.createHash('sha256').update(KEY1).digest('hex') === h1);

  // ═══ 3. enforcing ═════════════════════════════════════════════════════════
  section('3. restart: the backend now enforces the key');
  await stopBackend(); backend = await startBackend(h1);
  check('startup log says the key is required', /REQUIRED/.test(backend.output()));
  check('status reports ENFORCING', (await (async () => { const l = []; await status({ ...opts, log: x => l.push(x) }); return l.join('\n'); })()).includes('ENFORCING'));
  check('forged token, no key -> 401', (await mcpInit()).status === 401);
  check('forged token, wrong key -> 401', (await mcpInit({ 'X-Gateway-Key': 'bgk_wrong' })).status === 401);
  check('empty key header -> 401', (await mcpInit({ 'X-Gateway-Key': '' })).status === 401);
  check('GET and DELETE /mcp are gated too', (await call(B, 'GET', '/mcp')).status === 401 && (await call(B, 'DELETE', '/mcp')).status === 401);
  check('the correct key reaches the MCP server directly', (await mcpInit({ 'X-Gateway-Key': KEY1 })).status === 200);
  check('the rest of the backend is unaffected (/api/health)', (await call(B, 'GET', '/api/health')).status === 200);
  const ok = await viaWarden(bank);
  check('through Warden (brokered) the banking tool still works', toolOk(ok), ok.text.slice(0, 200));
  check('a caller not on the VS allowlist is refused by Warden', (await viaWarden(rogue)).status === 403);
  await warden('POST', `/api/virtual-servers/${vsId}/agents`, { agent_id: noPolicy.id });
  const np = await viaWarden(noPolicy);
  check('an allowlisted agent with no vault policy cannot use the key (403, backend never reached)', np.status === 403, np.text.slice(0, 200));
  check('the agent never sees the key in the tool reply', !ok.text.includes(KEY1));

  // ═══ 4. rotation ══════════════════════════════════════════════════════════
  section('4. rotate');
  const en2 = await enable({ ...opts, log });
  const h2 = readHash(envFile);
  check('enable again rotates the same secret and changes the hash', en2.rotated === true && h2 !== h1 && /^[0-9a-f]{64}$/.test(h2));
  check('the backup of the ORIGINAL auth is not overwritten by the rotation', JSON.parse(fs.readFileSync(backupFile, 'utf8')).auth_type === 'none');
  const stale = await viaWarden(bank);
  check('until the backend restarts, the mismatched key fails CLOSED (no silent bypass)', !toolOk(stale), stale.status);
  await stopBackend(); backend = await startBackend(h2);
  check('after the restart the new key works through Warden', toolOk(await viaWarden(bank)));
  check('the previous key is now rejected by the backend', (await mcpInit({ 'X-Gateway-Key': KEY1 })).status === 401);

  // ═══ 5. fail-safe configuration ═══════════════════════════════════════════
  section('5. a broken setting never silently opens the endpoint');
  await stopBackend();
  const bad = await new Promise(resolve => {
    const p = spawn(process.execPath, ['src/index.js'], { cwd: backendDir, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PORT: '3029', DB_PATH: path.join(tmp, 'bad.db'), NODE_ENV: 'development', MCP_GATEWAY_KEY_SHA256: 'not-a-hash' } });
    let out = ''; p.stdout.on('data', d => { out += d; }); p.stderr.on('data', d => { out += d; });
    const t = setTimeout(() => { p.kill(); resolve({ code: 'timeout', out }); }, 8000);
    p.on('exit', code => { clearTimeout(t); resolve({ code, out }); });
  });
  check('a malformed MCP_GATEWAY_KEY_SHA256 makes the backend refuse to start', bad.code === 1 && /64-character/.test(bad.out), bad);

  // ═══ 6. no leaks ══════════════════════════════════════════════════════════
  section('6. the key never leaks');
  const dump = JSON.stringify([wdb.prepare('SELECT summary, data FROM event_log').all(), wdb.prepare('SELECT * FROM audit_log').all(), wdb.prepare('SELECT * FROM approval_tickets').all(), wdb.prepare('SELECT * FROM vault_leases').all(), wdb.prepare('SELECT id,name,auth_config FROM mcp_servers').all()]);
  check('not in Warden logs, tickets, leases or the MCP registry', !dump.includes(KEY1));
  check('not in what the enable/rotate/status commands printed', !logs.join('\n').includes('bgk_'));
  check('not in the env file', !fs.readFileSync(envFile, 'utf8').includes('bgk_'));

  // ═══ 7. rollback ══════════════════════════════════════════════════════════
  section('7. rollback');
  const rbLogs = []; await rollback({ ...opts, log: l => rbLogs.push(l) });
  check('the hash is removed from the env file', readHash(envFile) === '');
  const mcpBack = (await warden('GET', `/api/mcp/${mcpId}`)).json;
  check('the MCP server auth is restored exactly', mcpBack.auth_type === 'none' && Object.keys(mcpBack.auth_config).length === 0, mcpBack);
  const left = { secret: (await warden('GET', '/api/vault/secrets')).json.some(s => s.name === SECRET_NAME), pol: (await warden('GET', '/api/vault/policies')).json.filter(p => p.name.startsWith('banking-mcp gateway key:')).length };
  check('vault secret and broker policies are removed (the unrelated test-reader policy is untouched)', left.secret === false && left.pol === 0, left);
  check('the backup file is removed', !fs.existsSync(backupFile));
  backend = await startBackend(readHash(envFile) || null);
  check('after a restart the backend is open again and the banking tool still works', toolOk(await viaWarden(bank)) && /not required/.test(backend.output()));

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length) console.log('Failed:\n - ' + failures.join('\n - '));
  return failures.length;
}

function finish(code) {
  for (const p of procs) { try { p.kill(); } catch {} }
  setTimeout(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} process.exit(code ? 1 : 0); }, 500);
}
main().then(n => finish(n), e => { console.error('\nTEST HARNESS ERROR:', e); finish(1); });
