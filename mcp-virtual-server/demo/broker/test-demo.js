'use strict';

// End-to-end test of the broker demo against a THROWAWAY Warden (never your real one).
//   node demo/broker/test-demo.js

const fs = require('fs');
const os = require('os');
const path = require('path');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'broker-demo-test-'));
Object.assign(process.env, {
  SQLITE_PATH: path.join(tmp, 'warden.db'), PORT: '3022', NODE_ENV: 'development', JWKS_URI: '', REDIS_URL: 'redis://127.0.0.1:1',
  WARDEN_URL: 'http://127.0.0.1:3022', WARDEN_ADMIN_TOKEN: '', DEMO_PORT: '3052', DEMO_STATE_FILE: path.join(tmp, 'state.json'),
});
delete process.env.WARDEN_SECRETS_KEY;
const DEMO = 'http://127.0.0.1:3052';

let passed = 0; const failures = [];
function check(name, cond, detail) {
  if (cond) { passed++; console.log(`  ok   ${name}`); }
  else { failures.push(name); console.log(`  FAIL ${name}${detail !== undefined ? '  -> ' + (typeof detail === 'string' ? detail : JSON.stringify(detail)) : ''}`); }
}
const section = (t) => console.log(`\n== ${t}`);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// every body the demo server ever sends to a browser, swept for secrets at the end
const wire = [];
async function demo(method, p, body) {
  const res = await fetch(DEMO + p, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text(); wire.push(text);
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text };
}
const post = (p, b = {}) => demo('POST', p, b);
const get = (p) => demo('GET', p);

async function main() {
  const L = require('./lib');
  const { setup } = require('./setup');
  const { teardown } = require('./teardown');
  const { start } = require('./server');
  const secretsSeen = new Set();
  const harvest = () => { const s = L.readState(); if (s) [s.paymentsKey, s.hookSecret, s.vaultKey, s.agents.report.token, s.agents.rogue.token].forEach(v => secretsSeen.add(v)); };

  require(path.join(__dirname, '..', '..', 'src', 'app.js'));
  for (let i = 0; i < 80; i++) { try { if ((await fetch(L.WARDEN_URL + '/api/health')).ok) break; } catch {} await sleep(100); }
  const wardenGet = async (p) => (await L.warden('GET', p)).json;
  const demoObjects = async () => {
    const [a, s, v, m, vp] = await Promise.all(['/api/agents', '/api/vault/secrets', '/api/virtual-servers', '/api/mcp', '/api/vault/policies'].map(wardenGet));
    const demoish = (n) => String(n).startsWith('demo');
    return { agents: a.filter(x => demoish(x.name)).length, secrets: s.filter(x => demoish(x.name)).length, vss: v.filter(x => demoish(x.name)).length, mcps: m.filter(x => demoish(x.name)).length, policies: vp.filter(x => demoish(x.name)).length };
  };

  section('1. before setup');
  const server = await start(Number(process.env.DEMO_PORT));
  const s0 = await get('/api/state');
  check('server starts without state and says setup is needed', s0.json.setupDone === false);
  check('actions refuse politely before setup (409)', (await post('/api/run', { who: 'report' })).status === 409);

  section('2. setup (and idempotency)');
  const state1 = await setup({ log: () => {} }); harvest();
  const o1 = await demoObjects();
  check('creates 2 agents, 2 secrets, 1 virtual server, 1 MCP server, 1 vault policy', o1.agents === 2 && o1.secrets === 2 && o1.vss === 1 && o1.mcps === 1 && o1.policies === 1, o1);
  const mcp = (await wardenGet('/api/mcp')).find(m => m.name === L.NAMES.mcp);
  check('the upstream credential is registered as a vault reference, not plaintext', mcp.auth_config.key === `vault://${L.NAMES.keySecret}` && !JSON.stringify(mcp).includes(state1.paymentsKey));
  const state2 = await setup({ log: () => {} }); harvest();
  const o2 = await demoObjects();
  check('setup is idempotent (no duplicates on re-run)', JSON.stringify(o1) === JSON.stringify(o2), o2);
  check('re-running setup refreshes agent tokens and keeps the same agents', state2.agents.report.id === state1.agents.report.id && state2.agents.report.token !== state1.agents.report.token);
  check('the running server picks up the new state without a restart', (await get('/api/state')).json.setupDone === true);

  section('3. page and state');
  const page = await fetch(DEMO + '/'); const html = await page.text();
  check('demo page is served', page.status === 200 && /Broker mode/.test(html));
  const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  let syntaxOk = scripts.length > 0; for (const s of scripts) { try { new Function(s); } catch { syntaxOk = false; } }
  check('page script parses', syntaxOk);
  const st = (await get('/api/state')).json;
  check('state: in sync, policy and secrets active, Warden reachable', st.setupDone && st.wardenReachable && st.vault.inSync && st.vault.policyActive && st.vault.hookSecretActive && st.vault.keySecretVersion >= 1, st);
  check('state shows only masked key values', !JSON.stringify(st).includes(state2.paymentsKey) && /…/.test(st.upstream.acceptsMasked));

  section('4. the broker scenes');
  const r1 = (await post('/api/run', { who: 'report' })).json;
  check('report-agent: allowed', r1.allowed === true && r1.httpStatus === 200, r1);
  check('upstream authenticated with the real key and got the real webhook secret', r1.upstreamSaw.keyValid === true && r1.upstreamSaw.webhookPlaceholderReplaced === true);
  check('the upstream echoed the secrets, but the agent only sees [REDACTED:…]', /REDACTED:vault:\/\/demo-payments-api-key/.test(r1.reply) && /REDACTED:vault:\/\/demo-webhook-secret/.test(r1.reply) && ![state2.paymentsKey, state2.hookSecret].some(s => r1.reply.includes(s)), r1.reply);
  const rv = (await post('/api/reveal-attempt')).json;
  check('report-agent cannot reveal the secret (broker is not reveal)', rv.allowed === false && rv.httpStatus === 403, rv);
  const rg = (await post('/api/run', { who: 'rogue' })).json;
  check('rogue-agent: denied, upstream never contacted', rg.allowed === false && rg.httpStatus === 403 && rg.upstreamSaw === null, rg);
  const an = (await post('/api/run', { who: 'anonymous' })).json;
  check('no identity: denied, upstream never contacted', an.allowed === false && an.httpStatus === 403 && an.upstreamSaw === null, an);
  check('bad "who" -> 400', (await post('/api/run', { who: 'admin' })).status === 400);

  section('5. rotation: provider rotates, then admin updates the vault');
  await post('/api/provider-rotate'); harvest();
  const stOut = (await get('/api/state')).json;
  check('state shows the vault is now out of sync', stOut.vault.inSync === false);
  const stale = (await post('/api/run', { who: 'report' })).json;
  check('stale key: the upstream rejects it', stale.allowed === false && stale.upstreamRejected === true && stale.upstreamSaw.keyValid === false, stale);
  const sy = (await post('/api/vault-sync')).json; harvest();
  check('vault-sync rotates the secret (one version higher than before)', sy.ok && sy.version === stOut.vault.keySecretVersion + 1, [sy, stOut.vault.keySecretVersion]);
  const fresh = (await post('/api/run', { who: 'report' })).json;
  check('after syncing, the identical request succeeds', fresh.allowed === true && fresh.upstreamSaw.keyValid === true, fresh);
  check('the new key is redacted from the reply too', ![...secretsSeen].some(s => fresh.reply.includes(s)));

  section('6. kill switches');
  await post('/api/toggle-policy', { active: false });
  const noPol = (await post('/api/run', { who: 'report' })).json;
  check('policy disabled -> the very next call is denied', noPol.allowed === false && noPol.httpStatus === 403 && noPol.upstreamSaw === null, noPol);
  await post('/api/toggle-policy', { active: true });
  check('policy re-enabled -> allowed again', (await post('/api/run', { who: 'report' })).json.allowed === true);
  await post('/api/toggle-secret', { active: false });
  const noSec = (await post('/api/run', { who: 'report' })).json;
  check('secret disabled -> fails closed, upstream not called', noSec.allowed === false && noSec.upstreamSaw === null, noSec);
  await post('/api/toggle-secret', { active: true });
  check('secret re-enabled -> allowed again', (await post('/api/run', { who: 'report' })).json.allowed === true);

  section('7. reset, audit, leaks');
  await post('/api/provider-rotate'); harvest();
  await post('/api/toggle-policy', { active: false });
  await post('/api/reset'); harvest();
  const stR = (await get('/api/state')).json;
  check('reset restores policy, secrets and sync', stR.vault.policyActive && stR.vault.hookSecretActive && stR.vault.inSync);
  check('works after reset', (await post('/api/run', { who: 'report' })).json.allowed === true);
  const audit = (await get('/api/audit')).json;
  check('audit trail has both allows and denies for demo secrets', audit.length > 0 && audit.some(e => e.decision === 'allow') && audit.some(e => e.decision === 'deny'), audit.length);
  harvest();
  const sweep = wire.join('\n');
  const leaked = [...secretsSeen].filter(s => s && sweep.includes(s));
  check('across every response the browser could see, no secret value or agent token ever appears', leaked.length === 0, `${leaked.length} leaked`);

  section('8. teardown');
  await teardown({ log: () => {} });
  const o3 = await demoObjects();
  check('teardown removes every demo object', Object.values(o3).every(n => n === 0), o3);
  check('state file removed and the server reports setup needed again', !fs.existsSync(process.env.DEMO_STATE_FILE) && (await get('/api/state')).json.setupDone === false);
  check('teardown is safe to run twice', (await teardown({ log: () => {} })).length === 0);

  await new Promise(r => server.close(r));
  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length) console.log('Failed:\n - ' + failures.join('\n - '));
  return failures.length;
}

main().then(n => finish(n), e => { console.error('\nTEST HARNESS ERROR:', e); finish(1); });
function finish(code) { setTimeout(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} process.exit(code ? 1 : 0); }, 300); }
