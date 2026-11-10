'use strict';

/**
 * Configures Warden for the A2A demo. Idempotent — safe to re-run.
 *
 *   node setup-warden.js            (WARDEN_URL=http://localhost:3003, CARD_AGENT_URL=http://localhost:4010)
 *
 * Creates: an A2A virtual server, the registered credit-card-agent, a "banking-agents" group
 * (auto-membership by metadata rule), a caller identity for the SecureBank agent, access policies,
 * and an interceptor rule that masks card numbers in responses.
 * Prints the values to put in agent/.env.
 */

const fs = require('fs');
const path = require('path');
const W = (process.env.WARDEN_URL || 'http://localhost:3003').replace(/\/$/, '');
const CARD_URL = (process.env.CARD_AGENT_URL || 'http://localhost:4010').replace(/\/$/, '');

const VS_NAME = 'securebank-a2a';
const TARGET_NAME = 'credit-card-agent';
const GROUP_NAME = 'banking-agents';
const CALLER_NAME = 'securebank-a2a-agent';

// Warden's admin API requires WARDEN_ADMIN_TOKEN when it is set there. Taken from the environment, else Warden's .env.
function adminHeaders() {
  let t = process.env.WARDEN_ADMIN_TOKEN; // set but empty = "no token" (tests use this)
  if (t === undefined) {
    try { const m = /^WARDEN_ADMIN_TOKEN=(.+)$/m.exec(fs.readFileSync(path.join(__dirname, '..', 'mcp-virtual-server', '.env'), 'utf8')); if (m) t = m[1].trim(); } catch { /* no .env: Warden is probably open */ }
  }
  return t ? { 'X-Admin-Token': t } : {};
}

async function api(method, path, body) {
  const r = await fetch(W + '/api' + path, { method, headers: { 'Content-Type': 'application/json', ...adminHeaders() }, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  if (!r.ok) throw Object.assign(new Error(`${method} ${path} -> ${r.status} ${data?.error || text}`), { status: r.status });
  return data;
}
const log = (m) => console.log('  ' + m);

(async () => {
  console.log(`\nConfiguring Warden at ${W}\n`);
  try { await fetch(W + '/api/health'); } catch { console.error(`Cannot reach Warden at ${W}. Start it first (cd mcp-virtual-server && npm start).`); process.exit(1); }

  // 1. A2A virtual server
  let vs = (await api('GET', '/virtual-servers')).find(v => v.name === VS_NAME);
  if (!vs) { vs = { id: (await api('POST', '/virtual-servers', { name: VS_NAME, description: 'SecureBank A2A demo', protocol: 'a2a', require_obo: false })).id }; log(`created virtual server "${VS_NAME}"`); }
  else { await api('PUT', `/virtual-servers/${vs.id}`, { ...vs, protocol: 'a2a', require_obo: false, okta_client_secret: '***' }); log(`virtual server "${VS_NAME}" exists (protocol set to a2a)`); }
  const vsId = vs.id;

  // 2. Register the credit card agent by its Agent Card URL
  let target = (await api('GET', '/a2a-agents')).find(a => a.name === TARGET_NAME);
  if (!target) {
    try { target = { id: (await api('POST', '/a2a-agents', { name: TARGET_NAME, card_url: `${CARD_URL}/.well-known/agent-card.json` })).id }; log(`registered "${TARGET_NAME}" from ${CARD_URL}`); }
    catch (e) { console.error(`\nCould not register the card agent: ${e.message}\nIs it running?  (cd credit-card-agent && node server.js)`); process.exit(1); }
  } else { await api('POST', `/a2a-agents/${target.id}/refresh`).catch(() => {}); log(`"${TARGET_NAME}" already registered (card refreshed)`); }
  try { await api('POST', `/virtual-servers/${vsId}/a2a-agents`, { a2a_agent_id: target.id }); log('assigned to the virtual server'); }
  catch (e) { if (e.status !== 409) throw e; log('already assigned to the virtual server'); }

  // 3. Group with an Okta-style rule: agents whose metadata team == banking join automatically
  let group = (await api('GET', '/agent-groups')).find(g => g.name === GROUP_NAME);
  if (!group) { group = { id: (await api('POST', '/agent-groups', { name: GROUP_NAME, description: 'Agents that may use banking A2A services', owner: 'Banking Platform', color_tag: '#10b981' })).id }; log(`created group "${GROUP_NAME}"`); }
  const rules = await api('GET', `/agent-groups/${group.id}/rules`);
  if (!rules.length) {
    await api('POST', `/agent-groups/${group.id}/rules`, { name: 'team is banking', match_mode: 'all', conditions: [{ field: 'team', operator: 'eq', value: 'banking' }] });
    log('added group rule: metadata team eq "banking"');
  }

  // 4. Caller identity for the SecureBank agent (token shown once; re-running rotates it)
  let caller = (await api('GET', '/agents')).find(a => a.name === CALLER_NAME);
  let token = null;
  if (!caller) {
    const created = await api('POST', '/agents', { name: CALLER_NAME, description: 'SecureBank assistant calling other agents over A2A', metadata: { team: 'banking', owner: 'securebank-assistant' } });
    token = created.token; caller = { id: created.id }; log(`created caller agent "${CALLER_NAME}"`);
  } else {
    token = (await api('POST', `/agents/${caller.id}/rotate-token`)).token;
    await api('PUT', `/agents/${caller.id}`, { metadata: { team: 'banking', owner: 'securebank-assistant' } });
    log(`caller agent "${CALLER_NAME}" exists (token rotated, metadata ensured)`);
  }
  // Group membership is normally evaluated in the background after an agent is created. The policy below
  // is group-based, so force a synchronous sync and confirm membership before moving on.
  await api('POST', `/agent-groups/${group.id}/sync`);
  const members = (await api('GET', `/agent-groups/${group.id}`)).members || [];
  if (!members.some(m => m.id === caller.id)) {
    console.error(`\nSetup problem: "${CALLER_NAME}" did not join group "${GROUP_NAME}" (rule: metadata team eq banking).`);
    process.exit(1);
  }
  log(`"${CALLER_NAME}" is a member of "${GROUP_NAME}" (auto, via rule)`);

  // 5. Policies (deny-by-default: nothing works without a permit)
  const pols = await api('GET', `/a2a-policies?virtual_server_id=${vsId}`);
  if (!pols.find(p => p.name === 'banking-agents may read card info')) {
    await api('POST', '/a2a-policies', { virtual_server_id: vsId, name: 'banking-agents may read card info', effect: 'permit', priority: 1,
      caller_type: 'group', caller_value: group.id, target_type: 'agent', target_value: target.id, skills: ['card-details', 'card-transactions'] });
    log('policy: PERMIT banking-agents -> credit-card-agent [card-details, card-transactions]');
  }
  if (!pols.find(p => p.name === 'nobody may freeze cards via A2A')) {
    await api('POST', '/a2a-policies', { virtual_server_id: vsId, name: 'nobody may freeze cards via A2A', effect: 'forbid', priority: 10,
      caller_type: 'any', target_type: 'agent', target_value: target.id, skills: ['card-freeze'] });
    log('policy: FORBID any -> credit-card-agent [card-freeze]');
  }

  // 6. Interceptor rules on this virtual server
  const irules = await api('GET', `/interceptors/${vsId}/rules`);
  if (!irules.find(r => r.name === 'mask card numbers & PII')) {
    await api('POST', `/interceptors/${vsId}/rules`, { name: 'mask card numbers & PII', scanner: '*', category: 'pii', score_min: 0.5, action: 'mask', priority: 5 });
    log('interceptor: MASK pii (card numbers) in A2A traffic');
  }
  if (!irules.find(r => r.name === 'block prompt injection')) {
    await api('POST', `/interceptors/${vsId}/rules`, { name: 'block prompt injection', scanner: '*', category: 'prompt_injection', score_min: 0.5, action: 'block', priority: 9 });
    log('interceptor: BLOCK prompt injection');
  }

  // 7. Wire the SecureBank chat UI. The browser holds NO Warden credentials: it calls the banking backend,
  // which acts as this A2A agent. The agent token is that agent's identity, so it is saved server-side in the
  // backend's git-ignored .env.local (merged so other keys are preserved). The shared Warden API key is read
  // from the Warden Credential Vault, so it is never written anywhere.
  const beDir = path.join(__dirname, '..', 'banking-app', 'backend');
  let feNote = '';
  if (!process.env.SKIP_BACKEND_ENV && fs.existsSync(beDir)) {
    const vals = { WARDEN_A2A_VS_ID: vsId, WARDEN_A2A_TARGET_ID: target.id, WARDEN_A2A_AGENT_TOKEN: token, ...(W !== 'http://localhost:3003' ? { WARDEN_URL: W } : {}) };
    const file = path.join(beDir, '.env.local');
    const keep = fs.existsSync(file)
      ? fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(l => l && !Object.keys(vals).some(k => l.startsWith(k + '=')))
      : [];
    fs.writeFileSync(file, [...keep, ...Object.entries(vals).map(([k, v]) => `${k}=${v}`)].join('\n') + '\n');
    feNote = `
SecureBank chat wired: ids and this agent's token saved to banking-app/backend/.env.local (git-ignored).
  If the virtual server uses Warden API keys, add a Vault policy letting this agent "reveal" the API-key
  secret, then restart the banking backend. The frontend needs no changes or env vars.`;
  }

  console.log(`
Done. Add these to agent/.env:

  WARDEN_URL=${W}
  WARDEN_A2A_VS_ID=${vsId}
  WARDEN_A2A_TARGET_ID=${target.id}
  WARDEN_A2A_AGENT_TOKEN=${token}

Warden gateway endpoint : ${W}/a2a/${vsId}/${target.id}
Gateway Agent Card      : ${W}/a2a/${vsId}/${target.id}/.well-known/agent-card.json
Then try:  python agent/test_a2a.py   (no LLM needed)   or   python agent/agent.py
${feNote}
`);
})().catch(e => { console.error('\nSetup failed:', e.message); process.exit(1); });
