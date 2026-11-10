// Turns the brokered gateway key for the banking MCP endpoint on or off.
//
//   node scripts/gateway-key.js status
//   node scripts/gateway-key.js enable  [--agent NAME]... [--vs ID] [--mcp ID]
//   node scripts/gateway-key.js rollback
//
// enable : generates a random key, stores it ONLY in the Warden Credential Vault, points Warden's `bank-mcp`
//          server at it (X-Gateway-Key = vault://banking-mcp-gateway-key), lets the virtual server's agents
//          BROKER it, and saves the key's SHA-256 (never the key) to .env.local as MCP_GATEWAY_KEY_SHA256.
//          Nobody, including you, ever sees the key. Warden-side changes are made first, the backend setting
//          last, and the backend only enforces after a restart, so it can never be locked out of Warden.
// Re-running `enable` rotates the key. `rollback` restores the previous behaviour.

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.join(here, '..');

export const SECRET_NAME = 'banking-mcp-gateway-key';
export const HEADER = 'X-Gateway-Key';
export const ENV_KEY = 'MCP_GATEWAY_KEY_SHA256';
const POLICY_PREFIX = 'banking-mcp gateway key:';

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// Warden's admin API requires WARDEN_ADMIN_TOKEN when it is set there. Taken from the environment, else Warden's .env.
function adminHeaders() {
  let t = process.env.WARDEN_ADMIN_TOKEN; // set but empty = "no token" (tests use this)
  if (t === undefined) {
    try { const m = /^WARDEN_ADMIN_TOKEN=(.+)$/m.exec(fs.readFileSync(path.join(backendDir, '..', '..', 'mcp-virtual-server', '.env'), 'utf8')); if (m) t = m[1].trim(); } catch { /* no .env: Warden is probably open */ }
  }
  return t ? { 'X-Admin-Token': t } : {};
}

function makeWarden(baseUrl) {
  return async (method, p, body) => {
    const res = await fetch(baseUrl.replace(/\/$/, '') + p, { method, headers: { 'Content-Type': 'application/json', ...adminHeaders() }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch { /* non-JSON */ }
    return { status: res.status, json, text };
  };
}
const must = (r, what) => {
  if (r.status >= 400) throw new Error(`${what} failed (HTTP ${r.status}): ${r.text.slice(0, 160)}`);
  return r.json;
};

// Sets (or, with null, removes) KEY=value lines, preserving every other line.
function mergeEnv(file, values) {
  const lines = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(l => l !== '') : [];
  const kept = lines.filter(l => !Object.keys(values).some(k => l.startsWith(`${k}=`)));
  for (const [k, v] of Object.entries(values)) if (v !== null) kept.push(`${k}=${v}`);
  fs.writeFileSync(file, kept.length ? kept.join('\n') + '\n' : '', { mode: 0o600 });
}

async function context({ wardenUrl, vsId, mcpId }) {
  const w = makeWarden(wardenUrl);
  const meta = await w('GET', '/api/vault/meta').catch(e => ({ status: 0, text: e.message }));
  if (meta.status !== 200) throw new Error(`Cannot use the Credential Vault at ${wardenUrl} (HTTP ${meta.status}). Is Warden running with the vault?`);
  const mcp = must(await w('GET', `/api/mcp/${mcpId}`), 'read MCP server');
  const vs = must(await w('GET', `/api/virtual-servers/${vsId}`), 'read virtual server');
  if (!(vs.tools || []).some(t => t.mcp_server_id === mcpId)) throw new Error(`Virtual server "${vs.name}" does not use MCP server "${mcp.name}"`);
  return { w, mcp, vs };
}

export async function enable({ wardenUrl, vsId, mcpId, agentNames = [], envFile, backupFile, log = console.log }) {
  const { w, mcp, vs } = await context({ wardenUrl, vsId, mcpId });

  const callerNames = agentNames.length ? agentNames : (vs.agents || []).map(a => a.name);
  if (!callerNames.length) throw new Error(`Virtual server "${vs.name}" has no agent allowlist. Pass --agent NAME for each agent that should be able to use the gateway key.`);
  const agents = must(await w('GET', '/api/agents'), 'list agents');
  const callers = callerNames.map(n => agents.find(a => a.name === n) || (() => { throw new Error(`Unknown agent "${n}"`); })());

  // Keep the original auth settings once, so rollback can restore them exactly.
  const alreadyOurs = mcp.auth_type === 'apikey' && mcp.auth_config?.key === `vault://${SECRET_NAME}`;
  if (!alreadyOurs && !fs.existsSync(backupFile)) {
    fs.writeFileSync(backupFile, JSON.stringify({ auth_type: mcp.auth_type, auth_config: mcp.auth_config || {}, savedAt: new Date().toISOString() }, null, 2), { mode: 0o600 });
  }

  const key = `bgk_${crypto.randomBytes(24).toString('hex')}`; // lives only in memory and the vault
  const secrets = must(await w('GET', '/api/vault/secrets'), 'list secrets');
  const existing = secrets.find(s => s.name === SECRET_NAME);
  let secretId;
  if (existing) {
    must(await w('POST', `/api/vault/secrets/${existing.id}/rotate`, { value: key }), 'rotate secret');
    if (!existing.is_active) await w('PUT', `/api/vault/secrets/${existing.id}`, { is_active: true });
    secretId = existing.id;
  } else {
    secretId = must(await w('POST', '/api/vault/secrets', {
      name: SECRET_NAME, type: 'api_key', value: key,
      description: 'Gateway key the banking MCP endpoint requires. Brokered by Warden; agents never hold it.',
    }), 'create secret').id;
  }

  const policies = must(await w('GET', '/api/vault/policies'), 'list vault policies');
  for (const agent of callers) {
    const p = { name: `${POLICY_PREFIX} ${agent.name} may broker on ${vs.name}`, effect: 'permit', caller_type: 'agent', caller_value: agent.id, secret_id: secretId, virtual_server_id: vsId, operations: ['broker'], is_active: true };
    const found = policies.find(x => x.name === p.name);
    if (found) must(await w('PUT', `/api/vault/policies/${found.id}`, p), 'update vault policy');
    else must(await w('POST', '/api/vault/policies', p), 'create vault policy');
  }

  must(await w('PUT', `/api/mcp/${mcpId}`, {
    name: mcp.name, url: mcp.url, description: mcp.description,
    auth_type: 'apikey', auth_config: { header: HEADER, key: `vault://${SECRET_NAME}` },
  }), 'update MCP server');

  mergeEnv(envFile, { [ENV_KEY]: sha256(key) }); // last: the backend only enforces after a restart
  log(`vault secret:  ${SECRET_NAME} (${existing ? 'rotated' : 'created'}; the value is never displayed)`);
  log(`MCP server:    ${mcp.name} now sends ${HEADER} = vault://${SECRET_NAME}`);
  log(`vault policy:  ${callers.map(a => a.name).join(', ')} may BROKER it on ${vs.name}`);
  log(`backend:       ${ENV_KEY} saved to ${path.basename(envFile)} (hash only)`);
  return { secretId, callers: callers.map(a => a.name), rotated: !!existing };
}

export async function rollback({ wardenUrl, vsId, mcpId, envFile, backupFile, log = console.log }) {
  const { w, mcp } = await context({ wardenUrl, vsId, mcpId });
  mergeEnv(envFile, { [ENV_KEY]: null }); // first: stop the backend enforcing (on its next restart)
  let backup = null; try { backup = JSON.parse(fs.readFileSync(backupFile, 'utf8')); } catch { /* none saved */ }
  must(await w('PUT', `/api/mcp/${mcpId}`, {
    name: mcp.name, url: mcp.url, description: mcp.description,
    auth_type: backup?.auth_type || 'none', auth_config: backup?.auth_config || {},
  }), 'restore MCP server');
  const policies = must(await w('GET', '/api/vault/policies'), 'list vault policies');
  for (const p of policies.filter(x => x.name.startsWith(POLICY_PREFIX))) await w('DELETE', `/api/vault/policies/${p.id}`);
  const secret = must(await w('GET', '/api/vault/secrets'), 'list secrets').find(s => s.name === SECRET_NAME);
  if (secret) await w('DELETE', `/api/vault/secrets/${secret.id}?force=true`);
  try { fs.unlinkSync(backupFile); } catch { /* none */ }
  log(`MCP server:    ${mcp.name} auth restored to "${backup?.auth_type || 'none'}"`);
  log(`vault:         policies and ${SECRET_NAME} removed`);
  log(`backend:       ${ENV_KEY} removed from ${path.basename(envFile)}`);
}

export async function status({ wardenUrl, vsId, mcpId, envFile, log = console.log }) {
  const { w, mcp, vs } = await context({ wardenUrl, vsId, mcpId });
  const secret = must(await w('GET', '/api/vault/secrets'), 'list secrets').find(s => s.name === SECRET_NAME);
  const pols = must(await w('GET', '/api/vault/policies'), 'list vault policies').filter(p => p.name.startsWith(POLICY_PREFIX));
  const injected = mcp.auth_type === 'apikey' && mcp.auth_config?.key === `vault://${SECRET_NAME}`;
  const hashSet = fs.existsSync(envFile) && fs.readFileSync(envFile, 'utf8').split(/\r?\n/).some(l => l.startsWith(`${ENV_KEY}=`));
  let live = 'unknown';
  try { live = (await fetch(mcp.url)).status === 401 ? 'ENFORCING (rejects calls without the key)' : 'OPEN (accepts calls without the key)'; } catch { live = 'unreachable'; }
  log(`Warden injects the key:   ${injected ? `yes (${mcp.name} -> vault://${SECRET_NAME})` : 'no'}`);
  log(`vault secret:             ${secret ? `${SECRET_NAME} v${secret.version}${secret.is_active ? '' : ' (DISABLED)'}` : 'none'}`);
  log(`broker policies:          ${pols.length ? pols.map(p => p.caller_name).join(', ') : 'none'} on ${vs.name}`);
  log(`backend env (${path.basename(envFile)}): ${hashSet ? `${ENV_KEY} set` : 'not set'}`);
  log(`running backend /mcp:     ${live}`);
}

function parseArgs(argv) {
  const out = { cmd: argv[0], agents: [] };
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === '--agent') out.agents.push(argv[++i]);
    else if (argv[i] === '--vs') out.vs = argv[++i];
    else if (argv[i] === '--mcp') out.mcp = argv[++i];
  }
  return out;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  dotenv.config({ path: path.join(backendDir, '.env') });
  dotenv.config({ path: path.join(backendDir, '.env.local') });
  const a = parseArgs(process.argv.slice(2));
  const opts = {
    wardenUrl: process.env.WARDEN_URL || 'http://localhost:3003',
    vsId: a.vs || process.env.WARDEN_VIRTUAL_SERVER_ID,
    mcpId: a.mcp || process.env.WARDEN_MCP_SERVER_ID,
    envFile: path.join(backendDir, '.env.local'),
    backupFile: path.join(backendDir, '.gateway-key-backup.json'),
  };
  const fns = { enable: () => enable({ ...opts, agentNames: a.agents }), rollback: () => rollback(opts), status: () => status(opts) };
  if (!fns[a.cmd]) { console.error('Usage: node scripts/gateway-key.js <status|enable|rollback> [--agent NAME]... [--vs ID] [--mcp ID]'); process.exit(2); }
  if (!opts.vsId || !opts.mcpId) { console.error('WARDEN_VIRTUAL_SERVER_ID and WARDEN_MCP_SERVER_ID must be set (backend .env), or pass --vs / --mcp.'); process.exit(2); }
  fns[a.cmd]().then(() => {
    if (a.cmd === 'enable') console.log('\nNow RESTART the banking backend: it enforces the key from its next start.\nCheck:  node scripts/gateway-key.js status');
    if (a.cmd === 'rollback') console.log('\nNow RESTART the banking backend so it stops requiring the key.');
  }).catch(e => { console.error(`\n${a.cmd} failed: ${e.message}`); process.exit(1); });
}
