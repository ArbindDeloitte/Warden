'use strict';

// Removes everything demo/broker/setup.js created (by the exact names in lib.js), then the saved state.
//   node demo/broker/teardown.js

const L = require('./lib');

async function teardown({ log = console.log } = {}) {
  const removed = [];
  const del = async (label, p) => { const r = await L.warden('DELETE', p); if (r.status < 300) removed.push(label); return r; };

  const [vaultPols, mcps, vsList, secrets, agents] = await Promise.all([
    L.warden('GET', '/api/vault/policies'), L.warden('GET', '/api/mcp'), L.warden('GET', '/api/virtual-servers'),
    L.warden('GET', '/api/vault/secrets'), L.warden('GET', '/api/agents'),
  ]);
  for (const p of vaultPols.json || []) if (p.name === L.NAMES.vaultPolicy) await del(`vault policy: ${p.name}`, `/api/vault/policies/${p.id}`);
  for (const m of mcps.json || []) if (m.name === L.NAMES.mcp) await del(`MCP server: ${m.name}`, `/api/mcp/${m.id}`);
  for (const v of vsList.json || []) if (v.name === L.NAMES.vs) await del(`virtual server: ${v.name}`, `/api/virtual-servers/${v.id}`);
  for (const s of secrets.json || []) if ([L.NAMES.keySecret, L.NAMES.hookSecret].includes(s.name)) await del(`vault secret: ${s.name}`, `/api/vault/secrets/${s.id}?force=true`);
  for (const a of agents.json || []) if ([L.NAMES.reportAgent, L.NAMES.rogueAgent].includes(a.name)) await del(`agent: ${a.name}`, `/api/agents/${a.id}`);
  L.clearState();
  removed.forEach(r => log(`removed ${r}`));
  if (!removed.length) log('nothing to remove');
  return removed;
}

if (require.main === module) {
  teardown().then(() => console.log('\nDemo objects removed.')).catch(e => { console.error(`\nTeardown failed: ${e.message}`); process.exit(1); });
}

module.exports = { teardown };
