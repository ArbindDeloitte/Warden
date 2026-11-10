'use strict';

// Agent-credential checks shared by the data-plane endpoints that are not the MCP proxy itself (message scan,
// approval status). They mirror the proxy: a registered, active agent token, plus the virtual server's API key
// when it has active keys.

const crypto = require('crypto');
const db = require('../db/database');

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

/** Resolves X-Agent-Token to an active agent. Returns { agent } or { error: { status, message } }. */
function authenticateAgent(req) {
  const t = req.headers['x-agent-token'];
  if (!t) return { error: { status: 401, message: 'Agent identity required (X-Agent-Token)' } };
  const agent = db.prepare('SELECT id, name, is_active FROM agents WHERE token_hash = ?').get(sha256(t));
  if (!agent) return { error: { status: 401, message: 'Invalid agent token' } };
  if (!agent.is_active) return { error: { status: 403, message: 'Agent is disabled' } };
  return { agent };
}

/** null when fine, else { status, message }: the virtual server's active API keys must be presented. */
function checkVsApiKey(req, vsId) {
  const now = new Date().toISOString();
  const active = db.prepare('SELECT * FROM api_keys WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > ?)').all(now)
    .filter(k => { let l = []; try { l = JSON.parse(k.virtual_server_ids || '[]'); } catch {} return l.length === 0 || l.includes(vsId); });
  if (!active.length) return null;
  const provided = req.headers['x-api-key'];
  if (!provided) return { status: 401, message: 'X-API-Key header required' };
  const h = sha256(provided);
  const hit = active.find(k => k.key_hash === h);
  if (!hit) return { status: 401, message: 'Invalid API key' };
  try { db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now, hit.id); } catch {}
  return null;
}

module.exports = { authenticateAgent, checkVsApiKey };
