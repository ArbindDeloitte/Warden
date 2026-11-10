'use strict';

const express = require('express');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const vault = require('../services/vault');
const { explainVaultPolicy, parseOps } = require('../services/vaultPolicy');

const router = express.Router();

const pick = (v, allowed, dflt) => (allowed.includes(v) ? v : dflt);
const nowIso = () => new Date().toISOString();

// ═════════════════════════════════════════════════════════════════════════════
// Agent-facing endpoints (authenticated with X-Agent-Token)
// ═════════════════════════════════════════════════════════════════════════════

function agentAuth(req, res, next) {
  const token = req.headers['x-agent-token'];
  if (!token) {
    return res.status(401).json({ error: 'Agent identity required', hint: 'Include X-Agent-Token with a registered Warden agent token.' });
  }
  const hash = crypto.createHash('sha256').update(String(token)).digest('hex');
  const agent = db.prepare('SELECT id, name, is_active FROM agents WHERE token_hash = ?').get(hash);
  if (!agent) return res.status(401).json({ error: 'Invalid agent token' });
  if (!agent.is_active) return res.status(403).json({ error: 'Agent is disabled' });
  try { db.prepare('UPDATE agents SET last_seen_at = ? WHERE id = ?').run(nowIso(), agent.id); } catch {}

  // A named virtual server must pass the same gates as a proxied tool call; otherwise a VS-scoped
  // policy could be satisfied by simply claiming the VS id.
  const vsId = req.body?.virtual_server_id || null;
  if (vsId) {
    const vs = db.prepare('SELECT * FROM virtual_servers WHERE id = ? AND is_active = 1').get(vsId);
    if (!vs) return res.status(404).json({ error: 'Virtual server not found or inactive' });
    if (vs.vault_enabled === 0) return res.status(403).json({ error: 'The Credential Vault is disabled on this virtual server' });

    const keys = db.prepare('SELECT * FROM api_keys WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > ?)').all(nowIso())
      .filter(k => { const l = vault.parseJson(k.virtual_server_ids, []); return l.length === 0 || l.includes(vsId); });
    if (keys.length) {
      const provided = req.headers['x-api-key'];
      if (!provided) return res.status(401).json({ error: 'X-API-Key header required' });
      const h = crypto.createHash('sha256').update(String(provided)).digest('hex');
      if (!keys.some(k => k.key_hash === h)) return res.status(401).json({ error: 'Invalid API key' });
    }
    if (vs.require_agent_token &&
        !db.prepare('SELECT id FROM virtual_server_agents WHERE vs_id = ? AND agent_id = ?').get(vsId, agent.id)) {
      return res.status(403).json({ error: 'Agent not authorized for this virtual server' });
    }
  }
  req.agent = agent;
  req.vsId = vsId;
  next();
}

function runVault(res, fn) {
  try {
    res.set('Cache-Control', 'no-store');
    return res.json(fn());
  } catch (err) {
    if (!(err instanceof vault.VaultError)) throw err;
    return res.status(err.status).json({ error: err.message, code: err.code });
  }
}

const requireName = (req, res) => {
  const name = req.body?.secret;
  if (typeof name !== 'string' || !name) { res.status(400).json({ error: 'secret (name) is required' }); return null; }
  return name;
};

// Runtime checkout: returns the value plus a lease the agent may cache until it expires.
router.post('/checkout', agentAuth, (req, res) => {
  const name = requireName(req, res); if (!name) return;
  const ctx = { agentId: req.agent.id, agentName: req.agent.name, vsId: req.vsId };
  runVault(res, () => {
    const { secret, value, lease } = vault.access(ctx, name, 'reveal', 'checkout', { ttl: req.body.ttl_seconds });
    return {
      secret: secret.name, type: secret.type, metadata: vault.parseJson(secret.metadata, {}), version: secret.version,
      value, lease_id: lease.id, issued_at: lease.issued_at, expires_at: lease.expires_at, ttl_seconds: lease.ttl_seconds,
    };
  });
});

// Sign-on-behalf: the private key never leaves the vault, only the JWT does.
router.post('/sign', agentAuth, (req, res) => {
  const name = requireName(req, res); if (!name) return;
  const ctx = { agentId: req.agent.id, agentName: req.agent.name, vsId: req.vsId };
  runVault(res, () => vault.signJwt(ctx, name, {
    claims: req.body.claims, algorithm: req.body.algorithm || 'RS256', expiresIn: req.body.expires_in,
  }));
});

// Lets an agent confirm a cached lease is still good (not expired, revoked, or superseded by a rotation).
router.get('/validate/:leaseId', agentAuth, (req, res) => {
  const l = db.prepare('SELECT * FROM vault_leases WHERE id = ? AND agent_id = ?').get(req.params.leaseId, req.agent.id);
  if (!l) return res.status(404).json({ valid: false, reason: 'Lease not found' });
  const s = db.prepare('SELECT version, is_active, expires_at FROM vault_secrets WHERE id = ?').get(l.secret_id);
  let reason = null;
  if (l.revoked_at) reason = 'Lease was revoked';
  else if (Date.parse(l.expires_at) <= Date.now()) reason = 'Lease expired';
  else if (!s || !s.is_active) reason = 'Secret is disabled';
  else if (s.expires_at && Date.parse(s.expires_at) <= Date.now()) reason = 'Secret has expired';
  else if (s.version !== l.secret_version) reason = 'Secret was rotated';
  res.json({ valid: !reason, reason, expires_at: l.expires_at });
});

// ═════════════════════════════════════════════════════════════════════════════
// Admin: secrets (values are write-only — never returned)
// ═════════════════════════════════════════════════════════════════════════════

function publicSecret(r) {
  const { value_enc, ...rest } = r;
  return { ...rest, metadata: vault.parseJson(r.metadata, {}), expired: !!(r.expires_at && Date.parse(r.expires_at) <= Date.now()) };
}

function usageOf(name) {
  const ref = `${vault.REF_PREFIX}${name}`;
  const mcp = db.prepare('SELECT id, name, auth_config FROM mcp_servers').all()
    .filter(s => Object.values(vault.parseJson(s.auth_config, {})).includes(ref))
    .map(({ id, name: n }) => ({ id, name: n }));
  const vs = db.prepare('SELECT id, name FROM virtual_servers WHERE okta_client_secret = ?').all(ref);
  return { mcp_servers: mcp, virtual_servers: vs };
}

function normaliseMetadata(m) {
  if (m === undefined) return { value: undefined };
  if (m === null) return { value: {} };
  if (typeof m !== 'object' || Array.isArray(m)) return { error: 'metadata must be an object' };
  if (JSON.stringify(m).length > 4096) return { error: 'metadata is too large (max 4 KB)' };
  return { value: m };
}

function normaliseExpiry(v) {
  if (v === undefined) return { value: undefined };
  if (v === null || v === '') return { value: null };
  const t = Date.parse(v);
  if (Number.isNaN(t)) return { error: 'expires_at is not a valid date' };
  return { value: new Date(t).toISOString() };
}

router.get('/secrets', (req, res) => {
  res.json(db.prepare('SELECT * FROM vault_secrets ORDER BY name').all().map(publicSecret));
});

router.get('/secrets/:id', (req, res) => {
  const s = db.prepare('SELECT * FROM vault_secrets WHERE id = ?').get(req.params.id);
  if (!s) return res.status(404).json({ error: 'Secret not found' });
  res.json({ ...publicSecret(s), usage: usageOf(s.name) });
});

router.post('/secrets', (req, res) => {
  const b = req.body || {};
  const name = String(b.name ?? '').trim();
  if (!vault.NAME_RE.test(name)) {
    return res.status(400).json({ error: 'name must be 1-64 characters: letters, digits, ".", "_" or "-", starting with a letter or digit' });
  }
  const type = pick(b.type, vault.SECRET_TYPES, 'generic');
  const bad = vault.validateSecretValue(type, b.value);
  if (bad) return res.status(400).json({ error: bad });
  const meta = normaliseMetadata(b.metadata); if (meta.error) return res.status(400).json({ error: meta.error });
  const exp = normaliseExpiry(b.expires_at); if (exp.error) return res.status(400).json({ error: exp.error });

  const id = uuidv4();
  try {
    db.prepare(`INSERT INTO vault_secrets (id, name, type, description, value_enc, metadata, expires_at) VALUES (?,?,?,?,?,?,?)`)
      .run(id, name, type, String(b.description ?? ''), vault.encrypt(b.value), JSON.stringify(meta.value ?? {}), exp.value ?? null);
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: `A secret named "${name}" already exists` });
    throw err;
  }
  vault.audit('info', `create: ${name}`, null, { operation: 'create', principal: 'admin', secret_id: id, secret_name: name, type });
  res.status(201).json({ id, name, reference: `${vault.REF_PREFIX}${name}` });
});

// Name and value are immutable here: the name is what vault:// references point at, and the value
// changes only through /rotate so every change bumps the version and voids outstanding leases.
router.put('/secrets/:id', (req, res) => {
  const cur = db.prepare('SELECT * FROM vault_secrets WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'Secret not found' });
  const b = req.body || {};
  const meta = normaliseMetadata(b.metadata); if (meta.error) return res.status(400).json({ error: meta.error });
  const exp = normaliseExpiry(b.expires_at); if (exp.error) return res.status(400).json({ error: exp.error });
  db.prepare(`UPDATE vault_secrets SET description=?, metadata=?, expires_at=?, is_active=?, updated_at=? WHERE id=?`).run(
    b.description !== undefined ? String(b.description) : cur.description,
    meta.value !== undefined ? JSON.stringify(meta.value) : cur.metadata,
    exp.value !== undefined ? exp.value : cur.expires_at,
    b.is_active !== undefined ? (b.is_active ? 1 : 0) : cur.is_active,
    nowIso(), cur.id,
  );
  vault.audit('info', `update: ${cur.name}`, null, { operation: 'update', principal: 'admin', secret_id: cur.id, secret_name: cur.name });
  res.json({ ok: true });
});

router.post('/secrets/:id/rotate', (req, res) => {
  const cur = db.prepare('SELECT * FROM vault_secrets WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'Secret not found' });
  const bad = vault.validateSecretValue(cur.type, req.body?.value);
  if (bad) return res.status(400).json({ error: bad });
  const ts = nowIso();
  db.prepare('UPDATE vault_secrets SET value_enc=?, version=version+1, rotated_at=?, updated_at=? WHERE id=?')
    .run(vault.encrypt(req.body.value), ts, ts, cur.id);
  const revoked = Number(db.prepare('UPDATE vault_leases SET revoked_at = ? WHERE secret_id = ? AND revoked_at IS NULL').run(ts, cur.id).changes);
  vault.audit('info', `rotate: ${cur.name}`, null, {
    operation: 'rotate', principal: 'admin', secret_id: cur.id, secret_name: cur.name, version: cur.version + 1, leases_revoked: revoked,
  });
  res.json({ ok: true, version: cur.version + 1, leases_revoked: revoked });
});

router.delete('/secrets/:id', (req, res) => {
  const cur = db.prepare('SELECT * FROM vault_secrets WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'Secret not found' });
  const usage = usageOf(cur.name);
  if ((usage.mcp_servers.length || usage.virtual_servers.length) && req.query.force !== 'true') {
    return res.status(409).json({ error: 'Secret is referenced by existing configuration', usage, hint: 'Remove the references or retry with ?force=true' });
  }
  db.prepare('DELETE FROM vault_policies WHERE secret_id = ?').run(cur.id);
  db.prepare('DELETE FROM vault_secrets WHERE id = ?').run(cur.id);
  vault.audit('warn', `delete: ${cur.name}`, null, { operation: 'delete', principal: 'admin', secret_id: cur.id, secret_name: cur.name });
  res.json({ ok: true });
});

// ═════════════════════════════════════════════════════════════════════════════
// Admin: policies
// ═════════════════════════════════════════════════════════════════════════════

function normalisePolicy(b, cur = {}) {
  const callerType = pick(b.caller_type ?? cur.caller_type, ['any', 'agent', 'group'], 'any');
  let ops = b.operations ?? (cur.operations ? JSON.parse(cur.operations) : ['*']);
  if (typeof ops === 'string') ops = ops.split(',').map(s => s.trim()).filter(Boolean);
  ops = Array.isArray(ops) ? ops.filter(o => o === '*' || vault.OPERATIONS.includes(o)) : [];
  if (!ops.length || ops.includes('*')) ops = ['*'];
  const ttl = Math.floor(Number(b.max_ttl_seconds ?? cur.max_ttl_seconds ?? vault.DEFAULT_TTL));
  const vs = 'virtual_server_id' in b ? (b.virtual_server_id || null) : (cur.virtual_server_id ?? null);
  return {
    name: String(b.name ?? cur.name ?? '').trim(),
    effect: pick(b.effect ?? cur.effect, ['permit', 'forbid'], 'permit'),
    priority: Number.isFinite(Number(b.priority ?? cur.priority)) ? Math.floor(Number(b.priority ?? cur.priority)) : 0,
    caller_type: callerType,
    caller_value: callerType === 'any' ? '*' : String(b.caller_value ?? cur.caller_value ?? ''),
    secret_id: String(b.secret_id ?? cur.secret_id ?? '*') || '*',
    virtual_server_id: vs,
    operations: JSON.stringify(ops),
    max_ttl_seconds: Number.isFinite(ttl) && ttl > 0 ? Math.min(ttl, vault.MAX_TTL) : vault.DEFAULT_TTL,
    is_active: (b.is_active ?? cur.is_active ?? 1) ? 1 : 0,
  };
}

function validatePolicy(p) {
  if (!p.name) return 'name is required';
  if (p.caller_type === 'agent' && !db.prepare('SELECT id FROM agents WHERE id = ?').get(p.caller_value)) return 'caller_value is not a known agent';
  if (p.caller_type === 'group' && !db.prepare('SELECT id FROM agent_groups WHERE id = ?').get(p.caller_value)) return 'caller_value is not a known agent group';
  if (p.secret_id !== '*' && !db.prepare('SELECT id FROM vault_secrets WHERE id = ?').get(p.secret_id)) return 'secret_id is not a known secret';
  if (p.virtual_server_id && !db.prepare('SELECT id FROM virtual_servers WHERE id = ?').get(p.virtual_server_id)) return 'virtual_server_id is not a known virtual server';
  return null;
}

const POLICY_SQL = `
  SELECT p.*, vs.name AS virtual_server_name,
    CASE p.caller_type WHEN 'agent' THEN (SELECT name FROM agents WHERE id = p.caller_value)
                       WHEN 'group' THEN (SELECT name FROM agent_groups WHERE id = p.caller_value) END AS caller_name,
    (SELECT name FROM vault_secrets WHERE id = p.secret_id) AS secret_name
  FROM vault_policies p LEFT JOIN virtual_servers vs ON vs.id = p.virtual_server_id`;

const policyOut = (r) => ({ ...r, operations: parseOps(r.operations) });

router.get('/policies', (req, res) => {
  const rows = req.query.secret_id
    ? db.prepare(`${POLICY_SQL} WHERE p.secret_id IN (?, '*') ORDER BY p.priority DESC, p.created_at`).all(req.query.secret_id)
    : db.prepare(`${POLICY_SQL} ORDER BY p.priority DESC, p.created_at`).all();
  res.json(rows.map(policyOut));
});

router.post('/policies', (req, res) => {
  const p = normalisePolicy(req.body || {});
  const bad = validatePolicy(p);
  if (bad) return res.status(400).json({ error: bad });
  const id = uuidv4();
  db.prepare(`INSERT INTO vault_policies (id,name,effect,priority,caller_type,caller_value,secret_id,virtual_server_id,operations,max_ttl_seconds,is_active)
              VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, p.name, p.effect, p.priority, p.caller_type, p.caller_value, p.secret_id, p.virtual_server_id, p.operations, p.max_ttl_seconds, p.is_active);
  vault.audit('info', `policy created: ${p.name}`, p.virtual_server_id, { operation: 'policy_create', principal: 'admin', policy_id: id, effect: p.effect });
  res.status(201).json({ id });
});

router.put('/policies/:id', (req, res) => {
  const cur = db.prepare('SELECT * FROM vault_policies WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'Policy not found' });
  const p = normalisePolicy(req.body || {}, cur);
  const bad = validatePolicy(p);
  if (bad) return res.status(400).json({ error: bad });
  db.prepare(`UPDATE vault_policies SET name=?,effect=?,priority=?,caller_type=?,caller_value=?,secret_id=?,virtual_server_id=?,operations=?,max_ttl_seconds=?,is_active=? WHERE id=?`)
    .run(p.name, p.effect, p.priority, p.caller_type, p.caller_value, p.secret_id, p.virtual_server_id, p.operations, p.max_ttl_seconds, p.is_active, cur.id);
  vault.audit('info', `policy updated: ${p.name}`, p.virtual_server_id, { operation: 'policy_update', principal: 'admin', policy_id: cur.id, effect: p.effect });
  res.json({ ok: true });
});

router.delete('/policies/:id', (req, res) => {
  const cur = db.prepare('SELECT * FROM vault_policies WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'Policy not found' });
  db.prepare('DELETE FROM vault_policies WHERE id = ?').run(cur.id);
  vault.audit('warn', `policy deleted: ${cur.name}`, cur.virtual_server_id, { operation: 'policy_delete', principal: 'admin', policy_id: cur.id });
  res.json({ ok: true });
});

// Dry run: would this agent be allowed to perform this operation on this secret?
router.post('/policies/simulate', (req, res) => {
  const { caller_agent_id, secret_id, virtual_server_id } = req.body || {};
  const op = pick(req.body?.operation, vault.OPERATIONS, 'reveal');
  if (!caller_agent_id || !secret_id) return res.status(400).json({ error: 'caller_agent_id and secret_id are required' });

  const caller = db.prepare('SELECT id, name FROM agents WHERE id = ?').get(caller_agent_id);
  const secret = db.prepare('SELECT id, name, type, is_active, expires_at FROM vault_secrets WHERE id = ?').get(secret_id);
  if (!caller) return res.status(404).json({ error: 'Agent not found' });
  if (!secret) return res.status(404).json({ error: 'Secret not found' });
  const groups = db.prepare(`SELECT g.name FROM agent_group_members m JOIN agent_groups g ON g.id = m.group_id
                             WHERE m.agent_id = ? AND g.is_active = 1 ORDER BY g.name`).all(caller_agent_id).map(r => r.name);

  const v = explainVaultPolicy({ agentId: caller_agent_id, secretId: secret_id, vsId: virtual_server_id || null, op });
  let { decision, reason } = v;
  // Mirrors vault.access(): the secret's own state is checked before any policy is consulted.
  if (!secret.is_active) { decision = 'deny'; reason = 'Secret is disabled'; }
  else if (secret.expires_at && Date.parse(secret.expires_at) <= Date.now()) { decision = 'deny'; reason = 'Secret has expired'; }

  res.json({
    decision, reason, policy_id: v.policy?.id || null, operation: op,
    max_ttl_seconds: decision === 'allow' && op === 'reveal' ? v.policy?.max_ttl_seconds ?? null : null,
    caller: { ...caller, groups }, secret: { id: secret.id, name: secret.name, type: secret.type },
    trace: v.trace,
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Admin: leases and activity
// ═════════════════════════════════════════════════════════════════════════════

router.get('/leases', (req, res) => {
  const where = []; const params = [];
  if (req.query.secret_id) { where.push('l.secret_id = ?'); params.push(req.query.secret_id); }
  if (req.query.agent_id) { where.push('l.agent_id = ?'); params.push(req.query.agent_id); }
  if (req.query.active === '1') { where.push('l.revoked_at IS NULL AND l.expires_at > ?'); params.push(nowIso()); }
  const rows = db.prepare(`
    SELECT l.*, s.name AS secret_name, a.name AS agent_name, vs.name AS virtual_server_name
    FROM vault_leases l
    JOIN vault_secrets s ON s.id = l.secret_id
    LEFT JOIN agents a ON a.id = l.agent_id
    LEFT JOIN virtual_servers vs ON vs.id = l.vs_id
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY l.issued_at DESC LIMIT 200
  `).all(...params);
  const now = Date.now();
  res.json(rows.map(l => ({ ...l, state: l.revoked_at ? 'revoked' : Date.parse(l.expires_at) <= now ? 'expired' : 'active' })));
});

router.delete('/leases/:id', (req, res) => {
  const l = db.prepare('SELECT l.*, s.name AS secret_name FROM vault_leases l JOIN vault_secrets s ON s.id = l.secret_id WHERE l.id = ?').get(req.params.id);
  if (!l) return res.status(404).json({ error: 'Lease not found' });
  if (!l.revoked_at) {
    db.prepare('UPDATE vault_leases SET revoked_at = ? WHERE id = ?').run(nowIso(), l.id);
    vault.audit('warn', `lease revoked: ${l.secret_name}`, l.vs_id, { operation: 'lease_revoke', principal: 'admin', secret_id: l.secret_id, secret_name: l.secret_name, lease_id: l.id, agent_id: l.agent_id });
  }
  res.json({ ok: true });
});

router.get('/activity', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
  const where = ["log_type = 'vault_access'"]; const params = [];
  if (req.query.secret_name) { where.push("json_extract(data, '$.secret_name') = ?"); params.push(req.query.secret_name); }
  if (req.query.level) { where.push('level = ?'); params.push(req.query.level); }
  const rows = db.prepare(`SELECT * FROM event_log WHERE ${where.join(' AND ')} ORDER BY created_at DESC, rowid DESC LIMIT ?`).all(...params, limit);
  res.json(rows.map(r => ({ ...r, data: vault.parseJson(r.data, {}) })));
});

// Metadata the UI needs to render forms without hard-coding enums.
router.get('/meta', (req, res) => {
  res.json({ types: vault.SECRET_TYPES, operations: vault.OPERATIONS, sign_algorithms: vault.SIGN_ALGORITHMS, max_ttl_seconds: vault.MAX_TTL, default_ttl_seconds: vault.DEFAULT_TTL, reference_prefix: vault.REF_PREFIX });
});

module.exports = router;
