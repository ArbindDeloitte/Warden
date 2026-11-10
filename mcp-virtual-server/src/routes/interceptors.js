'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { run } = require('../interceptors/InterceptorPipeline');
const { evaluateUserTriggers } = require('../services/triggerEvaluator');
const admin = require('../middleware/adminAuth');
const { authenticateAgent, checkVsApiKey } = require('../services/dataPlaneAuth');

// Decode a JWT payload (base64, no verification) to extract user identity
function extractUserFromToken(tokenHeader) {
  try {
    if (!tokenHeader) return null;
    const raw    = tokenHeader.replace(/^Bearer\s+/i, '');
    const parts  = raw.split('.');
    if (parts.length < 2) return null;
    const padded = parts[1] + '='.repeat((4 - parts[1].length % 4) % 4);
    const payload = JSON.parse(Buffer.from(padded, 'base64url').toString('utf8'));
    if (!payload.sub) return null;
    return {
      sub:   payload.sub,
      email: payload.email || payload.preferred_username || null,
      name:  payload.name  || null,
      iss:   payload.iss   || null,
    };
  } catch { return null; }
}

// Resolve user identity from x-id-token (or x-user-token fallback),
// but only when the VS has at least one active IDP config whose issuer matches.
function resolveUserForVs(vsId, req) {
  try {
    const configs = db.prepare(
      'SELECT issuer FROM vs_idp_configs WHERE virtual_server_id = ? AND is_active = 1'
    ).all(vsId);
    if (!configs.length) return null;

    const tokenHeader = req.headers['x-id-token'] || req.headers['x-user-token'];
    const user = extractUserFromToken(tokenHeader);
    if (!user) return null;

    // Only attach identity if the token's issuer matches a trusted IDP config
    const trusted = configs.some(c => c.issuer === user.iss);
    return trusted ? user : null;
  } catch { return null; }
}

const router = express.Router();

const SCANNER_CATALOG = [
  { name: 'regex',       label: 'Regex + Keyword',    tier: 'sync',  defaultEnabled: true,  description: 'PII patterns (SSN, cards, emails, API keys) and prompt injection heuristics. Always-on, <1ms.' },
  { name: 'embedding',   label: 'Embedding Scanner',  tier: 'sync',  defaultEnabled: false, description: 'Semantic similarity against 20+ OWASP injection vectors using all-MiniLM-L6-v2. Runs fully in-process from local model — no network dependency. Catches rephrased injections regex misses. ~30ms.' },
  { name: 'presidio',    label: 'Presidio PII',       tier: 'sync',  defaultEnabled: false, description: 'NLP-based Named Entity Recognition via local presidio-analyzer. Catches names, addresses, org names.' },
  { name: 'llama-guard', label: 'Llama Guard 3',      tier: 'async', defaultEnabled: false, description: 'Semantic safety classification via Ollama. Async only — never blocks requests, enriches audit log.' },
];

// ── Scanners ──────────────────────────────────────────────────────────────────

// GET /api/interceptors/:vsId/scanners  — list scanner configs for a VS
router.get('/:vsId/scanners', (req, res) => {
  const { vsId } = req.params;

  const saved = db.prepare('SELECT * FROM interceptor_scanners WHERE virtual_server_id = ?').all(vsId);
  const savedMap = Object.fromEntries(saved.map(r => [r.scanner_name, r]));

  const scanners = SCANNER_CATALOG.map(cat => {
    const row = savedMap[cat.name];
    return {
      scanner_name: cat.name,
      label: cat.label,
      tier: cat.tier,
      description: cat.description,
      enabled: row ? row.enabled === 1 : cat.defaultEnabled,
      direction: row ? row.direction : 'both',
      id: row ? row.id : null,
    };
  });

  res.json(scanners);
});

// PUT /api/interceptors/:vsId/scanners/:scannerName  — upsert scanner config
router.put('/:vsId/scanners/:scannerName', (req, res) => {
  const { vsId, scannerName } = req.params;
  const { enabled, direction } = req.body;

  const existing = db.prepare('SELECT id FROM interceptor_scanners WHERE virtual_server_id = ? AND scanner_name = ?').get(vsId, scannerName);

  if (existing) {
    db.prepare(`
      UPDATE interceptor_scanners SET enabled = ?, direction = ? WHERE id = ?
    `).run(enabled ? 1 : 0, direction || 'both', existing.id);
    res.json({ ok: true, id: existing.id });
  } else {
    const id = uuidv4();
    db.prepare(`
      INSERT INTO interceptor_scanners (id, virtual_server_id, scanner_name, direction, enabled)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, vsId, scannerName, direction || 'both', enabled ? 1 : 0);
    res.status(201).json({ ok: true, id });
  }
});

// ── Rules ─────────────────────────────────────────────────────────────────────

// GET /api/interceptors/:vsId/rules
router.get('/:vsId/rules', (req, res) => {
  const rules = db.prepare(`
    SELECT * FROM interceptor_rules WHERE virtual_server_id = ? ORDER BY priority DESC, created_at
  `).all(req.params.vsId);
  res.json(rules);
});

// POST /api/interceptors/:vsId/rules
router.post('/:vsId/rules', (req, res) => {
  const { vsId } = req.params;
  const { name, scanner, category, score_min, action, priority } = req.body;

  if (!action || !['block', 'mask', 'warn', 'log'].includes(action)) {
    return res.status(400).json({ error: 'action must be block, mask, warn, or log' });
  }

  const id = uuidv4();
  db.prepare(`
    INSERT INTO interceptor_rules (id, virtual_server_id, name, scanner, category, score_min, action, priority)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, vsId, name || null, scanner || '*', category || '*', score_min ?? 0.7, action, priority ?? 0);

  res.status(201).json({ id });
});

// PUT /api/interceptors/:vsId/rules/:id
router.put('/:vsId/rules/:id', (req, res) => {
  const { name, scanner, category, score_min, action, priority, is_active } = req.body;
  const rule = db.prepare('SELECT id FROM interceptor_rules WHERE id = ? AND virtual_server_id = ?').get(req.params.id, req.params.vsId);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });

  db.prepare(`
    UPDATE interceptor_rules SET name=?, scanner=?, category=?, score_min=?, action=?, priority=?, is_active=?
    WHERE id=?
  `).run(name || null, scanner || '*', category || '*', score_min ?? 0.7, action, priority ?? 0, is_active !== false ? 1 : 0, req.params.id);

  res.json({ ok: true });
});

// DELETE /api/interceptors/:vsId/rules/:id
router.delete('/:vsId/rules/:id', (req, res) => {
  db.prepare('DELETE FROM interceptor_rules WHERE id = ? AND virtual_server_id = ?').run(req.params.id, req.params.vsId);
  res.json({ ok: true });
});

// PATCH /api/interceptors/:vsId/rules/:id/toggle
router.patch('/:vsId/rules/:id/toggle', (req, res) => {
  const rule = db.prepare('SELECT id, is_active FROM interceptor_rules WHERE id = ? AND virtual_server_id = ?').get(req.params.id, req.params.vsId);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });
  const newState = rule.is_active ? 0 : 1;
  db.prepare('UPDATE interceptor_rules SET is_active=? WHERE id=?').run(newState, req.params.id);
  res.json({ is_active: newState === 1 });
});

// ── Audit Log ─────────────────────────────────────────────────────────────────

// GET /api/interceptors/:vsId/log?limit=20&offset=0&scanner=regex&flagged=1
router.get('/:vsId/log', (req, res) => {
  const limit   = Math.min(parseInt(req.query.limit) || 20, 200);
  const offset  = parseInt(req.query.offset) || 0;
  const scanner = req.query.scanner || '';
  const flagged = req.query.flagged;  // '1' | '0' | undefined

  const conditions = ["vs_id = ? AND log_type = 'interceptor'"];
  const params     = [req.params.vsId];

  const where = conditions.join(' AND ');

  const rawRows = db.prepare(`
    SELECT * FROM event_log WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(...params, limit, offset);

  // Reshape event_log rows into the old interceptor_log shape for UI compat
  let rows = rawRows.map(r => {
    const d = (() => { try { return JSON.parse(r.data || '{}'); } catch { return {}; } })();
    return {
      id:                r.id,
      virtual_server_id: r.vs_id,
      created_at:        r.created_at,
      direction:         d.direction || null,
      scanner:           d.scanner   || null,
      flagged:           d.flagged   || 0,
      action_taken:      d.action_taken || null,
      categories:        Array.isArray(d.categories) ? d.categories : [],
      pii_types:         Array.isArray(d.pii_types)  ? d.pii_types  : [],
      score:             d.score  || 0,
      degraded:          d.degraded || 0,
    };
  });

  // Apply in-memory filters for scanner and flagged (since they're in the JSON data)
  if (scanner)  rows = rows.filter(r => r.scanner === scanner);
  if (flagged === '1') rows = rows.filter(r => r.flagged === 1);
  if (flagged === '0') rows = rows.filter(r => r.flagged === 0);

  const total = db.prepare(`SELECT COUNT(*) as n FROM event_log WHERE ${where}`).get(...params).n;

  res.json({ rows, total, limit, offset });
});

// ── Test endpoint ─────────────────────────────────────────────────────────────

// POST /api/interceptors/:vsId/scan  — run a message through the pipeline (also aliased as /test for the UI)
// Optional body fields: agent_name (string) or agent_id (UUID) to attach to the event_log entry.
router.post('/:vsId/scan', async (req, res) => {
  const { text, direction, agent_name, agent_id } = req.body;
  if (!text) return res.status(400).json({ error: 'text is required' });

  // Secure mode (WARDEN_ADMIN_TOKEN set): an admin may scan freely (the UI's test tool); anyone else must be a
  // registered agent, with the virtual server's API key if it has one. The agent's identity then comes from its
  // token, never from the body, so findings and scores cannot be attributed to an agent the caller is not.
  let tokenAgent = null;
  if (admin.enabled() && !admin.isAdmin(req)) {
    const a = authenticateAgent(req);
    if (a.error) return res.status(a.error.status).json({ error: a.error.message });
    const k = checkVsApiKey(req, req.params.vsId);
    if (k) return res.status(k.status).json({ error: k.message });
    tokenAgent = a.agent;
  } else if (req.headers['x-agent-token']) {
    // Open mode, or an admin who also sent an agent token: a valid token still identifies the caller (an invalid one is ignored)
    tokenAgent = authenticateAgent(req).agent || null;
  }

  // Resolve agent_id: the authenticated agent, else an explicit UUID, else a lookup by name
  let resolvedAgentId = tokenAgent ? tokenAgent.id : (agent_id || null);
  if (!resolvedAgentId && agent_name) {
    const row = db.prepare('SELECT id FROM agents WHERE name = ?').get(agent_name);
    if (row) resolvedAgentId = row.id;
  }

  // Resolve user identity from IDP token if the VS has IDP Connect configured
  const user = resolveUserForVs(req.params.vsId, req);

  const result = await run(text, direction || 'inbound', req.params.vsId, resolvedAgentId, null, user);
  res.json(result);
  // Fire Warden Function triggers asynchronously — after response is sent
  if (user?.sub) {
    evaluateUserTriggers(req.params.vsId, user.sub, user.email, user.name).catch(() => {});
  }
});

// Alias /test → /scan so the Warden UI "Test a message" button still works
router.post('/:vsId/test', async (req, res) => {
  const { text, direction } = req.body;
  if (!text) return res.status(400).json({ error: 'text is required' });
  const result = await run(text, direction || 'inbound', req.params.vsId);
  res.json(result);
});

module.exports = router;
