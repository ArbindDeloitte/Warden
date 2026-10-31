'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { runFunction, TEMPLATE_CODE, TEMPLATES } = require('../services/wardenRunner');

const router = express.Router();

// ── Functions CRUD ────────────────────────────────────────────────────────────

router.get('/', (_req, res) => {
  const rows = db.prepare(`
    SELECT wf.*,
      COUNT(DISTINCT CASE WHEN wft.is_active=1 THEN wft.id END) AS active_trigger_count,
      COUNT(DISTINCT wfl.id) AS total_invocations,
      MAX(wfl.created_at) AS last_invoked_at
    FROM warden_functions wf
    LEFT JOIN warden_function_triggers wft ON wft.function_id = wf.id
    LEFT JOIN warden_function_logs     wfl ON wfl.function_id = wf.id
    GROUP BY wf.id
    ORDER BY wf.created_at DESC
  `).all();
  res.json(rows);
});

const VALID_TYPES = ['user_risk', 'vs_risk', 'agent_risk', 'scheduled'];

router.post('/', (req, res) => {
  const { name, description, function_type } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'name is required' });
  const type     = VALID_TYPES.includes(function_type) ? function_type : 'user_risk';
  const template = TEMPLATES[type] || TEMPLATE_CODE;
  const id = uuidv4();
  db.prepare(`INSERT INTO warden_functions (id,name,description,code,function_type) VALUES (?,?,?,?,?)`)
    .run(id, name.trim(), description || '', template, type);
  res.status(201).json({ id });
});

router.get('/:id', (req, res) => {
  const fn = db.prepare('SELECT * FROM warden_functions WHERE id = ?').get(req.params.id);
  if (!fn) return res.status(404).json({ error: 'Not found' });
  const triggers   = db.prepare(`
    SELECT wft.*, vs.name AS vs_name
    FROM warden_function_triggers wft
    LEFT JOIN virtual_servers vs ON vs.id = wft.vs_id
    WHERE wft.function_id = ? ORDER BY wft.created_at DESC
  `).all(req.params.id);
  const secretKeys = db.prepare('SELECT id, key, created_at FROM warden_function_secrets WHERE function_id = ? ORDER BY created_at').all(req.params.id);
  res.json({ ...fn, triggers, secret_keys: secretKeys });
});

router.put('/:id', (req, res) => {
  const fn = db.prepare('SELECT id FROM warden_functions WHERE id = ?').get(req.params.id);
  if (!fn) return res.status(404).json({ error: 'Not found' });
  const { name, description, code, is_active } = req.body;
  db.prepare(`UPDATE warden_functions
    SET name=COALESCE(?,name), description=COALESCE(?,description),
        code=COALESCE(?,code), is_active=COALESCE(?,is_active),
        updated_at=datetime('now')
    WHERE id=?`)
    .run(name ?? null, description ?? null, code ?? null,
         is_active !== undefined ? (is_active ? 1 : 0) : null, req.params.id);
  res.json({ ok: true });
});

router.delete('/:id', (req, res) => {
  db.prepare('DELETE FROM warden_functions WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── Secrets ───────────────────────────────────────────────────────────────────

router.put('/:id/secrets/:key', (req, res) => {
  const { value } = req.body;
  if (value === undefined) return res.status(400).json({ error: 'value is required' });
  if (!db.prepare('SELECT id FROM warden_functions WHERE id = ?').get(req.params.id))
    return res.status(404).json({ error: 'Not found' });
  const b64 = Buffer.from(String(value)).toString('base64');
  const existing = db.prepare('SELECT id FROM warden_function_secrets WHERE function_id=? AND key=?').get(req.params.id, req.params.key);
  if (existing) {
    db.prepare('UPDATE warden_function_secrets SET value_b64=? WHERE id=?').run(b64, existing.id);
  } else {
    db.prepare('INSERT INTO warden_function_secrets (id,function_id,key,value_b64) VALUES (?,?,?,?)').run(uuidv4(), req.params.id, req.params.key, b64);
  }
  res.json({ ok: true });
});

router.delete('/:id/secrets/:key', (req, res) => {
  db.prepare('DELETE FROM warden_function_secrets WHERE function_id=? AND key=?').run(req.params.id, req.params.key);
  res.json({ ok: true });
});

// ── Triggers ──────────────────────────────────────────────────────────────────

const VALID_TRIGGER_TYPES = ['user_score_below', 'vs_score_below', 'agent_score_below', 'scheduled'];

router.post('/:id/triggers', (req, res) => {
  const fn = db.prepare('SELECT id FROM warden_functions WHERE id = ?').get(req.params.id);
  if (!fn) return res.status(404).json({ error: 'Not found' });

  const { vs_id, threshold, trigger_type, interval_minutes } = req.body;
  const ttype = VALID_TRIGGER_TYPES.includes(trigger_type) ? trigger_type : 'user_score_below';

  let thresh = null, intervalMin = null;
  if (ttype === 'scheduled') {
    intervalMin = Number(interval_minutes) || 1440;
  } else {
    thresh = Number(threshold);
    if (isNaN(thresh) || thresh < 0 || thresh > 1000)
      return res.status(400).json({ error: 'threshold must be 0–1000' });
  }

  const tid = uuidv4();
  db.prepare(`INSERT INTO warden_function_triggers (id,function_id,vs_id,trigger_type,threshold,interval_minutes) VALUES (?,?,?,?,?,?)`)
    .run(tid, req.params.id, vs_id || null, ttype, thresh, intervalMin);
  res.status(201).json({ id: tid });
});

router.patch('/:id/triggers/:tid', (req, res) => {
  const { is_active } = req.body;
  db.prepare('UPDATE warden_function_triggers SET is_active=? WHERE id=? AND function_id=?')
    .run(is_active ? 1 : 0, req.params.tid, req.params.id);
  res.json({ ok: true });
});

router.delete('/:id/triggers/:tid', (req, res) => {
  db.prepare('DELETE FROM warden_function_triggers WHERE id=? AND function_id=?').run(req.params.tid, req.params.id);
  res.json({ ok: true });
});

// ── Execution Logs ────────────────────────────────────────────────────────────

router.get('/:id/logs', (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit)  || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  const logs   = db.prepare(`SELECT * FROM warden_function_logs WHERE function_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .all(req.params.id, limit, offset);
  const total  = db.prepare('SELECT COUNT(*) AS n FROM warden_function_logs WHERE function_id=?').get(req.params.id).n;
  res.json({ logs, total, limit, offset });
});

// ── Test Run ──────────────────────────────────────────────────────────────────

router.post('/:id/test', async (req, res) => {
  const fn = db.prepare('SELECT * FROM warden_functions WHERE id = ?').get(req.params.id);
  if (!fn) return res.status(404).json({ error: 'Not found' });
  const secretRows = db.prepare('SELECT key, value_b64 FROM warden_function_secrets WHERE function_id = ?').all(req.params.id);
  const secrets    = Object.fromEntries(secretRows.map(r => [r.key, Buffer.from(r.value_b64, 'base64').toString('utf8')]));
  const event      = req.body.event || {
    type:           'user_score_below_threshold',
    triggered_at:   new Date().toISOString(),
    user:           { sub: 'test-user-sub', email: 'test@example.com', name: 'Test User' },
    score:          { current: 185, threshold: 200, tier: 'Critical' },
    virtual_server: { id: 'test-vs-id', name: 'test-vs' },
  };
  const result = await runFunction(fn.code, event, secrets);
  res.json(result);
});

module.exports = router;
