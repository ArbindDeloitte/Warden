'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { run } = require('../interceptors/InterceptorPipeline');

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
  const limit  = Math.min(parseInt(req.query.limit)  || 20, 200);
  const offset = parseInt(req.query.offset) || 0;
  const scanner = req.query.scanner || '';
  const flagged = req.query.flagged;   // '1' | '0' | undefined

  const conditions = ['virtual_server_id = ?'];
  const params     = [req.params.vsId];

  if (scanner) { conditions.push('scanner = ?'); params.push(scanner); }
  if (flagged === '1' || flagged === '0') { conditions.push('flagged = ?'); params.push(Number(flagged)); }

  const where = conditions.join(' AND ');

  const rows  = db.prepare(`SELECT * FROM interceptor_log WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
  const total = db.prepare(`SELECT COUNT(*) as n FROM interceptor_log WHERE ${where}`).get(...params).n;

  rows.forEach(r => {
    try { r.categories = JSON.parse(r.categories); } catch { r.categories = []; }
    try { r.pii_types  = JSON.parse(r.pii_types);  } catch { r.pii_types  = []; }
  });

  res.json({ rows, total, limit, offset });
});

// ── Test endpoint ─────────────────────────────────────────────────────────────

// POST /api/interceptors/:vsId/scan  — run a message through the pipeline (also aliased as /test for the UI)
router.post('/:vsId/scan', async (req, res) => {
  const { text, direction } = req.body;
  if (!text) return res.status(400).json({ error: 'text is required' });

  const result = await run(text, direction || 'inbound', req.params.vsId);
  res.json(result);
});

// Alias /test → /scan so the Warden UI "Test a message" button still works
router.post('/:vsId/test', async (req, res) => {
  const { text, direction } = req.body;
  if (!text) return res.status(400).json({ error: 'text is required' });
  const result = await run(text, direction || 'inbound', req.params.vsId);
  res.json(result);
});

module.exports = router;
