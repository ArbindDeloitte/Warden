'use strict';
const express = require('express');
const crypto  = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { evaluateAgentRules } = require('../services/ruleEngine');

const router = express.Router();

function generateToken() {
  return `wag_${crypto.randomBytes(16).toString('hex')}`;
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function parseMetadata(raw) {
  try { return JSON.parse(raw || '{}'); } catch { return {}; }
}

// GET /api/agents
router.get('/', (req, res) => {
  const agents = db.prepare(
    'SELECT id, name, description, token_prefix, metadata, is_active, created_at, last_seen_at FROM agents ORDER BY created_at DESC'
  ).all();
  agents.forEach(a => { a.metadata = parseMetadata(a.metadata); });
  res.json(agents);
});

// GET /api/agents/:id
router.get('/:id', (req, res) => {
  const a = db.prepare(
    'SELECT id, name, description, token_prefix, metadata, is_active, created_at, last_seen_at FROM agents WHERE id = ?'
  ).get(req.params.id);
  if (!a) return res.status(404).json({ error: 'Agent not found' });
  a.metadata = parseMetadata(a.metadata);
  res.json(a);
});

// POST /api/agents — create; returns token once
router.post('/', (req, res) => {
  const { name, description, metadata } = req.body;
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'name is required' });
  const token  = generateToken();
  const id     = uuidv4();
  const prefix = token.slice(0, 12); // "wag_" + 8 hex chars
  try {
    db.prepare(`
      INSERT INTO agents (id, name, description, token_hash, token_prefix, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, String(name).trim(), description || null, hashToken(token), prefix, JSON.stringify(metadata || {}));
    res.status(201).json({ id, name: String(name).trim(), token, token_prefix: prefix, message: 'Token shown once — save it now.' });
    // Evaluate group rules for the new agent (async, don't block response)
    setImmediate(() => { try { evaluateAgentRules(id); } catch {} });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: `Agent named "${name}" already exists` });
    throw err;
  }
});

// PUT /api/agents/:id — update name/description/metadata/is_active
router.put('/:id', (req, res) => {
  const cur = db.prepare('SELECT * FROM agents WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'Agent not found' });
  const { name, description, metadata, is_active } = req.body;
  try {
    db.prepare(`UPDATE agents SET name=?, description=?, metadata=?, is_active=? WHERE id=?`).run(
      name        !== undefined ? String(name).trim() : cur.name,
      description !== undefined ? description         : cur.description,
      metadata    !== undefined ? JSON.stringify(metadata) : cur.metadata,
      is_active   !== undefined ? (is_active ? 1 : 0) : cur.is_active,
      req.params.id
    );
    res.json({ ok: true });
    // Re-evaluate group rules after metadata change
    setImmediate(() => { try { evaluateAgentRules(req.params.id); } catch {} });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: `Agent named "${name}" already exists` });
    throw err;
  }
});

// DELETE /api/agents/:id
router.delete('/:id', (req, res) => {
  db.prepare('DELETE FROM agents WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// PATCH /api/agents/:id/toggle
router.patch('/:id/toggle', (req, res) => {
  const a = db.prepare('SELECT id, is_active FROM agents WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).json({ error: 'Agent not found' });
  const next = a.is_active ? 0 : 1;
  db.prepare('UPDATE agents SET is_active=? WHERE id=?').run(next, req.params.id);
  res.json({ is_active: next === 1 });
});

// POST /api/agents/:id/rotate-token
router.post('/:id/rotate-token', (req, res) => {
  const a = db.prepare('SELECT id FROM agents WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).json({ error: 'Agent not found' });
  const token  = generateToken();
  const prefix = token.slice(0, 12);
  db.prepare('UPDATE agents SET token_hash=?, token_prefix=? WHERE id=?').run(hashToken(token), prefix, req.params.id);
  res.json({ token, token_prefix: prefix, message: 'New token issued. Old token is immediately invalidated.' });
});

module.exports = router;
