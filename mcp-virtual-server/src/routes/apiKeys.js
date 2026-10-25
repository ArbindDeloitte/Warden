'use strict';

const express = require('express');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');

const router = express.Router();

function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function generateKey() {
  return 'wrd_' + crypto.randomBytes(24).toString('hex'); // wrd_ + 48 hex = 52 chars total
}

function formatKey(row) {
  return {
    id: row.id,
    name: row.name,
    key_prefix: row.key_prefix,
    key_suffix: row.key_suffix,
    virtual_server_ids: JSON.parse(row.virtual_server_ids || '[]'),
    expires_at: row.expires_at || null,
    is_active: row.is_active === 1,
    created_at: row.created_at,
    last_used_at: row.last_used_at || null,
  };
}

// GET /api/keys
router.get('/', (req, res) => {
  const keys = db.prepare('SELECT * FROM api_keys ORDER BY created_at DESC').all();
  res.json(keys.map(formatKey));
});

// POST /api/keys — create; returns full key value ONCE
router.post('/', (req, res) => {
  const { name, virtual_server_ids = [], expires_at } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'name is required' });

  const fullKey  = generateKey();
  const id       = uuidv4();
  const prefix   = fullKey.slice(0, 12);   // "wrd_" + 8 hex chars
  const suffix   = fullKey.slice(-4);

  db.prepare(`
    INSERT INTO api_keys (id, name, key_hash, key_prefix, key_suffix, virtual_server_ids, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, name.trim(), hashKey(fullKey), prefix, suffix,
    JSON.stringify(Array.isArray(virtual_server_ids) ? virtual_server_ids : []),
    expires_at || null
  );

  res.status(201).json({
    ...formatKey(db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id)),
    key: fullKey,   // full value returned exactly once
  });
});

// PATCH /api/keys/:id — update name, allowed VSes, expiry, active state
router.patch('/:id', (req, res) => {
  const cur = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'Key not found' });

  const { name, virtual_server_ids, expires_at, is_active } = req.body;

  db.prepare(`
    UPDATE api_keys SET name=?, virtual_server_ids=?, expires_at=?, is_active=? WHERE id=?
  `).run(
    name          !== undefined ? name.trim()                   : cur.name,
    virtual_server_ids !== undefined
      ? JSON.stringify(Array.isArray(virtual_server_ids) ? virtual_server_ids : [])
      : cur.virtual_server_ids,
    expires_at    !== undefined ? (expires_at || null)          : cur.expires_at,
    is_active     !== undefined ? (is_active ? 1 : 0)          : cur.is_active,
    req.params.id
  );

  res.json({ ok: true });
});

// DELETE /api/keys/:id
router.delete('/:id', (req, res) => {
  const cur = db.prepare('SELECT id FROM api_keys WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'Key not found' });
  db.prepare('DELETE FROM api_keys WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

module.exports = router;
