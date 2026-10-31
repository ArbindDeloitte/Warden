'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');

const router = express.Router({ mergeParams: true });

// GET /api/virtual-servers/:id/idp-configs
router.get('/', (req, res) => {
  const rows = db.prepare(
    'SELECT * FROM vs_idp_configs WHERE virtual_server_id = ? ORDER BY created_at'
  ).all(req.params.id);
  res.json(rows);
});

// POST /api/virtual-servers/:id/idp-configs
router.post('/', (req, res) => {
  const { name, provider, issuer, audience, jwks_uri, full_verification } = req.body;
  if (!name || !issuer) return res.status(400).json({ error: 'name and issuer are required' });

  const vs = db.prepare('SELECT id FROM virtual_servers WHERE id = ?').get(req.params.id);
  if (!vs) return res.status(404).json({ error: 'Virtual server not found' });

  const id = uuidv4();
  db.prepare(`
    INSERT INTO vs_idp_configs (id, virtual_server_id, name, provider, issuer, audience, jwks_uri, full_verification)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, req.params.id, name, provider || 'okta', issuer,
    audience || null, jwks_uri || null, full_verification ? 1 : 0);
  res.status(201).json({ id });
});

// PUT /api/virtual-servers/:id/idp-configs/:configId
router.put('/:configId', (req, res) => {
  const { name, provider, issuer, audience, jwks_uri, full_verification, is_active } = req.body;
  if (!name || !issuer) return res.status(400).json({ error: 'name and issuer are required' });

  db.prepare(`
    UPDATE vs_idp_configs
    SET name=?, provider=?, issuer=?, audience=?, jwks_uri=?, full_verification=?, is_active=?
    WHERE id=? AND virtual_server_id=?
  `).run(name, provider || 'okta', issuer, audience || null, jwks_uri || null,
    full_verification ? 1 : 0, is_active !== false ? 1 : 0,
    req.params.configId, req.params.id);
  res.json({ ok: true });
});

// DELETE /api/virtual-servers/:id/idp-configs/:configId
router.delete('/:configId', (req, res) => {
  db.prepare('DELETE FROM vs_idp_configs WHERE id = ? AND virtual_server_id = ?')
    .run(req.params.configId, req.params.id);
  res.json({ ok: true });
});

module.exports = router;
