const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');

const router = express.Router();

// List all virtual servers
router.get('/', (req, res) => {
  const servers = db.prepare('SELECT * FROM virtual_servers ORDER BY created_at DESC').all();
  servers.forEach((s) => {
    if (s.okta_client_secret) s.okta_client_secret = '***';
  });
  res.json(servers);
});

// Get single virtual server with assigned tools and policies
router.get('/:id', (req, res) => {
  const server = db.prepare('SELECT * FROM virtual_servers WHERE id = ?').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'Virtual server not found' });

  const tools = db.prepare(`
    SELECT vst.*, ms.name AS mcp_server_name, ms.url AS mcp_server_url
    FROM virtual_server_tools vst
    JOIN mcp_servers ms ON ms.id = vst.mcp_server_id
    WHERE vst.virtual_server_id = ?
    ORDER BY ms.name, vst.tool_name
  `).all(req.params.id);

  const policies = db.prepare(`
    SELECT * FROM policies WHERE virtual_server_id = ? ORDER BY priority DESC, created_at
  `).all(req.params.id);

  if (server.okta_client_secret) server.okta_client_secret = '***';

  res.json({ ...server, tools, policies });
});

// Create a virtual server
router.post('/', (req, res) => {
  const { name, description, okta_issuer, okta_client_id, okta_client_secret, okta_audience, jwks_uri, require_obo } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  const id = uuidv4();
  db.prepare(`
    INSERT INTO virtual_servers (id, name, description, okta_issuer, okta_client_id, okta_client_secret, okta_audience, jwks_uri, require_obo)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, description || null, okta_issuer || null, okta_client_id || null,
    okta_client_secret || null, okta_audience || null, jwks_uri || null,
    require_obo === false || require_obo === 0 ? 0 : 1);

  res.status(201).json({ id, name });
});

// Update a virtual server
router.put('/:id', (req, res) => {
  const { name, description, okta_issuer, okta_client_id, okta_client_secret, okta_audience, jwks_uri, is_active, require_obo } = req.body;
  const server = db.prepare('SELECT id FROM virtual_servers WHERE id = ?').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'Virtual server not found' });

  const secretUpdate = okta_client_secret && okta_client_secret !== '***' ? okta_client_secret : null;
  const oboVal = require_obo === false || require_obo === 0 ? 0 : 1;

  if (secretUpdate) {
    db.prepare(`
      UPDATE virtual_servers SET name=?, description=?, okta_issuer=?, okta_client_id=?,
        okta_client_secret=?, okta_audience=?, jwks_uri=?, is_active=?, require_obo=? WHERE id=?
    `).run(name, description || null, okta_issuer || null, okta_client_id || null,
      secretUpdate, okta_audience || null, jwks_uri || null,
      is_active !== undefined ? (is_active ? 1 : 0) : 1, oboVal, req.params.id);
  } else {
    db.prepare(`
      UPDATE virtual_servers SET name=?, description=?, okta_issuer=?, okta_client_id=?,
        okta_audience=?, jwks_uri=?, is_active=?, require_obo=? WHERE id=?
    `).run(name, description || null, okta_issuer || null, okta_client_id || null,
      okta_audience || null, jwks_uri || null,
      is_active !== undefined ? (is_active ? 1 : 0) : 1, oboVal, req.params.id);
  }

  res.json({ ok: true });
});

// Delete a virtual server
router.delete('/:id', (req, res) => {
  db.prepare('DELETE FROM virtual_servers WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Assign tools to a virtual server
router.post('/:id/tools', (req, res) => {
  const { mcp_server_id, tool_name } = req.body;
  if (!mcp_server_id || !tool_name) {
    return res.status(400).json({ error: 'mcp_server_id and tool_name are required' });
  }

  const id = uuidv4();
  try {
    db.prepare(`
      INSERT INTO virtual_server_tools (id, virtual_server_id, mcp_server_id, tool_name)
      VALUES (?, ?, ?, ?)
    `).run(id, req.params.id, mcp_server_id, tool_name);
    res.status(201).json({ id });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Tool already assigned to this virtual server' });
    }
    throw err;
  }
});

// Remove a tool assignment
router.delete('/:id/tools/:toolId', (req, res) => {
  db.prepare('DELETE FROM virtual_server_tools WHERE id = ? AND virtual_server_id = ?')
    .run(req.params.toolId, req.params.id);
  res.json({ ok: true });
});

module.exports = router;
