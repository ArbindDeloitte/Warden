const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { fetchMcpTools } = require('../services/mcpClient');

const router = express.Router();

// List all tools across all MCP servers (must be before /:id route)
router.get('/tools/all', (req, res) => {
  const { mcp_server_id, search } = req.query;

  const conditions = [];
  const params = [];

  if (mcp_server_id) {
    conditions.push('mt.mcp_server_id = ?');
    params.push(mcp_server_id);
  }
  if (search) {
    conditions.push('(mt.name LIKE ? OR mt.description LIKE ?)');
    params.push(`%${search}%`, `%${search}%`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const tools = db.prepare(`
    SELECT mt.*, ms.name AS mcp_server_name, ms.url AS mcp_server_url, ms.is_active AS mcp_server_active
    FROM mcp_tools mt
    JOIN mcp_servers ms ON ms.id = mt.mcp_server_id
    ${where}
    ORDER BY ms.name, mt.name
  `).all(...params);

  tools.forEach(t => {
    try { t.input_schema = JSON.parse(t.input_schema || '{}'); } catch {}
  });

  res.json(tools);
});

// List all MCP servers
router.get('/', (req, res) => {
  const servers = db.prepare('SELECT * FROM mcp_servers ORDER BY created_at DESC').all();
  servers.forEach((s) => {
    s.auth_config = JSON.parse(s.auth_config || '{}');
    // Never return secrets in list
    if (s.auth_config.token) s.auth_config.token = '***';
    if (s.auth_config.password) s.auth_config.password = '***';
    if (s.auth_config.key) s.auth_config.key = '***';
  });
  res.json(servers);
});

// Get single MCP server with its tools
router.get('/:id', (req, res) => {
  const server = db.prepare('SELECT * FROM mcp_servers WHERE id = ?').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'MCP server not found' });

  const tools = db.prepare('SELECT * FROM mcp_tools WHERE mcp_server_id = ? ORDER BY name').all(req.params.id);
  server.auth_config = JSON.parse(server.auth_config || '{}');
  res.json({ ...server, tools });
});

// Register a new MCP server
router.post('/', (req, res) => {
  const { name, url, description, auth_type, auth_config } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'name and url are required' });

  const id = uuidv4();
  db.prepare(`
    INSERT INTO mcp_servers (id, name, url, description, auth_type, auth_config)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, name, url, description || null, auth_type || 'none', JSON.stringify(auth_config || {}));

  res.status(201).json({ id, name, url });
});

// Update an MCP server
router.put('/:id', (req, res) => {
  const { name, url, description, auth_type, auth_config } = req.body;
  const server = db.prepare('SELECT id FROM mcp_servers WHERE id = ?').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'MCP server not found' });

  db.prepare(`
    UPDATE mcp_servers SET name=?, url=?, description=?, auth_type=?, auth_config=?
    WHERE id=?
  `).run(
    name, url, description || null,
    auth_type || 'none', JSON.stringify(auth_config || {}),
    req.params.id
  );

  res.json({ ok: true });
});

// Delete an MCP server (cascades to tools)
router.delete('/:id', (req, res) => {
  db.prepare('DELETE FROM mcp_servers WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Sync tools from the MCP server
router.post('/:id/sync', async (req, res) => {
  const server = db.prepare('SELECT * FROM mcp_servers WHERE id = ?').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'MCP server not found' });

  try {
    const tools = await fetchMcpTools(server);

    const upsert = db.prepare(`
      INSERT INTO mcp_tools (id, mcp_server_id, name, description, input_schema)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(mcp_server_id, name) DO UPDATE SET
        description=excluded.description,
        input_schema=excluded.input_schema
    `);

    db.exec('BEGIN');
    try {
      for (const tool of tools) {
        upsert.run(
          uuidv4(),
          server.id,
          tool.name,
          tool.description || null,
          JSON.stringify(tool.inputSchema || tool.input_schema || {})
        );
      }
      db.exec('COMMIT');
    } catch (txErr) {
      db.exec('ROLLBACK');
      throw txErr;
    }

    db.prepare("UPDATE mcp_servers SET last_synced = datetime('now') WHERE id = ?").run(server.id);

    res.json({ synced: tools.length, tools: tools.map((t) => t.name) });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

module.exports = router;
