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

function listVsA2aAgents(vsId) {
  return db.prepare(`
    SELECT a.id, a.name, a.description, a.card_url, a.endpoint_url, a.is_active,
           a.card_fetched_at, a.card_error, a.card_json, v.created_at AS assigned_at
    FROM virtual_server_a2a_agents v
    JOIN a2a_agents a ON a.id = v.a2a_agent_id
    WHERE v.vs_id = ? ORDER BY v.created_at DESC
  `).all(vsId).map(({ card_json, ...a }) => {
    let skills = [];
    try { skills = (JSON.parse(card_json).skills || []).map(s => ({ id: s.id, name: s.name, description: s.description })); } catch {}
    return { ...a, skills, gateway_endpoint: `/a2a/${vsId}/${a.id}`, gateway_card_url: `/a2a/${vsId}/${a.id}/.well-known/agent-card.json` };
  });
}

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

  const agents = db.prepare(`
    SELECT a.id, a.name, a.description, a.token_prefix, a.is_active, vsa.created_at AS assigned_at
    FROM virtual_server_agents vsa
    JOIN agents a ON a.id = vsa.agent_id
    WHERE vsa.vs_id = ?
    ORDER BY vsa.created_at DESC
  `).all(req.params.id);

  if (server.okta_client_secret) server.okta_client_secret = '***';

  const a2a_agents = listVsA2aAgents(req.params.id);

  res.json({ ...server, tools, policies, agents, a2a_agents });
});

const PROTOCOLS = ['mcp', 'a2a', 'both'];
const parseProtocol = (p, fallback = 'mcp') => (PROTOCOLS.includes(p) ? p : fallback);

function parseFeatures(raw) {
  const DEFAULT = ['interceptors', 'policy'];
  if (!raw) return DEFAULT;
  try { return Array.isArray(raw) ? raw : JSON.parse(raw); } catch { return DEFAULT; }
}

// Create a virtual server
router.post('/', (req, res) => {
  const { name, description, okta_issuer, okta_client_id, okta_client_secret, okta_audience, jwks_uri, require_obo, require_agent_token, features_enabled, protocol } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  const id = uuidv4();
  db.prepare(`
    INSERT INTO virtual_servers (id, name, description, okta_issuer, okta_client_id, okta_client_secret, okta_audience, jwks_uri, require_obo, require_agent_token, features_enabled, protocol)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, description || null, okta_issuer || null, okta_client_id || null,
    okta_client_secret || null, okta_audience || null, jwks_uri || null,
    require_obo === false || require_obo === 0 ? 0 : 1,
    require_agent_token ? 1 : 0,
    JSON.stringify(parseFeatures(features_enabled)),
    parseProtocol(protocol));

  res.status(201).json({ id, name });
});

// Update a virtual server
router.put('/:id', (req, res) => {
  const { name, description, okta_issuer, okta_client_id, okta_client_secret, okta_audience, jwks_uri, is_active, require_obo, require_agent_token, features_enabled, protocol } = req.body;
  const server = db.prepare('SELECT id FROM virtual_servers WHERE id = ?').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'Virtual server not found' });

  const secretUpdate = okta_client_secret && okta_client_secret !== '***' ? okta_client_secret : null;
  const oboVal      = require_obo === false || require_obo === 0 ? 0 : 1;
  const agentVal    = require_agent_token ? 1 : 0;
  const featuresJson = JSON.stringify(parseFeatures(features_enabled));

  if (secretUpdate) {
    db.prepare(`
      UPDATE virtual_servers SET name=?, description=?, okta_issuer=?, okta_client_id=?,
        okta_client_secret=?, okta_audience=?, jwks_uri=?, is_active=?, require_obo=?, require_agent_token=?, features_enabled=? WHERE id=?
    `).run(name, description || null, okta_issuer || null, okta_client_id || null,
      secretUpdate, okta_audience || null, jwks_uri || null,
      is_active !== undefined ? (is_active ? 1 : 0) : 1, oboVal, agentVal, featuresJson, req.params.id);
  } else {
    db.prepare(`
      UPDATE virtual_servers SET name=?, description=?, okta_issuer=?, okta_client_id=?,
        okta_audience=?, jwks_uri=?, is_active=?, require_obo=?, require_agent_token=?, features_enabled=? WHERE id=?
    `).run(name, description || null, okta_issuer || null, okta_client_id || null,
      okta_audience || null, jwks_uri || null,
      is_active !== undefined ? (is_active ? 1 : 0) : 1, oboVal, agentVal, featuresJson, req.params.id);
  }

  // protocol is only changed when explicitly supplied, so older clients can't reset it
  if (protocol !== undefined) {
    const cur = db.prepare('SELECT protocol FROM virtual_servers WHERE id = ?').get(req.params.id);
    db.prepare('UPDATE virtual_servers SET protocol=? WHERE id=?')
      .run(parseProtocol(protocol, cur?.protocol || 'mcp'), req.params.id);
  }

  res.json({ ok: true });
});

// ── Per-VS A2A target agents ─────────────────────────────────────────────────

router.get('/:id/a2a-agents', (req, res) => res.json(listVsA2aAgents(req.params.id)));

router.post('/:id/a2a-agents', (req, res) => {
  const { a2a_agent_id } = req.body;
  if (!a2a_agent_id) return res.status(400).json({ error: 'a2a_agent_id is required' });
  const vs = db.prepare('SELECT protocol FROM virtual_servers WHERE id = ?').get(req.params.id);
  if (!vs) return res.status(404).json({ error: 'Virtual server not found' });
  if (vs.protocol === 'mcp') return res.status(400).json({ error: 'Set this virtual server\'s protocol to A2A or Both first' });
  if (!db.prepare('SELECT id FROM a2a_agents WHERE id = ?').get(a2a_agent_id))
    return res.status(404).json({ error: 'A2A agent not found' });
  try {
    const id = uuidv4();
    db.prepare('INSERT INTO virtual_server_a2a_agents (id, vs_id, a2a_agent_id) VALUES (?,?,?)')
      .run(id, req.params.id, a2a_agent_id);
    res.status(201).json({ id });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'A2A agent already assigned to this virtual server' });
    throw err;
  }
});

router.delete('/:id/a2a-agents/:a2aAgentId', (req, res) => {
  db.prepare('DELETE FROM virtual_server_a2a_agents WHERE vs_id = ? AND a2a_agent_id = ?')
    .run(req.params.id, req.params.a2aAgentId);
  res.json({ ok: true });
});

// ── Per-VS Agent Allowlist ────────────────────────────────────────────────────

// GET /api/virtual-servers/:id/agents
router.get('/:id/agents', (req, res) => {
  const agents = db.prepare(`
    SELECT a.id, a.name, a.description, a.token_prefix, a.is_active, vsa.created_at AS assigned_at
    FROM virtual_server_agents vsa
    JOIN agents a ON a.id = vsa.agent_id
    WHERE vsa.vs_id = ?
    ORDER BY vsa.created_at DESC
  `).all(req.params.id);
  res.json(agents);
});

// POST /api/virtual-servers/:id/agents  — assign an agent
router.post('/:id/agents', (req, res) => {
  const { agent_id } = req.body;
  if (!agent_id) return res.status(400).json({ error: 'agent_id is required' });
  const vs    = db.prepare('SELECT id FROM virtual_servers WHERE id = ?').get(req.params.id);
  if (!vs) return res.status(404).json({ error: 'Virtual server not found' });
  const agent = db.prepare('SELECT id FROM agents WHERE id = ?').get(agent_id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  try {
    const id = require('uuid').v4();
    db.prepare(`INSERT INTO virtual_server_agents (id, vs_id, agent_id) VALUES (?, ?, ?)`)
      .run(id, req.params.id, agent_id);
    res.status(201).json({ id });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Agent already assigned to this virtual server' });
    throw err;
  }
});

// DELETE /api/virtual-servers/:id/agents/:agentId
router.delete('/:id/agents/:agentId', (req, res) => {
  db.prepare('DELETE FROM virtual_server_agents WHERE vs_id = ? AND agent_id = ?')
    .run(req.params.id, req.params.agentId);
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
