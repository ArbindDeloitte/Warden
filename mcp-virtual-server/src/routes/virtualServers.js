const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { isRef } = require('../services/vault');

const router = express.Router();

// List all virtual servers
router.get('/', (req, res) => {
  const servers = db.prepare('SELECT * FROM virtual_servers ORDER BY created_at DESC').all();
  servers.forEach((s) => {
    if (s.okta_client_secret && !isRef(s.okta_client_secret)) s.okta_client_secret = '***';
  });
  res.json(servers);
});

function listVsA2aAgents(vsId) {
  return db.prepare(`
    SELECT a.id, a.name, a.description, a.card_url, a.endpoint_url, a.is_active,
           a.card_fetched_at, a.card_error, a.card_json, a.protocol_version, v.created_at AS assigned_at
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

  if (server.okta_client_secret && !isRef(server.okta_client_secret)) server.okta_client_secret = '***';

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

// A virtual server that proxies MCP tools (protocol mcp or both) with require_obo = 0 AND require_agent_token = 0
// has no caller identity at all: no user token and no agent token. Warden then cannot say who is calling, so agent
// rules cannot apply and anyone who can reach it (plus its API key, if it has any) reaches the tools. Saving that
// combination needs an explicit `allow_anonymous: true`. A2A-only virtual servers have their own controls and are exempt.
// (A vaulted upstream credential is never injected for an unidentified caller either way; this guards the rest.)
function anonymousRefusal({ protocol, requireObo, requireAgentToken, allowAnonymous }) {
  if (protocol === 'a2a') return null;
  if (requireObo !== 0 || requireAgentToken) return null;
  if (allowAnonymous) return null;
  return {
    error: 'Refusing to save: this virtual server would accept calls from anyone',
    code: 'anonymous_virtual_server',
    hint: 'require_obo is off and require_agent_token is off, so no caller identity is checked. Turn on require_agent_token (and add the agents that need access), or send allow_anonymous: true to confirm that unauthenticated calls are intended.',
  };
}

// require_obo on means the caller's user token is verified and exchanged. With no issuer, no jwks_uri and no global
// JWKS_URI there is nothing to verify it against, so the token's claims would be read unchecked (and the exchange,
// which needs the issuer, could not work either). Refuse to save that instead of failing on the first call.
function noIdpRefusal({ protocol, requireObo, issuer, jwksUri }) {
  if (protocol === 'a2a' || requireObo === 0) return null;
  if (String(issuer || '').trim() || String(jwksUri || '').trim() || process.env.JWKS_URI) return null;
  return {
    error: 'Refusing to save: require_obo is on but no identity provider is configured',
    code: 'obo_without_idp',
    hint: 'Set the Okta issuer (or a jwks_uri) so user tokens can be verified, or turn off require_obo for an agent-only virtual server.',
  };
}

function logAnonymousAck(vsId, name) {
  try {
    db.prepare(`INSERT INTO event_log (id, vs_id, log_type, level, summary, data) VALUES (?,?,?,?,?,?)`)
      .run(uuidv4(), vsId, 'config', 'warn', `Virtual server "${name}" saved as anonymous (no user token, no agent token required)`, JSON.stringify({ allow_anonymous: true }));
  } catch {}
}

// Create a virtual server
router.post('/', (req, res) => {
  const { name, description, okta_issuer, okta_client_id, okta_client_secret, okta_audience, jwks_uri, require_obo, require_agent_token, features_enabled, protocol, vault_enabled, user_token_audience, user_token_issuer, allow_anonymous } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  const oboNew = require_obo === false || require_obo === 0 ? 0 : 1;
  const agentNew = require_agent_token ? 1 : 0;
  const protoNew = parseProtocol(protocol);
  const refusal = anonymousRefusal({ protocol: protoNew, requireObo: oboNew, requireAgentToken: agentNew, allowAnonymous: allow_anonymous === true || allow_anonymous === 1 });
  if (refusal) return res.status(400).json(refusal);
  const noIdp = noIdpRefusal({ protocol: protoNew, requireObo: oboNew, issuer: okta_issuer, jwksUri: jwks_uri });
  if (noIdp) return res.status(400).json(noIdp);
  const anonAck = protoNew !== 'a2a' && oboNew === 0 && !agentNew ? 1 : 0;

  const id = uuidv4();
  db.prepare(`
    INSERT INTO virtual_servers (id, name, description, okta_issuer, okta_client_id, okta_client_secret, okta_audience, jwks_uri, require_obo, require_agent_token, features_enabled, protocol, vault_enabled, allow_anonymous)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, description || null, okta_issuer || null, okta_client_id || null,
    okta_client_secret || null, okta_audience || null, jwks_uri || null,
    oboNew,
    agentNew,
    JSON.stringify(parseFeatures(features_enabled)),
    protoNew,
    // omitted = on, so clients that predate this switch keep their behaviour (the UI sends it explicitly)
    vault_enabled === undefined ? 1 : (vault_enabled ? 1 : 0),
    anonAck);
  if (anonAck) logAnonymousAck(id, name);
  if (user_token_audience || user_token_issuer) {
    db.prepare('UPDATE virtual_servers SET user_token_audience=?, user_token_issuer=? WHERE id=?')
      .run(String(user_token_audience || '').trim() || null, String(user_token_issuer || '').trim() || null, id);
  }

  res.status(201).json({ id, name });
});

// Update a virtual server
router.put('/:id', (req, res) => {
  const { name, description, okta_issuer, okta_client_id, okta_client_secret, okta_audience, jwks_uri, is_active, require_obo, require_agent_token, features_enabled, protocol, vault_enabled, user_token_audience, user_token_issuer, allow_anonymous } = req.body;
  const server = db.prepare('SELECT id, protocol, allow_anonymous FROM virtual_servers WHERE id = ?').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'Virtual server not found' });

  const secretUpdate = okta_client_secret && okta_client_secret !== '***' ? okta_client_secret : null;
  const oboVal      = require_obo === false || require_obo === 0 ? 0 : 1;
  const agentVal    = require_agent_token ? 1 : 0;

  // Checked before anything is written. protocol / allow_anonymous change only when supplied (like vault_enabled),
  // so an older client that omits them neither flips the protocol nor loses or gains the acknowledgement.
  const effProtocol = protocol !== undefined ? parseProtocol(protocol, server.protocol || 'mcp') : (server.protocol || 'mcp');
  const effAllow = allow_anonymous !== undefined ? (allow_anonymous === true || allow_anonymous === 1) : !!server.allow_anonymous;
  const refusal = anonymousRefusal({ protocol: effProtocol, requireObo: oboVal, requireAgentToken: agentVal, allowAnonymous: effAllow });
  if (refusal) return res.status(400).json(refusal);
  const noIdp = noIdpRefusal({ protocol: effProtocol, requireObo: oboVal, issuer: okta_issuer, jwksUri: jwks_uri });
  if (noIdp) return res.status(400).json(noIdp);
  const anonNow =effProtocol !== 'a2a' && oboVal === 0 && !agentVal;
  // The acknowledgement only means something while the combination is in effect; securing the VS clears it.
  const allowStored = anonNow ? 1 : 0;
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

  // The expected user-token audience / issuer change only when supplied ('' clears them), so older clients can't drop a check.
  if (user_token_audience !== undefined) {
    db.prepare('UPDATE virtual_servers SET user_token_audience=? WHERE id=?').run(String(user_token_audience || '').trim() || null, req.params.id);
  }
  if (user_token_issuer !== undefined) {
    db.prepare('UPDATE virtual_servers SET user_token_issuer=? WHERE id=?').run(String(user_token_issuer || '').trim() || null, req.params.id);
  }

  db.prepare('UPDATE virtual_servers SET allow_anonymous=? WHERE id=?').run(allowStored, req.params.id);
  if (allowStored && !server.allow_anonymous) logAnonymousAck(req.params.id, name);

  // vault_enabled, like protocol, changes only when explicitly supplied, so older clients can't flip it
  if (vault_enabled !== undefined) {
    db.prepare('UPDATE virtual_servers SET vault_enabled=? WHERE id=?').run(vault_enabled ? 1 : 0, req.params.id);
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
