const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { simulatePolicies } = require('../services/policyEngine');

const router = express.Router();

// List policies for a virtual server
router.get('/virtual-server/:vsId', (req, res) => {
  const policies = db.prepare(`
    SELECT * FROM policies WHERE virtual_server_id = ? ORDER BY priority DESC, created_at
  `).all(req.params.vsId);

  policies.forEach((p) => {
    try { p.policy_json = JSON.parse(p.policy_json); } catch {}
  });

  res.json(policies);
});

// Get single policy
router.get('/:id', (req, res) => {
  const policy = db.prepare('SELECT * FROM policies WHERE id = ?').get(req.params.id);
  if (!policy) return res.status(404).json({ error: 'Policy not found' });
  try { policy.policy_json = JSON.parse(policy.policy_json); } catch {}
  res.json(policy);
});

// Create a policy
router.post('/', (req, res) => {
  const { virtual_server_id, name, description, effect, priority, policy_json } = req.body;

  if (!virtual_server_id || !name || !effect) {
    return res.status(400).json({ error: 'virtual_server_id, name, and effect are required' });
  }
  if (!['permit', 'forbid'].includes(effect)) {
    return res.status(400).json({ error: 'effect must be "permit" or "forbid"' });
  }

  const vs = db.prepare('SELECT id FROM virtual_servers WHERE id = ?').get(virtual_server_id);
  if (!vs) return res.status(404).json({ error: 'Virtual server not found' });

  const id = uuidv4();
  const policyStr = JSON.stringify(policy_json || { actions: [], conditions: [] });

  db.prepare(`
    INSERT INTO policies (id, virtual_server_id, name, description, effect, priority, policy_json)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, virtual_server_id, name, description || null, effect, priority || 0, policyStr);

  res.status(201).json({ id });
});

// Update a policy
router.put('/:id', (req, res) => {
  const { name, description, effect, priority, policy_json, is_active } = req.body;
  const policy = db.prepare('SELECT id FROM policies WHERE id = ?').get(req.params.id);
  if (!policy) return res.status(404).json({ error: 'Policy not found' });

  db.prepare(`
    UPDATE policies SET name=?, description=?, effect=?, priority=?, policy_json=?, is_active=?
    WHERE id=?
  `).run(
    name, description || null, effect, priority || 0,
    JSON.stringify(policy_json || {}),
    is_active !== undefined ? (is_active ? 1 : 0) : 1,
    req.params.id
  );

  res.json({ ok: true });
});

// Delete a policy
router.delete('/:id', (req, res) => {
  db.prepare('DELETE FROM policies WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Toggle policy active/inactive
router.patch('/:id/toggle', (req, res) => {
  const policy = db.prepare('SELECT id, is_active FROM policies WHERE id = ?').get(req.params.id);
  if (!policy) return res.status(404).json({ error: 'Policy not found' });

  const newState = policy.is_active ? 0 : 1;
  db.prepare('UPDATE policies SET is_active=? WHERE id=?').run(newState, req.params.id);
  res.json({ is_active: newState === 1 });
});

// Simulate policy evaluation (dry-run)
router.post('/simulate', (req, res) => {
  const { virtual_server_id, mcp_server_id, tool_name, scopes, groups, sub } = req.body;

  if (!virtual_server_id || !mcp_server_id || !tool_name) {
    return res.status(400).json({ error: 'virtual_server_id, mcp_server_id, and tool_name are required' });
  }

  const policies = db.prepare('SELECT * FROM policies WHERE virtual_server_id = ?').all(virtual_server_id);

  const result = simulatePolicies(policies, {
    mcpServerId: mcp_server_id,
    toolName: tool_name,
    scopes: scopes || [],
    groups: groups || [],
    sub: sub || '',
  });

  res.json(result);
});

module.exports = router;
