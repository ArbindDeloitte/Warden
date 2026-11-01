'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { syncGroupRules } = require('../services/ruleEngine');

const router = express.Router();

const PRESET_COLORS = ['#6366f1','#10b981','#f59e0b','#ef4444','#8b5cf6','#06b6d4','#f97316','#ec4899'];
const VALID_OPERATORS = ['eq', 'ne', 'contains', 'startsWith', 'regex'];

// ── Global rules listing (must come before /:id routes) ──────────────────────

router.get('/rules', (_req, res) => {
  const rules = db.prepare(`
    SELECT r.*, g.name AS group_name, g.color_tag AS group_color,
      (SELECT COUNT(*) FROM agent_group_members m WHERE m.group_id = r.group_id AND m.rule_id = r.id) AS auto_member_count
    FROM agent_group_rules r
    JOIN agent_groups g ON g.id = r.group_id
    ORDER BY g.name ASC, r.created_at ASC
  `).all();
  res.json(rules);
});

// ── List ──────────────────────────────────────────────────────────────────────

router.get('/', (_req, res) => {
  const groups = db.prepare(`
    SELECT g.*,
      COUNT(DISTINCT m.agent_id) AS member_count
    FROM agent_groups g
    LEFT JOIN agent_group_members m ON m.group_id = g.id
    GROUP BY g.id
    ORDER BY g.created_at DESC
  `).all();
  res.json(groups);
});

// ── Create ────────────────────────────────────────────────────────────────────

router.post('/', (req, res) => {
  const { name, description, owner, color_tag } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'name is required' });
  const color = PRESET_COLORS.includes(color_tag) ? color_tag : '#6366f1';
  const id = uuidv4();
  try {
    db.prepare(`INSERT INTO agent_groups (id,name,description,owner,color_tag) VALUES (?,?,?,?,?)`)
      .run(id, name.trim(), description || '', owner || '', color);
    res.status(201).json({ id });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: `Group named "${name}" already exists` });
    throw err;
  }
});

// ── Detail ────────────────────────────────────────────────────────────────────

router.get('/:id', (req, res) => {
  const group = db.prepare('SELECT * FROM agent_groups WHERE id = ?').get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Not found' });

  const members = db.prepare(`
    SELECT a.id, a.name, a.description, a.token_prefix, a.is_active,
           a.created_at, a.last_seen_at, m.joined_at, m.source, m.rule_id,
           r.name AS rule_name
    FROM agent_group_members m
    JOIN agents a ON a.id = m.agent_id
    LEFT JOIN agent_group_rules r ON r.id = m.rule_id
    WHERE m.group_id = ?
    ORDER BY m.joined_at DESC
  `).all(req.params.id);

  const rules = db.prepare(
    `SELECT * FROM agent_group_rules WHERE group_id = ? ORDER BY created_at ASC`
  ).all(req.params.id);

  res.json({ ...group, members, rules });
});

// ── Update ────────────────────────────────────────────────────────────────────

router.put('/:id', (req, res) => {
  const group = db.prepare('SELECT id FROM agent_groups WHERE id = ?').get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Not found' });

  const { name, description, owner, color_tag, is_active } = req.body;
  const cur = db.prepare('SELECT * FROM agent_groups WHERE id = ?').get(req.params.id);
  const color = color_tag !== undefined
    ? (PRESET_COLORS.includes(color_tag) ? color_tag : cur.color_tag)
    : cur.color_tag;

  try {
    db.prepare(`UPDATE agent_groups SET
      name=?, description=?, owner=?, color_tag=?, is_active=?
      WHERE id=?`).run(
      name        !== undefined ? String(name).trim() : cur.name,
      description !== undefined ? description          : cur.description,
      owner       !== undefined ? owner                : cur.owner,
      color,
      is_active   !== undefined ? (is_active ? 1 : 0) : cur.is_active,
      req.params.id
    );
    res.json({ ok: true });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: `Group named "${name}" already exists` });
    throw err;
  }
});

// ── Delete ────────────────────────────────────────────────────────────────────

router.delete('/:id', (req, res) => {
  db.prepare('DELETE FROM agent_groups WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── Members ───────────────────────────────────────────────────────────────────

router.post('/:id/members', (req, res) => {
  const group = db.prepare('SELECT id FROM agent_groups WHERE id = ?').get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  const { agent_id } = req.body;
  if (!agent_id) return res.status(400).json({ error: 'agent_id is required' });
  const agent = db.prepare('SELECT id FROM agents WHERE id = ?').get(agent_id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });

  try {
    db.prepare(`INSERT INTO agent_group_members (id,group_id,agent_id) VALUES (?,?,?)`)
      .run(uuidv4(), req.params.id, agent_id);
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Agent already in group' });
    throw err;
  }
});

router.delete('/:id/members/:agentId', (req, res) => {
  db.prepare('DELETE FROM agent_group_members WHERE group_id=? AND agent_id=?')
    .run(req.params.id, req.params.agentId);
  res.json({ ok: true });
});

// ── Rules ─────────────────────────────────────────────────────────────────────

router.get('/:id/rules', (req, res) => {
  const rules = db.prepare(
    `SELECT * FROM agent_group_rules WHERE group_id = ? ORDER BY created_at ASC`
  ).all(req.params.id);
  res.json(rules);
});

router.post('/:id/rules', (req, res) => {
  const group = db.prepare('SELECT id FROM agent_groups WHERE id = ?').get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  const { name, match_mode, conditions } = req.body;
  const mode = match_mode === 'any' ? 'any' : 'all';
  let conds = [];
  try { conds = Array.isArray(conditions) ? conditions : JSON.parse(conditions || '[]'); } catch {}
  // Validate operators
  conds = conds.filter(c => c.field && VALID_OPERATORS.includes(c.operator));

  const id = uuidv4();
  db.prepare(
    `INSERT INTO agent_group_rules (id, group_id, name, match_mode, conditions) VALUES (?, ?, ?, ?, ?)`
  ).run(id, req.params.id, name || '', mode, JSON.stringify(conds));

  // Auto-sync after adding a rule
  try { syncGroupRules(req.params.id); } catch {}

  res.status(201).json({ id });
});

router.put('/:id/rules/:ruleId', (req, res) => {
  const rule = db.prepare('SELECT id FROM agent_group_rules WHERE id = ? AND group_id = ?').get(req.params.ruleId, req.params.id);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });

  const { name, match_mode, conditions, is_active } = req.body;
  const cur = db.prepare('SELECT * FROM agent_group_rules WHERE id = ?').get(req.params.ruleId);

  let conds = cur.conditions;
  if (conditions !== undefined) {
    try {
      const parsed = Array.isArray(conditions) ? conditions : JSON.parse(conditions);
      conds = JSON.stringify(parsed.filter(c => c.field && VALID_OPERATORS.includes(c.operator)));
    } catch {}
  }

  db.prepare(`UPDATE agent_group_rules SET
    name=?, match_mode=?, conditions=?, is_active=? WHERE id=?`).run(
    name        !== undefined ? name : cur.name,
    match_mode  !== undefined ? (match_mode === 'any' ? 'any' : 'all') : cur.match_mode,
    conds,
    is_active   !== undefined ? (is_active ? 1 : 0) : cur.is_active,
    req.params.ruleId
  );

  // Re-sync after updating
  try { syncGroupRules(req.params.id); } catch {}
  res.json({ ok: true });
});

router.delete('/:id/rules/:ruleId', (req, res) => {
  db.prepare('DELETE FROM agent_group_rules WHERE id = ? AND group_id = ?').run(req.params.ruleId, req.params.id);
  // Re-sync: rule-sourced members from this rule should be removed
  try { syncGroupRules(req.params.id); } catch {}
  res.json({ ok: true });
});

// ── Manual sync ───────────────────────────────────────────────────────────────

router.post('/:id/sync', (req, res) => {
  const group = db.prepare('SELECT id FROM agent_groups WHERE id = ?').get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  try {
    syncGroupRules(req.params.id);
    const memberCount = db.prepare('SELECT COUNT(*) AS n FROM agent_group_members WHERE group_id = ?').get(req.params.id).n;
    res.json({ ok: true, member_count: memberCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
