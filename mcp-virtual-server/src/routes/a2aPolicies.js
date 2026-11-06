'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { explainA2aPolicy } = require('../services/a2aPolicy');

const router = express.Router();

const pick = (v, allowed, dflt) => (allowed.includes(v) ? v : dflt);

function normalise(b, cur = {}) {
  const callerType = pick(b.caller_type ?? cur.caller_type, ['any', 'agent', 'group'], 'any');
  const targetType = pick(b.target_type ?? cur.target_type, ['any', 'agent'], 'any');
  let skills = b.skills ?? (cur.skills ? JSON.parse(cur.skills) : ['*']);
  if (typeof skills === 'string') skills = skills.split(',').map(s => s.trim()).filter(Boolean);
  if (!Array.isArray(skills) || !skills.length) skills = ['*'];
  return {
    name: String(b.name ?? cur.name ?? '').trim(),
    effect: pick(b.effect ?? cur.effect, ['permit', 'forbid'], 'permit'),
    priority: Number.isFinite(Number(b.priority ?? cur.priority)) ? Number(b.priority ?? cur.priority) : 0,
    caller_type: callerType,
    caller_value: callerType === 'any' ? '*' : String(b.caller_value ?? cur.caller_value ?? ''),
    target_type: targetType,
    target_value: targetType === 'any' ? '*' : String(b.target_value ?? cur.target_value ?? ''),
    skills: JSON.stringify(skills),
    require_user: (b.require_user ?? cur.require_user) ? 1 : 0,
    user_fail_mode: pick(b.user_fail_mode ?? cur.user_fail_mode, ['closed', 'open'], 'closed'),
    is_active: (b.is_active ?? cur.is_active ?? 1) ? 1 : 0,
  };
}

function validate(p) {
  if (!p.name) return 'name is required';
  if (p.caller_type !== 'any' && !p.caller_value) return 'caller_value is required for agent/group callers';
  if (p.target_type !== 'any' && !p.target_value) return 'target_value is required for agent targets';
  return null;
}

// Resolves ids to names so the UI can render rules without extra calls.
const LIST_SQL = `
  SELECT p.*, vs.name AS virtual_server_name,
    CASE p.caller_type WHEN 'agent' THEN (SELECT name FROM agents WHERE id = p.caller_value)
                       WHEN 'group' THEN (SELECT name FROM agent_groups WHERE id = p.caller_value) END AS caller_name,
    CASE p.target_type WHEN 'agent' THEN (SELECT name FROM a2a_agents WHERE id = p.target_value) END AS target_name
  FROM a2a_policies p JOIN virtual_servers vs ON vs.id = p.virtual_server_id`;

const out = (r) => ({ ...r, skills: JSON.parse(r.skills || '["*"]') });

router.get('/', (req, res) => {
  const rows = req.query.virtual_server_id
    ? db.prepare(`${LIST_SQL} WHERE p.virtual_server_id = ? ORDER BY p.priority DESC, p.created_at`).all(req.query.virtual_server_id)
    : db.prepare(`${LIST_SQL} ORDER BY vs.name, p.priority DESC, p.created_at`).all();
  res.json(rows.map(out));
});

router.post('/', (req, res) => {
  const vsId = req.body.virtual_server_id;
  if (!vsId || !db.prepare('SELECT id FROM virtual_servers WHERE id = ?').get(vsId))
    return res.status(400).json({ error: 'valid virtual_server_id is required' });
  const p = normalise(req.body);
  const bad = validate(p);
  if (bad) return res.status(400).json({ error: bad });
  const id = uuidv4();
  db.prepare(`INSERT INTO a2a_policies (id,virtual_server_id,name,effect,priority,caller_type,caller_value,target_type,target_value,skills,require_user,user_fail_mode,is_active)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(id, vsId, p.name, p.effect, p.priority, p.caller_type, p.caller_value, p.target_type, p.target_value, p.skills, p.require_user, p.user_fail_mode, p.is_active);
  res.status(201).json({ id });
});

router.put('/:id', (req, res) => {
  const cur = db.prepare('SELECT * FROM a2a_policies WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'Policy not found' });
  const p = normalise(req.body, cur);
  const bad = validate(p);
  if (bad) return res.status(400).json({ error: bad });
  db.prepare(`UPDATE a2a_policies SET name=?,effect=?,priority=?,caller_type=?,caller_value=?,target_type=?,target_value=?,skills=?,require_user=?,user_fail_mode=?,is_active=? WHERE id=?`)
    .run(p.name, p.effect, p.priority, p.caller_type, p.caller_value, p.target_type, p.target_value, p.skills, p.require_user, p.user_fail_mode, p.is_active, cur.id);
  res.json({ ok: true });
});

router.delete('/:id', (req, res) => {
  db.prepare('DELETE FROM a2a_policies WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Dry-run: would this caller be allowed to call this target (with this skill)?
// Dry run of the gateway's authorisation stages (policy, then the user-token requirement).
// `user_status` simulates the caller's X-User-Token: absent | verified | invalid (fails
// verification) | idp_down (identity provider unreachable). Defaults to absent.
router.post('/simulate', (req, res) => {
  const { virtual_server_id, caller_agent_id, target_agent_id } = req.body;
  const skill = req.body.skill ? String(req.body.skill).trim() : undefined;
  const userStatus = pick(req.body.user_status, ['absent', 'verified', 'invalid', 'idp_down'], 'absent');
  if (!virtual_server_id || !caller_agent_id || !target_agent_id)
    return res.status(400).json({ error: 'virtual_server_id, caller_agent_id and target_agent_id are required' });

  const v = explainA2aPolicy({ vsId: virtual_server_id, callerId: caller_agent_id, targetId: target_agent_id, skill });
  const p = v.policy;
  let decision = v.decision, reason = v.reason;

  // Mirrors the gateway: a matched permit that requires a user token still needs one that verifies,
  // unless the policy fails open and the only problem is an unreachable identity provider.
  const userCheck = { required: !!(p && p.require_user), status: userStatus, outcome: 'not_required', fail_mode: p?.user_fail_mode || null };
  if (v.decision === 'allow' && p?.require_user) {
    if (userStatus === 'verified') userCheck.outcome = 'passed';
    else if (p.user_fail_mode === 'open' && userStatus === 'idp_down') userCheck.outcome = 'degraded';
    else {
      userCheck.outcome = 'denied';
      decision = 'deny';
      reason = userStatus === 'absent' ? 'User token required by policy' : 'User token could not be verified';
    }
  } else if (v.decision !== 'allow') userCheck.outcome = 'skipped';

  const caller = db.prepare('SELECT id, name FROM agents WHERE id = ?').get(caller_agent_id);
  const target = db.prepare('SELECT id, name FROM a2a_agents WHERE id = ?').get(target_agent_id);
  const groups = db.prepare(`
    SELECT g.name FROM agent_group_members m JOIN agent_groups g ON g.id = m.group_id
    WHERE m.agent_id = ? AND g.is_active = 1 ORDER BY g.name
  `).all(caller_agent_id).map(r => r.name);

  res.json({
    decision, reason, policy_id: p?.id || null,
    skill: skill || null, caller: { ...caller, groups }, target,
    user_check: userCheck, trace: v.trace,
  });
});

module.exports = router;
