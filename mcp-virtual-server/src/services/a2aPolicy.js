'use strict';

const db = require('../db/database');

function callerGroupIds(agentId) {
  return db.prepare(`
    SELECT m.group_id FROM agent_group_members m
    JOIN agent_groups g ON g.id = m.group_id
    WHERE m.agent_id = ? AND g.is_active = 1
  `).all(agentId).map(r => r.group_id);
}

function parseSkills(raw) {
  try { const a = JSON.parse(raw || '["*"]'); return Array.isArray(a) && a.length ? a : ['*']; } catch { return ['*']; }
}

function listPolicies(vsId) {
  return db.prepare(
    'SELECT * FROM a2a_policies WHERE virtual_server_id = ? AND is_active = 1 ORDER BY priority DESC, created_at ASC'
  ).all(vsId);
}

/**
 * Single source of truth for whether one policy applies to a request. Used by both the
 * enforcing evaluator and the simulator's trace, so the two cannot drift apart.
 * Skill handling is conservative: a skill-restricted FORBID also matches when the
 * request names no skill (so omitting the skill can't dodge a forbid), while a
 * skill-restricted PERMIT does not.
 * anySkill=true is for follow-up methods (GetTask/CancelTask/...), which cannot name a skill:
 * a skill-restricted PERMIT still applies (the caller may continue work it was allowed to start),
 * but a skill-restricted FORBID does not (it would otherwise block every follow-up call from
 * everyone). Forbidden skills can't be initiated in the first place, and task ownership already
 * limits who can touch a task.
 */
function matchPolicy(p, { callerId, targetId, skill, anySkill = false, groups }) {
  const callerOk = p.caller_type === 'any'
    || (p.caller_type === 'agent' && p.caller_value === callerId)
    || (p.caller_type === 'group' && groups.includes(p.caller_value));
  const targetOk = p.target_type === 'any' || (p.target_type === 'agent' && p.target_value === targetId);
  const skills = parseSkills(p.skills);
  const skillOk = skills.includes('*')
    || (anySkill ? p.effect === 'permit' : (skill ? skills.includes(skill) : p.effect === 'forbid'));
  return { callerOk, targetOk, skillOk, matched: callerOk && targetOk && skillOk, skills };
}

/** Deny-by-default. Policies are evaluated by priority (desc); the first match decides. */
function evaluateA2aPolicy({ vsId, callerId, targetId, skill, anySkill = false }) {
  const groups = callerGroupIds(callerId);

  for (const p of listPolicies(vsId)) {
    if (!matchPolicy(p, { callerId, targetId, skill, anySkill, groups }).matched) continue;
    return {
      decision: p.effect === 'forbid' ? 'deny' : 'allow',
      policy: p,
      reason: p.effect === 'forbid' ? `Forbidden by policy "${p.name}"` : `Permitted by policy "${p.name}"`,
    };
  }
  return { decision: 'deny', policy: null, reason: 'No matching permit policy (deny by default)' };
}

/**
 * Same decision as evaluateA2aPolicy, plus a per-policy trace for the simulator.
 * Every active policy is listed in evaluation order: policies after the deciding one are
 * marked `reached: false` (first match wins, so they were never consulted).
 */
function explainA2aPolicy({ vsId, callerId, targetId, skill }) {
  const groups = callerGroupIds(callerId);
  const verdict = evaluateA2aPolicy({ vsId, callerId, targetId, skill });
  let decided = false;
  const trace = listPolicies(vsId).map(p => {
    const m = matchPolicy(p, { callerId, targetId, skill, groups });
    const reached = !decided;
    const decides = reached && m.matched;
    if (decides) decided = true;
    return {
      policyId: p.id, policyName: p.name, effect: p.effect, priority: p.priority,
      callerType: p.caller_type, targetType: p.target_type, skills: m.skills,
      callerMatched: m.callerOk, targetMatched: m.targetOk, skillMatched: m.skillOk,
      reached, decides,
    };
  });
  return { ...verdict, trace };
}

module.exports = { evaluateA2aPolicy, explainA2aPolicy };
