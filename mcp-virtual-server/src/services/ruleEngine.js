'use strict';

const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');

// ── Condition evaluation ──────────────────────────────────────────────────────

function matchesCondition(metadata, condition) {
  const { field, operator, value } = condition;
  if (!field || !operator) return false;
  const raw = metadata[field];
  const metaStr = raw === undefined || raw === null ? '' : String(raw);
  const testVal = String(value || '');

  switch (operator) {
    case 'eq':         return metaStr === testVal;
    case 'ne':         return metaStr !== testVal;
    case 'contains':   return metaStr.includes(testVal);
    case 'startsWith': return metaStr.startsWith(testVal);
    case 'regex': {
      try { return new RegExp(testVal).test(metaStr); } catch { return false; }
    }
    default: return false;
  }
}

function agentMatchesRule(agentMetadata, rule) {
  let conditions = [];
  try { conditions = JSON.parse(rule.conditions || '[]'); } catch {}
  if (!conditions.length) return false;

  const results = conditions.map(c => matchesCondition(agentMetadata, c));
  return rule.match_mode === 'any' ? results.some(Boolean) : results.every(Boolean);
}

// ── Core sync logic ───────────────────────────────────────────────────────────

/**
 * Evaluate all active rules for ONE group against ALL agents.
 * - Adds agents that now match (source='rule')
 * - Removes rule-sourced agents that no longer match any rule
 * - Never removes manually-added agents
 */
function syncGroupRules(groupId) {
  const rules = db.prepare(
    `SELECT * FROM agent_group_rules WHERE group_id = ? AND is_active = 1`
  ).all(groupId);

  const agents = db.prepare(`SELECT id, metadata FROM agents`).all();

  for (const agent of agents) {
    let meta = {};
    try { meta = JSON.parse(agent.metadata || '{}'); } catch {}

    const matchingRule = rules.find(r => agentMatchesRule(meta, r));

    const existing = db.prepare(
      `SELECT id, source FROM agent_group_members WHERE group_id = ? AND agent_id = ?`
    ).get(groupId, agent.id);

    if (matchingRule) {
      if (!existing) {
        db.prepare(
          `INSERT INTO agent_group_members (id, group_id, agent_id, source, rule_id) VALUES (?, ?, ?, 'rule', ?)`
        ).run(uuidv4(), groupId, agent.id, matchingRule.id);
      } else if (existing.source === 'rule') {
        // Update which rule is responsible
        db.prepare(
          `UPDATE agent_group_members SET rule_id = ? WHERE id = ?`
        ).run(matchingRule.id, existing.id);
      }
      // If source='manual', leave it alone (don't change source, don't remove)
    } else {
      // Agent doesn't match — only remove if it was rule-added
      if (existing && existing.source === 'rule') {
        db.prepare(
          `DELETE FROM agent_group_members WHERE id = ?`
        ).run(existing.id);
      }
    }
  }
}

/**
 * Evaluate ALL groups' rules for ONE agent (called after agent create/update).
 * Re-evaluates every group that has at least one active rule.
 */
function evaluateAgentRules(agentId) {
  const agent = db.prepare(`SELECT id, metadata FROM agents WHERE id = ?`).get(agentId);
  if (!agent) return;

  let meta = {};
  try { meta = JSON.parse(agent.metadata || '{}'); } catch {}

  // Get all groups that have at least one active rule
  const groupIds = db.prepare(
    `SELECT DISTINCT group_id FROM agent_group_rules WHERE is_active = 1`
  ).all().map(r => r.group_id);

  for (const groupId of groupIds) {
    const rules = db.prepare(
      `SELECT * FROM agent_group_rules WHERE group_id = ? AND is_active = 1`
    ).all(groupId);

    const matchingRule = rules.find(r => agentMatchesRule(meta, r));

    const existing = db.prepare(
      `SELECT id, source FROM agent_group_members WHERE group_id = ? AND agent_id = ?`
    ).get(groupId, agentId);

    if (matchingRule) {
      if (!existing) {
        db.prepare(
          `INSERT INTO agent_group_members (id, group_id, agent_id, source, rule_id) VALUES (?, ?, ?, 'rule', ?)`
        ).run(uuidv4(), groupId, agentId, matchingRule.id);
      } else if (existing.source === 'rule') {
        db.prepare(
          `UPDATE agent_group_members SET rule_id = ? WHERE id = ?`
        ).run(matchingRule.id, existing.id);
      }
    } else {
      if (existing && existing.source === 'rule') {
        db.prepare(`DELETE FROM agent_group_members WHERE id = ?`).run(existing.id);
      }
    }
  }
}

module.exports = { syncGroupRules, evaluateAgentRules, agentMatchesRule };
