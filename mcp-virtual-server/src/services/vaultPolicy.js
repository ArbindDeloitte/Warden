'use strict';

const db = require('../db/database');
const { callerGroupIds } = require('./a2aPolicy');

function parseOps(raw) {
  try { const a = JSON.parse(raw || '["*"]'); return Array.isArray(a) && a.length ? a : ['*']; } catch { return ['*']; }
}

// Priority DESC; on a tie a forbid is consulted before a permit so it cannot be out-voted.
function listPolicies() {
  return db.prepare(`
    SELECT * FROM vault_policies WHERE is_active = 1
    ORDER BY priority DESC, CASE effect WHEN 'forbid' THEN 0 ELSE 1 END, created_at ASC
  `).all();
}

/** Single source of truth for whether one policy applies — shared by enforcement and the simulator. */
function matchPolicy(p, { agentId, groups, secretId, vsId, op }) {
  const callerOk = p.caller_type === 'any'
    || (p.caller_type === 'agent' && p.caller_value === agentId)
    || (p.caller_type === 'group' && groups.includes(p.caller_value));
  const secretOk = p.secret_id === '*' || p.secret_id === secretId;
  // A VS-scoped policy never matches a request that names no virtual server.
  const vsOk = !p.virtual_server_id || p.virtual_server_id === vsId;
  const ops = parseOps(p.operations);
  const opOk = ops.includes('*') || ops.includes(op);
  return { callerOk, secretOk, vsOk, opOk, ops, matched: callerOk && secretOk && vsOk && opOk };
}

/** Deny-by-default. The first matching policy decides. */
function evaluateVaultPolicy({ agentId, secretId, vsId = null, op }) {
  const groups = callerGroupIds(agentId);
  for (const p of listPolicies()) {
    if (!matchPolicy(p, { agentId, groups, secretId, vsId, op }).matched) continue;
    const permit = p.effect !== 'forbid';
    return {
      decision: permit ? 'allow' : 'deny',
      policy: p,
      reason: permit ? `Permitted by policy "${p.name}"` : `Forbidden by policy "${p.name}"`,
    };
  }
  return { decision: 'deny', policy: null, reason: 'No matching permit policy (deny by default)' };
}

/** Same decision plus a per-policy trace; policies after the deciding one are `reached: false`. */
function explainVaultPolicy({ agentId, secretId, vsId = null, op }) {
  const groups = callerGroupIds(agentId);
  const verdict = evaluateVaultPolicy({ agentId, secretId, vsId, op });
  let decided = false;
  const trace = listPolicies().map(p => {
    const m = matchPolicy(p, { agentId, groups, secretId, vsId, op });
    const reached = !decided;
    const decides = reached && m.matched;
    if (decides) decided = true;
    return {
      policyId: p.id, policyName: p.name, effect: p.effect, priority: p.priority,
      callerMatched: m.callerOk, secretMatched: m.secretOk, scopeMatched: m.vsOk, operationMatched: m.opOk,
      operations: m.ops, reached, decides,
    };
  });
  return { ...verdict, trace };
}

module.exports = { evaluateVaultPolicy, explainVaultPolicy, parseOps };
