/**
 * Cedar-compatible policy engine.
 *
 * Policy JSON structure:
 * {
 *   "effect": "permit" | "forbid",
 *   "priority": 0,
 *   "actions": [
 *     { "mcp_server_id": "*" | "server-id", "tool": "*" | "toolName" }
 *   ],
 *   "conditions": [
 *     { "type": "scope_contains", "value": "banking:read" },
 *     { "type": "scope_contains_any", "values": ["read", "admin"] },
 *     { "type": "group_contains", "value": "bank-employees" },
 *     { "type": "group_contains_any", "values": ["admins", "super-users"] },
 *     { "type": "sub_equals", "value": "user@example.com" }
 *   ]
 * }
 *
 * Evaluation:
 * - Deny-overrides: any active 'forbid' with priority >= permit denies.
 * - If no permit matches → deny by default (default-deny).
 * - Forbid with higher or equal priority to any matching permit → deny.
 */

function evaluatePolicies(policies, context) {
  const { mcpServerId, toolName, scopes, groups, sub } = context;

  const activePolicies = policies
    .filter((p) => p.is_active)
    .sort((a, b) => (b.priority || 0) - (a.priority || 0));

  let matchedPermit   = null;
  let matchedApproval = null;
  let matchedForbid   = null;

  for (const policy of activePolicies) {
    let policyDef;
    try {
      policyDef = typeof policy.policy_json === 'string'
        ? JSON.parse(policy.policy_json)
        : policy.policy_json;
    } catch {
      continue;
    }

    if (!matchesAction(policyDef, mcpServerId, toolName)) continue;
    if (!matchesConditions(policyDef.conditions || [], scopes, groups, sub)) continue;

    if (policy.effect === 'forbid' && !matchedForbid) {
      matchedForbid = policy;
    } else if (policy.effect === 'approval' && !matchedApproval) {
      matchedApproval = { policy, policyDef };
    } else if (policy.effect === 'permit' && !matchedPermit) {
      matchedPermit = policy;
    }
  }

  // Forbid at priority >= best positive match always wins
  const bestPositivePriority = Math.max(
    matchedPermit   ? (matchedPermit.priority   || 0) : -1,
    matchedApproval ? (matchedApproval.policy.priority || 0) : -1,
  );
  if (matchedForbid && (matchedForbid.priority || 0) >= bestPositivePriority) {
    return { decision: 'deny', policyId: matchedForbid.id, reason: `Denied by policy "${matchedForbid.name}"` };
  }

  // Between permit and approval, higher priority wins
  if (matchedPermit && matchedApproval) {
    if ((matchedPermit.priority || 0) >= (matchedApproval.policy.priority || 0)) {
      return { decision: 'allow', policyId: matchedPermit.id, reason: `Permitted by policy "${matchedPermit.name}"` };
    }
  }

  if (matchedApproval) {
    const cfg = matchedApproval.policyDef.approval_config || {};
    return {
      decision: 'approval',
      policyId: matchedApproval.policy.id,
      reason: `Approval required by policy "${matchedApproval.policy.name}"`,
      approvalConfig: {
        ttl_minutes:    typeof cfg.ttl_minutes    === 'number' ? cfg.ttl_minutes    : 30,
        timeout_action: cfg.timeout_action === 'approve' ? 'approve' : 'deny',
      },
    };
  }

  if (matchedPermit) {
    return { decision: 'allow', policyId: matchedPermit.id, reason: `Permitted by policy "${matchedPermit.name}"` };
  }

  return { decision: 'deny', policyId: null, reason: 'No matching permit policy (default deny)' };
}

function matchesAction(policyDef, mcpServerId, toolName) {
  const actions = policyDef.actions;
  if (!actions || actions.length === 0) return true; // No action filter = match all

  return actions.some((action) => {
    const serverMatch = action.mcp_server_id === '*' || action.mcp_server_id === mcpServerId;
    const toolMatch = action.tool === '*' || action.tool === toolName;
    return serverMatch && toolMatch;
  });
}

function matchesConditions(conditions, scopes, groups, sub) {
  return conditions.every((cond) => evaluateCondition(cond, scopes, groups, sub));
}

function evaluateCondition(cond, scopes, groups, sub) {
  switch (cond.type) {
    case 'scope_contains':
      return scopes.includes(cond.value);

    case 'scope_contains_any':
      return (cond.values || []).some((v) => scopes.includes(v));

    case 'scope_contains_all':
      return (cond.values || []).every((v) => scopes.includes(v));

    case 'group_contains':
      return groups.includes(cond.value);

    case 'group_contains_any':
      return (cond.values || []).some((v) => groups.includes(v));

    case 'group_contains_all':
      return (cond.values || []).every((v) => groups.includes(v));

    case 'sub_equals':
      return sub === cond.value;

    case 'sub_in':
      return (cond.values || []).includes(sub);

    case 'not_scope_contains':
      return !scopes.includes(cond.value);

    case 'not_group_contains':
      return !groups.includes(cond.value);

    default:
      console.warn('[PolicyEngine] Unknown condition type:', cond.type);
      return false;
  }
}

/**
 * Simulate policy evaluation without actually making the call.
 * Returns detailed trace of which policies matched/didn't match and why.
 */
function simulatePolicies(policies, context) {
  const { mcpServerId, toolName, scopes, groups, sub } = context;

  const activePolicies = policies.filter((p) => p.is_active);
  const trace = [];

  for (const policy of activePolicies) {
    let policyDef;
    try {
      policyDef = typeof policy.policy_json === 'string'
        ? JSON.parse(policy.policy_json)
        : policy.policy_json;
    } catch {
      trace.push({ policy: policy.name, matched: false, reason: 'Invalid JSON' });
      continue;
    }

    const actionMatched = matchesAction(policyDef, mcpServerId, toolName);
    const conditionResults = (policyDef.conditions || []).map((cond) => ({
      condition: cond,
      passed: evaluateCondition(cond, scopes, groups, sub),
    }));
    const allConditionsPassed = conditionResults.every((r) => r.passed);

    trace.push({
      policyId: policy.id,
      policyName: policy.name,
      effect: policy.effect,
      priority: policy.priority,
      actionMatched,
      conditionResults,
      matched: actionMatched && allConditionsPassed,
    });
  }

  const result = evaluatePolicies(policies, context);
  return { ...result, trace };
}

module.exports = { evaluatePolicies, simulatePolicies };
