const express = require('express');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { verifyToken } = require('../middleware/auth');
const { exchangeForOboToken } = require('../services/oboService');
const { callMcpTool } = require('../services/mcpClient');
const { evaluatePolicies } = require('../services/policyEngine');
const pipeline = require('../interceptors/InterceptorPipeline');

const router = express.Router();

/**
 * GET /api/proxy/:virtualServerId/timing?token=<user_token>
 * Diagnostic: measures each step without executing the MCP tool.
 */
router.get('/:virtualServerId/timing', async (req, res) => {
  const { virtualServerId } = req.params;
  const report = [];
  const t0 = Date.now();
  const lap = (label, extra = '') => {
    report.push({ step: label, ms: Date.now() - t0, extra });
    console.log(`[Timing] ${label} +${Date.now() - t0}ms ${extra}`);
  };

  const virtualServer = db.prepare('SELECT * FROM virtual_servers WHERE id = ? AND is_active = 1').get(virtualServerId);
  if (!virtualServer) return res.status(404).json({ error: 'VS not found' });
  lap('VS loaded');

  req.virtualServer = virtualServer;

  // JWT verify
  try {
    await Promise.race([
      new Promise((resolve, reject) => {
        verifyToken(req, res, (err) => { if (err) reject(err); else resolve(); });
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('JWT timeout')), 8000)
      ),
    ]);
    lap('JWT verified', `verified=${req.tokenVerified}`);
  } catch (err) {
    lap('JWT FAILED', err.message);
    return res.json({ report, error: 'JWT failed: ' + err.message });
  }

  // OBO exchange
  let oboToken;
  if (virtualServer.require_obo !== 0) {
    try {
      const oboResult = await exchangeForOboToken(req.accessToken, virtualServer);
      oboToken = oboResult.token;
      lap('OBO exchange', `fromCache=${oboResult.fromCache}`);
    } catch (err) {
      lap('OBO FAILED', err.message);
      return res.json({ report, error: 'OBO failed: ' + err.message });
    }
  } else {
    oboToken = req.accessToken;
    lap('OBO skipped (require_obo=0)');
  }

  return res.json({ report, oboAudience: (() => { try { return JSON.parse(Buffer.from(oboToken.split('.')[1], 'base64').toString()).aud; } catch { return 'decode-failed'; } })() });
});

/**
 * POST /api/proxy/:virtualServerId
 *
 * Body: { mcp_server_id, tool_name, arguments }
 * Headers: Authorization: Bearer <user_access_token>
 *
 * Flow:
 * 1. Load virtual server config
 * 2. Verify user's access token
 * 3. Check tool is allowed on this virtual server
 * 4. Evaluate Cedar-style policies
 * 5. Perform OBO exchange (with cache)
 * 6. Forward call to MCP server
 * 7. Return result + write audit log
 */
router.post('/:virtualServerId', async (req, res) => {
  const { virtualServerId } = req.params;
  const { mcp_server_id, tool_name, arguments: toolArgs } = req.body;
  const t0 = Date.now();
  const lap = (label) => console.log(`[Proxy] ${label} +${Date.now() - t0}ms`);

  // Hard 20-second deadline — sends a 504 and stops the flow if anything hangs
  let _deadlineTimer;
  const deadline = new Promise((_, reject) => {
    _deadlineTimer = setTimeout(() => {
      if (!res.headersSent) {
        res.status(504).json({ error: 'Proxy timeout', detail: `Exceeded 20 s processing ${tool_name}` });
      }
      reject(Object.assign(new Error('Proxy deadline exceeded'), { silent: true }));
    }, 20000);
  });
  const withDeadline = (p) => Promise.race([p, deadline]);
  const done = () => clearTimeout(_deadlineTimer);

  if (!mcp_server_id || !tool_name) {
    return res.status(400).json({ error: 'mcp_server_id and tool_name are required' });
  }

  // Load virtual server
  const virtualServer = db.prepare('SELECT * FROM virtual_servers WHERE id = ? AND is_active = 1').get(virtualServerId);
  if (!virtualServer) {
    return res.status(404).json({ error: 'Virtual server not found or inactive' });
  }

  // ── API key enforcement ───────────────────────────────────────────────────
  // If this VS has any active, non-expired API keys, callers must supply one.
  const now = new Date().toISOString();
  const vsActiveKeys = db.prepare(`
    SELECT * FROM api_keys WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > ?)
  `).all(now).filter(k => {
    const list = JSON.parse(k.virtual_server_ids || '[]');
    return list.length === 0 || list.includes(virtualServerId);
  });

  if (vsActiveKeys.length > 0) {
    const provided = req.headers['x-api-key'];
    if (!provided) {
      return res.status(401).json({
        error: 'X-API-Key header required',
        hint: 'This virtual server is protected by API keys. Generate one in Warden → Keys.',
      });
    }
    const hash = crypto.createHash('sha256').update(provided).digest('hex');
    const matched = vsActiveKeys.find(k => k.key_hash === hash);
    if (!matched) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    // Non-blocking last-used update
    try { db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now, matched.id); } catch {}
  }
  // ─────────────────────────────────────────────────────────────────────────

  // Attach for auth middleware
  req.virtualServer = virtualServer;

  // Verify incoming token — race against 8 s inner guard + 20 s overall deadline
  try {
    await withDeadline(Promise.race([
      new Promise((resolve, reject) => {
        verifyToken(req, res, (err) => { if (err) reject(err); else resolve(); });
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(Object.assign(new Error('JWT verification timed out'), { status: 504 })), 8000)
      ),
    ]));
  } catch (err) {
    done();
    if (err.silent) return; // deadline already sent the response
    if (!res.headersSent) {
      return res.status(err.status || 401).json({ error: err.message });
    }
    return;
  }
  lap('JWT verified');

  // If res was already sent (auth failed mid-verify), stop here
  if (res.headersSent) return;

  // sub/groups come from AT_A (user identity — stable, doesn't change with OBO).
  // scopes intentionally NOT used for policy here; we re-evaluate after OBO so
  // Cedar sees the actual scopes on the token that will hit the MCP server (AT_B).
  const { sub, jti, groups } = req.tokenClaims || {};
  // Keep AT_A scopes only for audit trail — not for policy evaluation.
  const atAScopes = req.tokenClaims?.scopes || [];

  // Check if the tool is assigned to this virtual server
  const toolAssignment = db.prepare(`
    SELECT vst.*, ms.url AS mcp_url, ms.name AS mcp_name,
           ms.auth_type, ms.auth_config
    FROM virtual_server_tools vst
    JOIN mcp_servers ms ON ms.id = vst.mcp_server_id
    WHERE vst.virtual_server_id = ?
      AND vst.mcp_server_id = ?
      AND (vst.tool_name = ? OR vst.tool_name = '*')
      AND ms.is_active = 1
  `).get(virtualServerId, mcp_server_id, tool_name);

  if (!toolAssignment) {
    writeAudit({
      virtualServerId, mcpServerId: mcp_server_id, toolName: tool_name,
      sub, jti, scopes: atAScopes, groups, decision: 'deny', reason: 'Tool not assigned to this virtual server',
      payload: toolArgs,
    });
    return res.status(403).json({ error: 'Tool not permitted on this virtual server' });
  }

  // Inbound interceptor scan (before OBO — no token needed, scans arguments only)
  const inboundText = JSON.stringify(toolArgs || {});
  try {
    const inbound = await pipeline.run(inboundText, 'inbound', virtualServerId);
    if (inbound.action === 'block') {
      return res.status(403).json({ error: 'Request blocked by interceptor', reason: inbound.reason, intercepted: true });
    }
  } catch (err) {
    console.warn('[Proxy] Inbound interceptor error (continuing):', err.message);
  }

  // OBO exchange (skipped when virtual server has require_obo = 0).
  // Must happen BEFORE Cedar policy evaluation so policies run against AT_B's
  // actual scopes, not AT_A's. Okta may downscope the OBO token, so evaluating
  // Cedar against AT_A scopes would give a false pass for scopes AT_B doesn't hold.
  let oboToken;
  if (virtualServer.require_obo !== 0) {
    try {
      const oboResult = await withDeadline(exchangeForOboToken(req.accessToken, virtualServer));
      oboToken = oboResult.token;
      lap(`OBO exchange (fromCache=${oboResult.fromCache})`);
    } catch (err) {
      done();
      if (err.silent) return; // deadline already sent the 504
      return res.status(502).json({ error: 'OBO token exchange failed', detail: err.message });
    }
  } else {
    // Direct proxy mode — forward with original user token
    oboToken = req.accessToken;
  }

  // Decode AT_B to extract the scopes that will actually reach the MCP server.
  const { extractTokenClaims } = require('../services/oboService');
  const oboClaims = extractTokenClaims(oboToken);
  const oboScopes = oboClaims.scopes || [];

  // Evaluate Cedar policies using AT_B scopes (accurate) + sub/groups from AT_A (identity).
  // This ensures a scope-based policy cannot pass when Okta has downscoped the OBO token.
  const policies = db.prepare('SELECT * FROM policies WHERE virtual_server_id = ? AND is_active = 1').all(virtualServerId);
  const policyResult = evaluatePolicies(policies, {
    mcpServerId: mcp_server_id,
    toolName: tool_name,
    scopes: oboScopes,
    groups: groups || [],
    sub: sub || '',
  });

  writeAudit({
    virtualServerId, mcpServerId: mcp_server_id, toolName: tool_name,
    sub, jti, scopes: oboScopes, groups,
    decision: policyResult.decision,
    matchedPolicyId: policyResult.policyId,
    reason: policyResult.reason,
    payload: toolArgs,
  });

  if (policyResult.decision !== 'allow') {
    return res.status(403).json({
      error: 'Access denied by policy',
      reason: policyResult.reason,
    });
  }

  // Forward to MCP
  let result;
  try {
    const mcpServer = {
      url: toolAssignment.mcp_url,
      auth_type: toolAssignment.auth_type,
      auth_config: toolAssignment.auth_config,
    };
    result = await withDeadline(callMcpTool(mcpServer, tool_name, toolArgs || {}, oboToken));
    lap(`MCP call done (${tool_name})`);
  } catch (err) {
    done();
    if (err.silent) return; // deadline already sent the 504
    return res.status(502).json({ error: 'MCP call failed', detail: err.message });
  }

  // Outbound interceptor scan (before returning to caller)
  // Scan only the human-readable text content, not the raw JSON envelope.
  // Masking raw JSON corrupts the structure when replacements land inside
  // JSON string values or span structural characters.
  try {
    const textItems = extractMcpTextItems(result);
    if (textItems.length > 0) {
      const combinedText = textItems.map(t => t.text).join('\n\n---\n\n');
      const outbound = await pipeline.run(combinedText, 'outbound', virtualServerId);
      if (outbound.action === 'block') {
        done();
        return res.status(403).json({ error: 'Response blocked by interceptor', reason: outbound.reason, intercepted: true });
      }
      if (outbound.action === 'mask' && outbound.text !== combinedText) {
        // Distribute masked text back into individual content items
        const maskedResult = injectMcpTextItems(result, outbound.text, textItems);
        done();
        return res.json(maskedResult);
      }
    }
  } catch (err) {
    console.warn('[Proxy] Outbound interceptor error (continuing):', err.message);
  }

  done();
  return res.json(result);
});

/**
 * Pull { index, text } for every text-type content item out of an MCP result.
 * Works for both { result: { content: [...] } } and { content: [...] } shapes.
 */
function extractMcpTextItems(result) {
  const content = result?.result?.content ?? result?.content ?? [];
  return content
    .map((item, index) => ({ index, text: item?.text ?? '' }))
    .filter(item => typeof item.text === 'string' && item.text.length > 0);
}

/**
 * Put masked text back into the result, distributing it across the original
 * content items using the same separator that was used to join them.
 */
function injectMcpTextItems(result, maskedCombined, originalItems) {
  const SEP = '\n\n---\n\n';
  const parts = maskedCombined.split(SEP);
  const contentSource = result?.result?.content ?? result?.content ?? [];
  const newContent = contentSource.map((item, idx) => {
    const slot = originalItems.findIndex(t => t.index === idx);
    if (slot === -1 || !parts[slot]) return item;
    return { ...item, text: parts[slot] };
  });
  if (result?.result?.content) {
    return { ...result, result: { ...result.result, content: newContent } };
  }
  return { ...result, content: newContent };
}

function writeAudit({ virtualServerId, mcpServerId, toolName, sub, jti, scopes, groups, decision, matchedPolicyId, reason, payload }) {
  try {
    db.prepare(`
      INSERT INTO audit_log
        (id, virtual_server_id, mcp_server_id, tool_name, user_sub, user_token_jti,
         user_scopes, user_groups, decision, matched_policy_id, reason, request_payload)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      uuidv4(), virtualServerId, mcpServerId, toolName, sub || null, jti || null,
      JSON.stringify(scopes || []), JSON.stringify(groups || []),
      decision, matchedPolicyId || null, reason || null,
      payload ? JSON.stringify(payload) : null
    );
  } catch (err) {
    console.error('[Audit] Failed to write audit log:', err.message);
  }
}

module.exports = router;
