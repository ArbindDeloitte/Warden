const express = require('express');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { verifyToken } = require('../middleware/auth');
const { exchangeForOboToken } = require('../services/oboService');
const { callMcpTool } = require('../services/mcpClient');
const { prepareToolCall, redact, VaultError } = require('../services/vault');
const { evaluatePolicies } = require('../services/policyEngine');
const pipeline = require('../interceptors/InterceptorPipeline');
const { evaluateUserTriggers } = require('../services/triggerEvaluator');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const router = express.Router();

function decodeJwtPayload(token) {
  try {
    const raw = token.replace(/^Bearer\s+/i, '');
    const parts = raw.split('.');
    if (parts.length < 2) return null;
    const padded = parts[1] + '='.repeat((4 - parts[1].length % 4) % 4);
    return JSON.parse(Buffer.from(padded, 'base64url').toString('utf8'));
  } catch { return null; }
}

async function verifyJwtWithJwks(token, jwksUri) {
  const raw = token.replace(/^Bearer\s+/i, '');
  const client = jwksClient({ jwksUri, cache: true, cacheMaxEntries: 10, cacheMaxAge: 600000 });
  return new Promise((resolve, reject) => {
    jwt.verify(raw, (header, callback) => {
      client.getSigningKey(header.kid, (err, key) => {
        if (err) return callback(err);
        callback(null, key.getPublicKey());
      });
    }, { algorithms: ['RS256', 'ES256'] }, (err, decoded) => {
      if (err) return reject(err);
      resolve(decoded);
    });
  });
}

async function enforceIdpConnect(virtualServerId, userTokenHeader) {
  const configs = db.prepare(
    'SELECT * FROM vs_idp_configs WHERE virtual_server_id = ? AND is_active = 1'
  ).all(virtualServerId);

  if (!configs.length) {
    return { ok: false, error: 'IDP Connect is enabled but no trusted issuers are configured', hint: 'Add at least one IDP issuer in Warden → Virtual Servers → Edit.' };
  }

  if (!userTokenHeader) {
    return { ok: false, error: 'IDP Connect requires x-user-token header', hint: "Include the user's ID/access token in the x-user-token header." };
  }

  const rawToken = userTokenHeader.replace(/^Bearer\s+/i, '');
  const payload = decodeJwtPayload(rawToken);
  if (!payload || !payload.iss) {
    return { ok: false, error: 'Could not decode x-user-token — missing iss claim' };
  }

  const matched = configs.find(c => {
    if (payload.iss !== c.issuer) return false;
    if (c.audience && payload.aud) {
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!aud.includes(c.audience)) return false;
    }
    return true;
  });

  if (!matched) {
    return {
      ok: false,
      error: `Token issuer "${payload.iss}" is not in the trusted IDP list for this virtual server`,
      hint: 'The x-user-token must be issued by a trusted IDP configured in Warden.',
    };
  }

  if (matched.full_verification) {
    try {
      const jwksUri = matched.jwks_uri || `${matched.issuer.replace(/\/$/, '')}/v1/keys`;
      await verifyJwtWithJwks(rawToken, jwksUri);
    } catch (err) {
      return { ok: false, error: `IDP token signature verification failed: ${err.message}` };
    }
  }

  const user = {
    sub: payload.sub || null,
    email: payload.email || payload.preferred_username || null,
    name: payload.name || null,
    iss: payload.iss,
  };

  return { ok: true, user, configId: matched.id, configName: matched.name };
}

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
  // Unique ID linking the inbound + outbound interceptor events for this request
  const callId = uuidv4();

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

  // ── Agent identity resolution ──────────────────────────────────────────────
  // X-Agent-Token identifies the calling agent. Fails open by default;
  // if VS.require_agent_token is set, missing/invalid tokens get 401.
  let agentId   = null;
  let agentName = null;
  const agentTokenHeader = req.headers['x-agent-token'];
  if (agentTokenHeader) {
    const agentHash = crypto.createHash('sha256').update(agentTokenHeader).digest('hex');
    const agentRow  = db.prepare('SELECT id, name, is_active FROM agents WHERE token_hash = ?').get(agentHash);
    if (agentRow) {
      if (!agentRow.is_active) {
        done();
        return res.status(403).json({
          error: 'Agent is disabled',
          hint: `Agent "${agentRow.name}" has been deactivated. Re-enable it in the Warden Agent Hub before making calls.`,
        });
      }
      agentId   = agentRow.id;
      agentName = agentRow.name;
      try { db.prepare('UPDATE agents SET last_seen_at = ? WHERE id = ?').run(new Date().toISOString(), agentId); } catch {}
    }
  }
  if (virtualServer.require_agent_token) {
    if (!agentId) {
      done();
      return res.status(401).json({
        error: 'Agent identity required',
        hint: 'Include X-Agent-Token header with a registered Warden agent token.',
      });
    }
    // Check agent is in this VS's allowlist
    const allowed = db.prepare(
      'SELECT id FROM virtual_server_agents WHERE vs_id = ? AND agent_id = ?'
    ).get(virtualServer.id, agentId);
    if (!allowed) {
      done();
      return res.status(403).json({
        error: 'Agent not authorized for this virtual server',
        hint: `Agent "${agentName}" is registered but not in the allowlist for this virtual server. Add it via the Warden UI.`,
      });
    }
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

  // verifyToken reads the claims without checking the signature when the virtual server has no way to verify tokens
  // (no jwks_uri, no issuer, no JWKS_URI). Whoever calls could then put any sub / groups / scopes in a token they made
  // up, and those would feed the policy engine and the audit log. Unverified claims are therefore never used as an
  // identity: they are dropped here, and a virtual server that wants OBO but cannot verify the user is refused.
  const claimsVerified = req.tokenVerified !== false;
  if (!claimsVerified) {
    req.tokenClaims = {};
    if (virtualServer.require_obo !== 0) {
      done();
      writeAudit({
        virtualServerId, mcpServerId: mcp_server_id, toolName: tool_name,
        sub: null, jti: null, scopes: [], groups: [], decision: 'deny',
        reason: 'No identity provider configured: cannot verify the user token', payload: toolArgs, agentId, agentName,
      });
      return res.status(401).json({
        error: 'This virtual server cannot verify user tokens',
        code: 'no_idp_configured',
        hint: 'Set the issuer or jwks_uri on the virtual server (Edit Virtual Server), or turn off require_obo for an agent-only virtual server.',
      });
    }
  }

  // sub/groups come from AT_A (user identity — stable, doesn't change with OBO).
  // scopes intentionally NOT used for policy here; we re-evaluate after OBO so
  // Cedar sees the actual scopes on the token that will hit the MCP server (AT_B).
  const { sub, jti, groups } = req.tokenClaims || {};
  // Keep AT_A scopes only for audit trail — not for policy evaluation.
  const atAScopes = req.tokenClaims?.scopes || [];

  // Resolve which pipeline features are enabled for this virtual server.
  // Default all-on so existing VSes without the column keep working.
  const featuresRaw = virtualServer.features_enabled;
  let enabledFeatures;
  try { enabledFeatures = featuresRaw ? JSON.parse(featuresRaw) : ['interceptors', 'policy']; }
  catch { enabledFeatures = ['interceptors', 'policy']; }
  const featureOn = (f) => enabledFeatures.includes(f);

  // ── IDP Connect enforcement ────────────────────────────────────────────────
  let idpUser = null; // populated when IDP Connect is on and verification passes
  if (featureOn('idp_connect')) {
    try {
      // Prefer x-id-token (ID token with client aud) over x-user-token (access token for OBO)
      const idpTokenHeader = req.headers['x-id-token'] || req.headers['x-user-token'];
      const idpResult = await withDeadline(enforceIdpConnect(virtualServerId, idpTokenHeader));
      if (!idpResult.ok) {
        done();
        return res.status(401).json({ error: idpResult.error, hint: idpResult.hint });
      }
      if (idpResult.user) {
        idpUser = idpResult.user;
        try {
          db.prepare(`INSERT INTO event_log (id, vs_id, log_type, level, summary, data) VALUES (?,?,?,?,?,?)`)
            .run(uuidv4(), virtualServerId, 'idp_auth', 'info',
              `IDP verified: ${idpResult.user.email || idpResult.user.sub}`,
              JSON.stringify({ sub: idpResult.user.sub, email: idpResult.user.email, name: idpResult.user.name, iss: idpResult.user.iss, idp_config: idpResult.configName })
            );
        } catch {}
      }
    } catch (err) {
      if (err.silent) return;
      done();
      return res.status(401).json({ error: 'IDP Connect validation failed', detail: err.message });
    }
    lap('IDP Connect verified');
  }
  // ─────────────────────────────────────────────────────────────────────────

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
      payload: toolArgs, agentId, agentName,
    });
    return res.status(403).json({ error: 'Tool not permitted on this virtual server' });
  }

  // Inbound interceptor scan (before OBO — no token needed, scans arguments only)
  if (featureOn('interceptors')) {
    const inboundText = JSON.stringify(toolArgs || {});
    try {
      const inbound = await pipeline.run(inboundText, 'inbound', virtualServerId, agentId, callId, idpUser);
      if (inbound.action === 'block') {
        return res.status(403).json({ error: 'Request blocked by interceptor', reason: inbound.reason, intercepted: true });
      }
      // Fire Warden Function triggers after inbound scan (non-blocking)
      if (idpUser?.sub) {
        evaluateUserTriggers(virtualServerId, idpUser.sub, idpUser.email, idpUser.name).catch(() => {});
      }
    } catch (err) {
      console.warn('[Proxy] Inbound interceptor error (continuing):', err.message);
    }
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
  // With OBO off the forwarded token is the caller's own, so its scopes are only as good as its verification.
  const oboScopes = (virtualServer.require_obo !== 0 || claimsVerified) ? (oboClaims.scopes || []) : [];

  // Evaluate Cedar policies using AT_B scopes (accurate) + sub/groups from AT_A (identity).
  // When policy evaluation is disabled for this VS, auto-allow and skip Cedar entirely.
  let policyResult;
  if (featureOn('policy')) {
    const policies = db.prepare('SELECT * FROM policies WHERE virtual_server_id = ? AND is_active = 1').all(virtualServerId);
    policyResult = evaluatePolicies(policies, {
      mcpServerId: mcp_server_id,
      toolName: tool_name,
      scopes: oboScopes,
      groups: groups || [],
      sub: sub || '',
      agentName: agentName || '',
    });
  } else {
    policyResult = { decision: 'allow', reason: 'Policy evaluation disabled for this virtual server' };
  }

  writeAudit({
    virtualServerId, mcpServerId: mcp_server_id, toolName: tool_name,
    sub, jti, scopes: oboScopes, groups,
    decision: policyResult.decision,
    matchedPolicyId: policyResult.policyId,
    reason: policyResult.reason,
    payload: toolArgs, agentId, agentName,
  });

  if (policyResult.decision === 'approval') {
    const { ttl_minutes, timeout_action } = policyResult.approvalConfig;
    const ticketId = uuidv4();
    const expiresAt = new Date(Date.now() + ttl_minutes * 60 * 1000).toISOString();
    try {
      db.prepare(`
        INSERT INTO approval_tickets
          (id, virtual_server_id, mcp_server_id, tool_name, tool_arguments,
           user_sub, user_jti, user_groups, user_token, matched_policy_id,
           ttl_minutes, timeout_action, expires_at, agent_id, agent_name)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).run(
        ticketId, virtualServerId, mcp_server_id, tool_name,
        JSON.stringify(toolArgs || {}), sub || null, jti || null,
        JSON.stringify(groups || []), req.accessToken,
        policyResult.policyId, ttl_minutes, timeout_action, expiresAt,
        agentId, agentName
      );
    } catch (err) {
      console.error('[Proxy] Failed to create approval ticket:', err.message);
      done();
      return res.status(500).json({ error: 'Failed to queue approval ticket' });
    }
    done();
    return res.status(202).json({
      status: 'pending_approval',
      ticket_id: ticketId,
      poll_url: `/api/approvals/${ticketId}/status`,
      expires_at: expiresAt,
      timeout_action,
      message: `Tool call requires admin approval. Poll /api/approvals/${ticketId}/status for updates.`,
    });
  }

  if (policyResult.decision !== 'allow') {
    return res.status(403).json({
      error: 'Access denied by policy',
      reason: policyResult.reason,
    });
  }

  // Resolve vault:// references (tool arguments + upstream auth) now that policy has allowed the call.
  // This runs after the inbound scan on purpose: interceptors only ever see the placeholder, never the secret.
  const mcpServer = {
    url: toolAssignment.mcp_url,
    auth_type: toolAssignment.auth_type,
    auth_config: toolAssignment.auth_config,
  };
  let prepared;
  try {
    prepared = prepareToolCall({
      args: toolArgs || {}, mcpServer,
      ctx: { agentId, agentName, vsId: virtualServerId },
      hasObo: virtualServer.require_obo !== 0,
      vaultEnabled: virtualServer.vault_enabled !== 0,
    });
  } catch (err) {
    done();
    if (err instanceof VaultError) {
      return res.status(err.status).json({ error: 'Vault credential unavailable', reason: err.message, code: err.code });
    }
    throw err;
  }

  // Forward to MCP
  let result;
  try {
    result = await withDeadline(callMcpTool(mcpServer, tool_name, prepared.args, oboToken, prepared.extraHeaders));
    lap(`MCP call done (${tool_name})`);
  } catch (err) {
    done();
    if (err.silent) return; // deadline already sent the 504
    return res.status(502).json({ error: 'MCP call failed', detail: redact(err.message, prepared.injected) });
  }
  // Never let a brokered secret flow back to the agent, even if the upstream echoes it.
  result = redact(result, prepared.injected);

  // Outbound interceptor scan (before returning to caller)
  // Scan only the human-readable text content, not the raw JSON envelope.
  if (featureOn('interceptors')) {
    try {
      const textItems = extractMcpTextItems(result);
      if (textItems.length > 0) {
        const combinedText = textItems.map(t => t.text).join('\n\n---\n\n');
        const outbound = await pipeline.run(combinedText, 'outbound', virtualServerId, agentId, callId, idpUser);
        if (outbound.action === 'block') {
          done();
          return res.status(403).json({ error: 'Response blocked by interceptor', reason: outbound.reason, intercepted: true });
        }
        if (outbound.action === 'mask' && outbound.text !== combinedText) {
          const maskedResult = injectMcpTextItems(result, outbound.text, textItems);
          done();
          return res.json(maskedResult);
        }
      }
    } catch (err) {
      console.warn('[Proxy] Outbound interceptor error (continuing):', err.message);
    }
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

function writeAudit({ virtualServerId, mcpServerId, toolName, sub, jti, scopes, groups, decision, matchedPolicyId, reason, payload, agentId, agentName }) {
  try {
    const level = decision === 'deny' ? 'warn'
      : decision === 'block'    ? 'block'
      : decision === 'error'    ? 'error'
      : 'info';

    const summary = `${toolName || '?'} → ${decision}${agentName ? ` (${agentName})` : ''}`;

    const data = JSON.stringify({
      tool_name:         toolName || null,
      decision,
      mcp_server_id:     mcpServerId || null,
      matched_policy_id: matchedPolicyId || null,
      reason:            reason || null,
      user_sub:          sub || null,
      user_token_jti:    jti || null,
      user_scopes:       scopes || [],
      user_groups:       groups || [],
      agent_id:          agentId || null,
      agent_name:        agentName || null,
      request_payload:   payload || null,
    });

    db.prepare(`
      INSERT INTO event_log (id, vs_id, log_type, level, summary, data)
      VALUES (?, ?, 'proxy_call', ?, ?, ?)
    `).run(uuidv4(), virtualServerId || null, level, summary, data);
  } catch (err) {
    console.error('[Audit] Failed to write audit log:', err.message);
  }
}

module.exports = router;
