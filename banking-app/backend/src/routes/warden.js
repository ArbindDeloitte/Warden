import express from 'express';
import { GatewayConfigError, WardenUpstreamError } from '../services/wardenGateway.js';
import { WardenVaultError } from '../services/wardenVault.js';

const ID_RE = /^[A-Za-z0-9_.:-]{1,100}$/;
const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Authenticated relay between the browser and Warden. Only the caller's Okta token is accepted from the
// browser; Warden credentials are added server-side and never appear in a request or response.
export function createWardenRouter({ gateway, authMiddleware }) {
  const router = express.Router();
  router.use(authMiddleware);

  const userToken = (req) => String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const bad = (res, error) => res.status(400).json({ success: false, error });

  function fail(res, err, next) {
    if (err instanceof GatewayConfigError) return res.status(503).json({ success: false, error: err.message });
    if (err instanceof WardenVaultError) {
      console.error('[Warden relay] vault error:', err.message);
      return res.status(502).json({ success: false, error: 'Could not obtain Warden credentials from the vault', detail: err.message });
    }
    if (err instanceof WardenUpstreamError) return res.status(502).json({ success: false, error: err.message });
    return next(err);
  }

  router.get('/config', (_req, res) => res.json(gateway.describe()));

  // Body: { tool_name, arguments }. Responds with Warden's status and body unchanged (including the
  // 202 pending_approval ticket), so the frontend handles it exactly as when it called Warden directly.
  router.post('/tool', async (req, res, next) => {
    const { tool_name: toolName, arguments: args = {} } = req.body || {};
    if (typeof toolName !== 'string' || !ID_RE.test(toolName)) return bad(res, 'tool_name is required');
    if (!isPlainObject(args)) return bad(res, 'arguments must be an object');
    try {
      const idToken = req.headers['x-id-token'];
      const { status, body } = await gateway.callTool({
        userToken: userToken(req), idToken: typeof idToken === 'string' ? idToken.replace(/^Bearer\s+/i, '') : null, toolName, args,
      });
      res.status(status).json(body);
    } catch (err) { fail(res, err, next); }
  });

  // Chat message scan. Body: { text, direction?: 'inbound'|'outbound', agent?: 'mcp'|'a2a' }. Responds with Warden's
  // scan result ({ action, text, reason, ... }) unchanged.
  router.post('/scan', async (req, res, next) => {
    const { text, direction = 'inbound', agent = 'mcp' } = req.body || {};
    if (typeof text !== 'string' || !text.trim() || text.length > 10000) return bad(res, 'text is required (max 10000 characters)');
    if (!['inbound', 'outbound'].includes(direction)) return bad(res, 'direction must be inbound or outbound');
    if (!['mcp', 'a2a'].includes(agent)) return bad(res, 'agent must be mcp or a2a');
    try {
      const idToken = req.headers['x-id-token'];
      const { status, body } = await gateway.scan({
        idToken: typeof idToken === 'string' ? idToken.replace(/^Bearer\s+/i, '') : null, text, direction, agent,
      });
      res.status(status).json(body);
    } catch (err) { fail(res, err, next); }
  });

  // Status of an approval ticket the chat is waiting on. ?kind=mcp|a2a says which agent made the call.
  router.get('/approvals/:id/status', async (req, res, next) => {
    const kind = req.query.kind === 'a2a' ? 'a2a' : 'mcp';
    if (!/^[A-Za-z0-9_-]{8,64}$/.test(req.params.id)) return bad(res, 'invalid ticket id');
    try {
      const { status, body } = await gateway.approvalStatus({ ticketId: req.params.id, agent: kind });
      res.status(status).json(body);
    } catch (err) { fail(res, err, next); }
  });

  // Body: { question, skillId?, contextId? }. Responds with Warden's raw JSON-RPC response.
  router.post('/a2a', async (req, res, next) => {
    const { question, skillId, contextId } = req.body || {};
    if (typeof question !== 'string' || !question.trim() || question.length > 10000) return bad(res, 'question is required (max 10000 characters)');
    if (skillId !== undefined && !(typeof skillId === 'string' && ID_RE.test(skillId))) return bad(res, 'skillId is invalid');
    if (contextId !== undefined && !(typeof contextId === 'string' && ID_RE.test(contextId))) return bad(res, 'contextId is invalid');
    try {
      const { status, body } = await gateway.sendA2A({ userToken: userToken(req), question, skillId, contextId });
      res.status(status).json(body);
    } catch (err) { fail(res, err, next); }
  });

  return router;
}
