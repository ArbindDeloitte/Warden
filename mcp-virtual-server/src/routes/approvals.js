'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { exchangeForOboToken } = require('../services/oboService');
const { callMcpTool } = require('../services/mcpClient');

const router = express.Router();

// ── List tickets (admin) ──────────────────────────────────────────────────────
// GET /api/approvals?status=pending&vs=...&limit=50
router.get('/', (req, res) => {
  const { status, vs, limit = 50 } = req.query;
  let sql = `SELECT * FROM approval_tickets WHERE 1=1`;
  const params = [];
  if (status) { sql += ` AND status = ?`; params.push(status); }
  if (vs)     { sql += ` AND virtual_server_id = ?`; params.push(vs); }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  params.push(Number(limit));
  const rows = db.prepare(sql).all(...params);
  res.json(rows.map(normalise));
});

// ── Pending count (for badge) ─────────────────────────────────────────────────
// GET /api/approvals/pending-count
router.get('/pending-count', (req, res) => {
  const { count } = db.prepare(
    `SELECT COUNT(*) AS count FROM approval_tickets WHERE status = 'pending'`
  ).get();
  res.json({ count });
});

// ── Ticket detail (admin) ─────────────────────────────────────────────────────
// GET /api/approvals/:id
router.get('/:id', (req, res) => {
  const ticket = db.prepare(`SELECT * FROM approval_tickets WHERE id = ?`).get(req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
  res.json(normalise(ticket));
});

// ── Poll endpoint (caller) ────────────────────────────────────────────────────
// GET /api/approvals/:id/status
// Returns lightweight status + result once executed.
router.get('/:id/status', (req, res) => {
  const ticket = db.prepare(`SELECT * FROM approval_tickets WHERE id = ?`).get(req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });

  const payload = {
    ticket_id:      ticket.id,
    status:         ticket.status,
    tool_name:      ticket.tool_name,
    expires_at:     ticket.expires_at,
    timeout_action: ticket.timeout_action,
    decided_at:     ticket.decided_at,
  };

  if (ticket.status === 'executed' && ticket.result) {
    payload.result = JSON.parse(ticket.result);
    return res.json(payload);
  }
  if (ticket.status === 'denied' || ticket.status === 'expired') {
    payload.error = ticket.status === 'denied'
      ? `Request denied by ${ticket.decided_by || 'admin'}`
      : `Approval timeout — auto-${ticket.timeout_action}d`;
    return res.status(403).json(payload);
  }
  if (ticket.status === 'approved') {
    // Execution in progress (async path); tell caller to keep polling
    payload.message = 'Approved — executing MCP call, check back shortly';
    return res.json(payload);
  }
  if (ticket.exec_error) {
    payload.error = ticket.exec_error;
    return res.status(502).json(payload);
  }

  // pending
  payload.message = 'Awaiting admin approval';
  return res.json(payload);
});

// ── Admin decision (approve / deny) ──────────────────────────────────────────
// POST /api/approvals/:id/decide
// Body: { action: 'approve'|'deny', decided_by?: string }
router.post('/:id/decide', async (req, res) => {
  const { id } = req.params;
  const { action, decided_by = 'admin' } = req.body;

  if (!['approve', 'deny'].includes(action)) {
    return res.status(400).json({ error: 'action must be "approve" or "deny"' });
  }

  const ticket = db.prepare(`SELECT * FROM approval_tickets WHERE id = ?`).get(id);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
  if (ticket.status !== 'pending') {
    return res.status(409).json({ error: `Ticket is already ${ticket.status}` });
  }

  const now = new Date().toISOString();

  if (action === 'deny') {
    db.prepare(`UPDATE approval_tickets SET status = 'denied', decided_by = ?, decided_at = ? WHERE id = ?`)
      .run(decided_by, now, id);
    return res.json({ ticket_id: id, status: 'denied' });
  }

  // Approve — mark then execute asynchronously so the HTTP response returns fast
  db.prepare(`UPDATE approval_tickets SET status = 'approved', decided_by = ?, decided_at = ? WHERE id = ?`)
    .run(decided_by, now, id);

  res.json({ ticket_id: id, status: 'approved', message: 'Executing MCP call…' });

  // Fire-and-forget execution (errors stored on ticket, caller sees via next poll)
  executeTicket(ticket).catch(err =>
    console.error(`[Approvals] Execution failed for ticket ${id}:`, err.message)
  );
});

// ── Internal helpers ──────────────────────────────────────────────────────────

async function executeTicket(ticket) {
  const now = new Date().toISOString();
  try {
    const virtualServer = db.prepare(
      `SELECT * FROM virtual_servers WHERE id = ?`
    ).get(ticket.virtual_server_id);
    if (!virtualServer) throw new Error('Virtual server not found');

    const toolAssignment = db.prepare(`
      SELECT vst.*, ms.url AS mcp_url, ms.auth_type, ms.auth_config
      FROM virtual_server_tools vst
      JOIN mcp_servers ms ON ms.id = vst.mcp_server_id
      WHERE vst.virtual_server_id = ? AND vst.mcp_server_id = ?
        AND (vst.tool_name = ? OR vst.tool_name = '*') AND ms.is_active = 1
    `).get(ticket.virtual_server_id, ticket.mcp_server_id, ticket.tool_name);
    if (!toolAssignment) throw new Error('Tool assignment not found');

    // Re-do OBO exchange with stored AT_A (leverages token cache)
    let oboToken;
    if (virtualServer.require_obo !== 0) {
      const oboResult = await exchangeForOboToken(ticket.user_token, virtualServer);
      oboToken = oboResult.token;
    } else {
      oboToken = ticket.user_token;
    }

    const mcpServer = {
      url: toolAssignment.mcp_url,
      auth_type: toolAssignment.auth_type,
      auth_config: toolAssignment.auth_config,
    };
    const toolArgs = JSON.parse(ticket.tool_arguments || '{}');
    const result = await callMcpTool(mcpServer, ticket.tool_name, toolArgs, oboToken);

    db.prepare(`
      UPDATE approval_tickets
      SET status = 'executed', result = ?, executed_at = ?
      WHERE id = ?
    `).run(JSON.stringify(result), now, ticket.id);

  } catch (err) {
    db.prepare(`
      UPDATE approval_tickets SET exec_error = ? WHERE id = ?
    `).run(err.message, ticket.id);
  }
}

// Parse JSON columns and add computed fields
function toUtcMs(iso) {
  if (!iso) return 0;
  // SQLite datetime('now') → "2024-01-01 12:00:00" (space sep, no Z).
  // Must replace space with T and append Z for reliable UTC parsing.
  if (iso.includes('Z') || iso.includes('+')) return new Date(iso).getTime();
  return new Date(iso.trim().replace(' ', 'T') + 'Z').getTime();
}

function normalise(t) {
  const now = Date.now();
  const expiresMs = toUtcMs(t.expires_at);
  return {
    ...t,
    tool_arguments: safeJson(t.tool_arguments, {}),
    user_groups:    safeJson(t.user_groups,    []),
    result:         safeJson(t.result,         null),
    time_remaining_seconds: t.status === 'pending' ? Math.max(0, Math.round((expiresMs - now) / 1000)) : 0,
  };
}

function safeJson(str, fallback) {
  try { return str ? JSON.parse(str) : fallback; } catch { return fallback; }
}

// ── Background expiry (called from app.js) ───────────────────────────────────
function processExpiredTickets() {
  const now = new Date().toISOString();
  const expired = db.prepare(
    `SELECT * FROM approval_tickets WHERE status = 'pending' AND expires_at <= ?`
  ).all(now);

  for (const ticket of expired) {
    if (ticket.timeout_action === 'approve') {
      // Mark approved, then execute
      db.prepare(`UPDATE approval_tickets SET status = 'approved', decided_by = 'system', decided_at = ? WHERE id = ?`)
        .run(now, ticket.id);
      executeTicket(ticket).catch(err =>
        console.error(`[Approvals] Auto-approve execution failed for ${ticket.id}:`, err.message)
      );
    } else {
      db.prepare(`UPDATE approval_tickets SET status = 'expired', decided_by = 'system', decided_at = ? WHERE id = ?`)
        .run(now, ticket.id);
    }
  }

  if (expired.length > 0) {
    console.log(`[Approvals] Processed ${expired.length} expired ticket(s)`);
  }
}

module.exports = router;
module.exports.processExpiredTickets = processExpiredTickets;
