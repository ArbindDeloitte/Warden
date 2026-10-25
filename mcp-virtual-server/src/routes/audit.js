const express = require('express');
const db = require('../db/database');

const router = express.Router();

// List audit log entries with filtering
router.get('/', (req, res) => {
  const {
    virtual_server_id,
    decision,
    user_sub,
    tool_name,
    limit = 100,
    offset = 0,
  } = req.query;

  const conditions = [];
  const filterParams = [];

  if (virtual_server_id) { conditions.push('al.virtual_server_id = ?'); filterParams.push(virtual_server_id); }
  if (decision) { conditions.push('al.decision = ?'); filterParams.push(decision); }
  if (user_sub) { conditions.push('al.user_sub = ?'); filterParams.push(user_sub); }
  if (tool_name) { conditions.push('al.tool_name = ?'); filterParams.push(tool_name); }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const entries = db.prepare(`
    SELECT al.*, vs.name AS virtual_server_name
    FROM audit_log al
    LEFT JOIN virtual_servers vs ON vs.id = al.virtual_server_id
    ${where}
    ORDER BY al.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...filterParams, parseInt(limit), parseInt(offset));

  entries.forEach((e) => {
    try { e.user_scopes = JSON.parse(e.user_scopes); } catch { e.user_scopes = []; }
    try { e.user_groups = JSON.parse(e.user_groups); } catch { e.user_groups = []; }
  });

  const totalRow = db.prepare(`
    SELECT COUNT(*) AS total FROM audit_log al ${where}
  `).get(...filterParams);

  res.json({ total: totalRow.total, entries });
});

// Stats summary
router.get('/stats', (req, res) => {
  const { virtual_server_id } = req.query;
  const where = virtual_server_id ? 'WHERE virtual_server_id = ?' : '';
  const params = virtual_server_id ? [virtual_server_id] : [];

  const stats = db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) AS allowed,
      SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) AS denied,
      COUNT(DISTINCT user_sub) AS unique_users,
      COUNT(DISTINCT tool_name) AS unique_tools
    FROM audit_log ${where}
  `).get(...params);

  const topTools = db.prepare(`
    SELECT tool_name, COUNT(*) AS calls, SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END) AS allowed
    FROM audit_log ${where}
    GROUP BY tool_name ORDER BY calls DESC LIMIT 10
  `).all(...params);

  const denyWhere = virtual_server_id ? 'WHERE virtual_server_id = ? AND decision = \'deny\'' : 'WHERE decision = \'deny\'';
  const recentDenies = db.prepare(`
    SELECT * FROM audit_log ${denyWhere}
    ORDER BY created_at DESC LIMIT 5
  `).all(...params);

  res.json({ stats, topTools, recentDenies });
});

module.exports = router;
