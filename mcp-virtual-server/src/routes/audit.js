'use strict';

const express = require('express');
const db = require('../db/database');

const router = express.Router();

// GET /api/audit  — unified event log with filtering
router.get('/', (req, res) => {
  const {
    virtual_server_id,
    log_type,
    level,
    limit  = 100,
    offset = 0,
  } = req.query;

  const conditions   = [];
  const filterParams = [];

  if (virtual_server_id) { conditions.push('el.vs_id = ?');     filterParams.push(virtual_server_id); }
  if (log_type)          { conditions.push('el.log_type = ?');  filterParams.push(log_type); }
  if (level)             { conditions.push('el.level = ?');     filterParams.push(level); }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const entries = db.prepare(`
    SELECT el.*, vs.name AS virtual_server_name
    FROM event_log el
    LEFT JOIN virtual_servers vs ON vs.id = el.vs_id
    ${where}
    ORDER BY el.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...filterParams, parseInt(limit), parseInt(offset));

  entries.forEach((e) => {
    try {
      const d = JSON.parse(e.data || '{}');
      Object.assign(e, d);
    } catch {}
    delete e.data;
    if (!Array.isArray(e.user_scopes)) e.user_scopes = [];
    if (!Array.isArray(e.user_groups)) e.user_groups = [];
    if (!Array.isArray(e.categories))  e.categories  = [];
    if (!Array.isArray(e.pii_types))   e.pii_types   = [];
  });

  const totalRow = db.prepare(`
    SELECT COUNT(*) AS total FROM event_log el ${where}
  `).get(...filterParams);

  res.json({ total: totalRow.total, entries });
});

// GET /api/audit/stats  — counts by type and level
router.get('/stats', (req, res) => {
  const { virtual_server_id } = req.query;
  const where  = virtual_server_id ? 'WHERE vs_id = ?' : '';
  const params = virtual_server_id ? [virtual_server_id] : [];

  const stats = db.prepare(`
    SELECT
      COUNT(*)                                                       AS total,
      SUM(CASE WHEN level = 'info'                    THEN 1 ELSE 0 END) AS allowed,
      SUM(CASE WHEN level IN ('warn','block','error') THEN 1 ELSE 0 END) AS denied,
      SUM(CASE WHEN log_type = 'proxy_call'           THEN 1 ELSE 0 END) AS proxy_calls,
      SUM(CASE WHEN log_type = 'interceptor'          THEN 1 ELSE 0 END) AS interceptor_scans,
      SUM(CASE WHEN level = 'block'                   THEN 1 ELSE 0 END) AS blocked
    FROM event_log ${where}
  `).get(...params);

  res.json({ stats: { ...stats, unique_users: 0 } });
});

module.exports = router;
