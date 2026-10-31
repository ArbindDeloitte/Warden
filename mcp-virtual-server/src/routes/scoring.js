'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');

const router = express.Router();

// ── Default scoring configuration ────────────────────────────────────────────
const DEFAULT_CONFIG = {
  time_window_days: 7,
  only_outbound: true,
  points: {
    clean_call:        5,   // proxy call that passed all checks
    clean_scan:        2,   // interceptor scan that found nothing
    policy_deny:      -15,
    interceptor_block: -30,
    pii_flag:         -10,
    injection_flag:   -20,
  },
};

const USER_DEFAULT_CONFIG = {
  only_inbound: true,
  time_window_days: 7,
  points: {
    clean_scan:        2,
    pii_flag:         -10,
    injection_flag:   -20,
    interceptor_block: -30,
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function getTier(score) {
  if (score >= 800) return { name: 'Trusted',   color: '#10b981', bg: 'rgba(16,185,129,.12)',  border: 'rgba(16,185,129,.3)'  };
  if (score >= 500) return { name: 'Monitored', color: '#f59e0b', bg: 'rgba(245,158,11,.12)',  border: 'rgba(245,158,11,.3)'  };
  if (score >= 200) return { name: 'At Risk',   color: '#f97316', bg: 'rgba(249,115,22,.12)',  border: 'rgba(249,115,22,.3)'  };
  return               { name: 'Critical',  color: '#ef4444', bg: 'rgba(239,68,68,.12)',   border: 'rgba(239,68,68,.3)'   };
}

function loadConfig(entityType, entityId) {
  const row = db.prepare(
    'SELECT mode, config_json FROM scoring_configs WHERE entity_type = ? AND entity_id = ?'
  ).get(entityType, entityId);

  if (!row || row.mode === 'default') return { mode: 'default', ...DEFAULT_CONFIG, reset_at: null };

  let cfg = {};
  try { cfg = JSON.parse(row.config_json || '{}'); } catch {}

  return {
    mode: 'custom',
    time_window_days: typeof cfg.time_window_days === 'number' ? cfg.time_window_days : DEFAULT_CONFIG.time_window_days,
    only_outbound: typeof cfg.only_outbound === 'boolean' ? cfg.only_outbound : DEFAULT_CONFIG.only_outbound,
    reset_at: cfg.reset_at || null,
    points: { ...DEFAULT_CONFIG.points, ...(cfg.points || {}) },
  };
}

const USER_GLOBAL_ID = '__users_global__';

function loadUserConfig() {
  const row = db.prepare(
    'SELECT * FROM scoring_configs WHERE entity_type = ? AND entity_id = ?'
  ).get('user', USER_GLOBAL_ID);
  if (!row || row.mode === 'default') return { mode: 'default', ...USER_DEFAULT_CONFIG, reset_at: null };
  try {
    const cfg = JSON.parse(row.config_json || '{}');
    return {
      mode: 'custom',
      time_window_days: typeof cfg.time_window_days === 'number' ? cfg.time_window_days : USER_DEFAULT_CONFIG.time_window_days,
      only_inbound:     typeof cfg.only_inbound === 'boolean'    ? cfg.only_inbound    : USER_DEFAULT_CONFIG.only_inbound,
      reset_at:         cfg.reset_at || null,
      points:           { ...USER_DEFAULT_CONFIG.points, ...(cfg.points || {}) },
    };
  } catch {
    return { mode: 'default', ...USER_DEFAULT_CONFIG, reset_at: null };
  }
}

function computeUserScore(userId, config, vsId = null) {
  const windowMs    = (config.time_window_days || 7) * 86400 * 1000;
  const windowStart = new Date(Date.now() - windowMs).toISOString();
  let since = windowStart;
  if (config.reset_at && config.reset_at > since) since = config.reset_at;

  const pts = { ...USER_DEFAULT_CONFIG.points, ...(config.points || {}) };

  let sql = `
    SELECT
      json_extract(data, '$.direction')    AS direction,
      json_extract(data, '$.flagged')      AS flagged,
      json_extract(data, '$.action_taken') AS action_taken,
      json_extract(data, '$.categories')   AS categories_json
    FROM event_log
    WHERE log_type = 'interceptor'
      AND json_extract(data, '$.user_sub') = ?
      AND created_at >= ?
  `;
  const params = [userId, since];
  if (vsId) { sql += ' AND vs_id = ?'; params.push(vsId); }

  let events = db.prepare(sql).all(...params);

  if (config.only_inbound) {
    events = events.filter(e => e.direction === 'inbound');
  }

  let score = 500;
  const breakdown = { clean_scans: 0, pii_flags: 0, injection_flags: 0, blocks: 0 };

  for (const e of events) {
    const flagged = e.flagged === 1 || e.flagged === '1';
    const action  = e.action_taken || 'allow';
    let cats = [];
    try { cats = JSON.parse(e.categories_json || '[]'); } catch {}

    if (!flagged) {
      score += pts.clean_scan;
      breakdown.clean_scans++;
    } else if (action === 'block') {
      const isInjection = cats.some(c => c === 'prompt_injection' || c === 'injection' || c === 'unsafe');
      score += isInjection ? pts.injection_flag : pts.interceptor_block;
      isInjection ? breakdown.injection_flags++ : breakdown.blocks++;
    } else {
      const isInjection = cats.some(c => c === 'prompt_injection' || c === 'injection' || c === 'unsafe');
      score += isInjection ? pts.injection_flag : pts.pii_flag;
      isInjection ? breakdown.injection_flags++ : breakdown.pii_flags++;
    }
  }

  score = Math.max(0, Math.min(1000, Math.round(score)));
  return { score, tier: getTier(score), event_count: events.length, breakdown };
}

function computeScore(entityType, entityId, config) {
  const windowDays = config.time_window_days;
  const weights    = config.points;

  // SQLite datetime strings are UTC ISO-like; keep as prefix for BETWEEN comparison
  let since = new Date(Date.now() - windowDays * 86400000).toISOString().replace('T', ' ').slice(0, 19);
  // If the score was reset more recently than the window start, use the reset timestamp
  if (config.reset_at && config.reset_at > since) since = config.reset_at;

  // ── Proxy call events ───────────────────────────────────────────────────────
  // Only count proxy calls from VSes that have interceptors enabled — calls
  // that route through a policy-only VS (e.g. banking-vs) are excluded.
  let proxyCalls;
  if (entityType === 'vs') {
    proxyCalls = db.prepare(
      `SELECT level, data FROM event_log el
       JOIN virtual_servers vs ON vs.id = el.vs_id
       WHERE el.log_type='proxy_call' AND el.vs_id=? AND el.created_at>=?
         AND vs.features_enabled LIKE '%"interceptors"%'`
    ).all(entityId, since);
  } else {
    // Agent: filter by agent_id embedded in the JSON data blob, only interceptor-enabled VSes
    proxyCalls = db.prepare(
      `SELECT el.level, el.data FROM event_log el
       LEFT JOIN virtual_servers vs ON vs.id = el.vs_id
       WHERE el.log_type='proxy_call' AND el.created_at>=? AND json_extract(el.data,'$.agent_id')=?
         AND (el.vs_id IS NULL OR vs.features_enabled LIKE '%"interceptors"%' OR vs.features_enabled IS NULL)`
    ).all(since, entityId);
  }

  // ── Interceptor events ────────────────────────────────────────────────────────
  // VS: filter by vs_id.  Agent: filter by agent_id stored in the JSON data blob.
  const interceptorEvents = entityType === 'vs'
    ? db.prepare(
        `SELECT data FROM event_log WHERE log_type='interceptor' AND vs_id=? AND created_at>=?`
      ).all(entityId, since)
    : db.prepare(
        `SELECT data FROM event_log WHERE log_type='interceptor' AND created_at>=? AND json_extract(data,'$.agent_id')=?`
      ).all(since, entityId);

  const breakdown = {
    total_proxy:       proxyCalls.length,
    total_interceptor: interceptorEvents.length,
    clean_calls:       0,
    policy_denials:    0,
    interceptor_blocks: 0,
    pii_flags:         0,
    injection_flags:   0,
  };

  // No activity → neutral 500
  if (!proxyCalls.length && !interceptorEvents.length) {
    return { score: 500, tier: getTier(500), breakdown, window_days: windowDays, neutral: true, config };
  }

  let delta = 0;

  for (const row of proxyCalls) {
    let data = {};
    try { data = JSON.parse(row.data || '{}'); } catch {}
    const isAllow = data.decision === 'allow' || row.level === 'info';
    if (isAllow) {
      delta += weights.clean_call;
      breakdown.clean_calls++;
    } else {
      delta += weights.policy_deny;
      breakdown.policy_denials++;
    }
  }

  let parsedEvents = interceptorEvents.map(row => {
    try { return JSON.parse(row.data || '{}'); } catch { return {}; }
  });

  // When only_outbound is on, ignore inbound scans entirely — user-initiated
  // messages shouldn't penalise or reward the entity being scored.
  if (config.only_outbound) {
    parsedEvents = parsedEvents.filter(e => e.direction === 'outbound');
  }
  breakdown.total_interceptor = parsedEvents.length;

  // Score each interceptor event independently
  for (const data of parsedEvents) {
    if (!data.flagged) {
      delta += weights.clean_scan ?? 2;
      breakdown.clean_scans = (breakdown.clean_scans || 0) + 1;
      continue;
    }
    const cats  = Array.isArray(data.categories) ? data.categories : [];
    const isPii = cats.some(c => ['pii', 'privacy'].includes(c));
    const isInj = cats.some(c => ['prompt_injection', 'injection', 'unsafe'].includes(c));
    if (data.action_taken === 'block') { delta += weights.interceptor_block; breakdown.interceptor_blocks++; }
    if (isPii) { delta += weights.pii_flag;       breakdown.pii_flags++;       }
    if (isInj) { delta += weights.injection_flag; breakdown.injection_flags++;  }
  }

  const score = Math.max(0, Math.min(1000, 500 + delta));
  return { score, tier: getTier(score), breakdown, window_days: windowDays, neutral: false, config };
}

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /api/scoring/vs  — all VSes (proxy call events from policy enforcement also contribute to scores)
router.get('/vs', (req, res) => {
  const allServers = db.prepare('SELECT id, name, is_active, features_enabled FROM virtual_servers ORDER BY created_at DESC').all();
  const results = allServers.map(vs => {
    let features;
    try { features = JSON.parse(vs.features_enabled || '["interceptors","policy"]'); }
    catch { features = ['interceptors', 'policy']; }
    const interceptors_enabled = features.includes('interceptors');

    const config = loadConfig('vs', vs.id);
    if (!interceptors_enabled) {
      return { id: vs.id, name: vs.name, is_active: vs.is_active, interceptors_enabled: false, score: null, tier: null, breakdown: null, neutral: true, config };
    }
    const { score, tier, breakdown, neutral } = computeScore('vs', vs.id, config);
    return { id: vs.id, name: vs.name, is_active: vs.is_active, interceptors_enabled: true, score, tier, breakdown, neutral, config };
  });
  res.json(results);
});

// GET /api/scoring/vs/:id
router.get('/vs/:id', (req, res) => {
  const vs = db.prepare('SELECT id, name, is_active FROM virtual_servers WHERE id = ?').get(req.params.id);
  if (!vs) return res.status(404).json({ error: 'Virtual server not found' });
  const config = loadConfig('vs', vs.id);
  res.json({ ...vs, ...computeScore('vs', vs.id, config) });
});

// GET /api/scoring/agents  — all agents with computed scores
router.get('/agents', (req, res) => {
  const agents = db.prepare('SELECT id, name, is_active, token_prefix FROM agents ORDER BY created_at DESC').all();
  const results = agents.map(a => {
    const config = loadConfig('agent', a.id);
    const { score, tier, breakdown, neutral } = computeScore('agent', a.id, config);
    return { id: a.id, name: a.name, is_active: a.is_active, token_prefix: a.token_prefix, score, tier, breakdown, neutral, config };
  });
  res.json(results);
});

// GET /api/scoring/agents/:id
router.get('/agents/:id', (req, res) => {
  const a = db.prepare('SELECT id, name, is_active, token_prefix FROM agents WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).json({ error: 'Agent not found' });
  const config = loadConfig('agent', a.id);
  res.json({ ...a, ...computeScore('agent', a.id, config) });
});

// PUT /api/scoring/:type/:id/config  — save scoring config for a VS or agent
router.put('/:type/:id/config', (req, res) => {
  const { type, id } = req.params;
  if (!['vs', 'agent'].includes(type)) return res.status(400).json({ error: 'type must be vs or agent' });

  const { mode, time_window_days, points, only_outbound } = req.body;
  if (!['default', 'custom'].includes(mode)) return res.status(400).json({ error: 'mode must be default or custom' });

  // Preserve reset_at if already stored — config saves must not wipe it
  const existing = db.prepare('SELECT id, config_json FROM scoring_configs WHERE entity_type=? AND entity_id=?').get(type, id);
  let preservedResetAt = null;
  if (existing) {
    try { preservedResetAt = JSON.parse(existing.config_json || '{}').reset_at || null; } catch {}
  }

  const configJson = JSON.stringify({ time_window_days, points, only_outbound: !!only_outbound, reset_at: preservedResetAt });

  if (existing) {
    db.prepare(`UPDATE scoring_configs SET mode=?, config_json=?, updated_at=datetime('now') WHERE entity_type=? AND entity_id=?`)
      .run(mode, configJson, type, id);
  } else {
    db.prepare('INSERT INTO scoring_configs (id, entity_type, entity_id, mode, config_json) VALUES (?,?,?,?,?)')
      .run(uuidv4(), type, id, mode, configJson);
  }
  res.json({ ok: true });
});

// POST /api/scoring/:type/:id/reset  — reset score to neutral by advancing the event window start
router.post('/:type/:id/reset', (req, res) => {
  const { type, id } = req.params;
  if (!['vs', 'agent'].includes(type)) return res.status(400).json({ error: 'type must be vs or agent' });

  const resetAt = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const existing = db.prepare('SELECT id, config_json FROM scoring_configs WHERE entity_type=? AND entity_id=?').get(type, id);

  if (existing) {
    let cfg = {};
    try { cfg = JSON.parse(existing.config_json || '{}'); } catch {}
    cfg.reset_at = resetAt;
    db.prepare(`UPDATE scoring_configs SET config_json=?, mode='custom', updated_at=datetime('now') WHERE entity_type=? AND entity_id=?`)
      .run(JSON.stringify(cfg), type, id);
  } else {
    db.prepare('INSERT INTO scoring_configs (id, entity_type, entity_id, mode, config_json) VALUES (?,?,?,?,?)')
      .run(uuidv4(), type, id, 'custom', JSON.stringify({ reset_at: resetAt }));
  }
  res.json({ ok: true, reset_at: resetAt });
});

// GET /api/scoring/defaults  — return the default weights for UI display
router.get('/defaults', (_req, res) => res.json(DEFAULT_CONFIG));

// ── User scoring routes (global config, per-user scores) ──────────────────────

// GET /api/scoring/users/idp-vs  — virtual servers with IDP Connect enabled
router.get('/users/idp-vs', (_req, res) => {
  const rows = db.prepare(
    `SELECT id, name FROM virtual_servers WHERE is_active = 1 AND features_enabled LIKE '%"idp_connect"%' ORDER BY name`
  ).all();
  res.json(rows);
});

// GET /api/scoring/users/:sub/events  — recent interceptor events for one user
router.get('/users/:sub/events', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const vsId  = req.query.vs_id || null;
  const sub   = decodeURIComponent(req.params.sub);

  let sql = `
    SELECT id, vs_id, created_at, data,
           (SELECT name FROM virtual_servers WHERE id = event_log.vs_id) AS vs_name
    FROM event_log
    WHERE log_type = 'interceptor'
      AND json_extract(data, '$.user_sub') = ?
  `;
  const params = [sub];
  if (vsId) { sql += ' AND vs_id = ?'; params.push(vsId); }
  sql += ' ORDER BY created_at DESC LIMIT ?';
  params.push(limit);

  const rows = db.prepare(sql).all(...params).map(r => {
    const d = (() => { try { return JSON.parse(r.data || '{}'); } catch { return {}; } })();
    return {
      id:         r.id,
      vs_id:      r.vs_id,
      vs_name:    r.vs_name || null,
      created_at: r.created_at,
      direction:  d.direction  || null,
      flagged:    d.flagged    === 1 || d.flagged === '1',
      action:     d.action_taken || 'allow',
      categories: Array.isArray(d.categories) ? d.categories : [],
      score:      d.score || 0,
    };
  });
  res.json(rows);
});

// GET /api/scoring/users  — all users scored against the GLOBAL user config
router.get('/users', (req, res) => {
  const config = loadUserConfig();
  const vsId   = req.query.vs_id || null;

  let sql = `
    SELECT DISTINCT
      json_extract(data, '$.user_sub')   AS user_sub,
      json_extract(data, '$.user_email') AS user_email,
      json_extract(data, '$.user_name')  AS user_name,
      MAX(created_at) AS last_seen
    FROM event_log
    WHERE log_type = 'interceptor'
      AND json_extract(data, '$.user_sub') IS NOT NULL
  `;
  const params = [];
  if (vsId) { sql += ' AND vs_id = ?'; params.push(vsId); }
  sql += ' GROUP BY json_extract(data, \'$.user_sub\') ORDER BY last_seen DESC';

  const users = db.prepare(sql).all(...params);

  const result = users.map(u => {
    const computed = computeUserScore(u.user_sub, config, vsId);
    return { ...u, ...computed };
  });
  res.json({ config, users: result });
});

// GET /api/scoring/users/config  — global user scoring config
router.get('/users/config', (_req, res) => {
  res.json(loadUserConfig());
});

// POST /api/scoring/users/config/reset  — reset all user scores (advance reset_at to now)
router.post('/users/config/reset', (req, res) => {
  const resetAt = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const existing = db.prepare('SELECT id, config_json FROM scoring_configs WHERE entity_type=? AND entity_id=?').get('user', USER_GLOBAL_ID);
  if (existing) {
    let cfg = {};
    try { cfg = JSON.parse(existing.config_json || '{}'); } catch {}
    cfg.reset_at = resetAt;
    db.prepare(`UPDATE scoring_configs SET config_json=?, mode='custom', updated_at=datetime('now') WHERE entity_type=? AND entity_id=?`)
      .run(JSON.stringify(cfg), 'user', USER_GLOBAL_ID);
  } else {
    db.prepare('INSERT INTO scoring_configs (id, entity_type, entity_id, mode, config_json) VALUES (?,?,?,?,?)')
      .run(uuidv4(), 'user', USER_GLOBAL_ID, 'custom', JSON.stringify({ reset_at: resetAt }));
  }
  res.json({ ok: true, reset_at: resetAt });
});

// PUT /api/scoring/users/config  — save global user scoring config
router.put('/users/config', (req, res) => {
  const { mode, time_window_days, points, only_inbound } = req.body;
  if (!['default', 'custom'].includes(mode)) return res.status(400).json({ error: 'mode must be default or custom' });

  const existing = db.prepare(
    'SELECT id, config_json FROM scoring_configs WHERE entity_type=? AND entity_id=?'
  ).get('user', USER_GLOBAL_ID);
  let preservedResetAt = null;
  if (existing) {
    try { preservedResetAt = JSON.parse(existing.config_json || '{}').reset_at || null; } catch {}
  }

  const configJson = JSON.stringify({ time_window_days, points, only_inbound: !!only_inbound, reset_at: preservedResetAt });

  if (existing) {
    db.prepare(`UPDATE scoring_configs SET mode=?, config_json=?, updated_at=datetime('now') WHERE entity_type=? AND entity_id=?`)
      .run(mode, configJson, 'user', USER_GLOBAL_ID);
  } else {
    db.prepare('INSERT INTO scoring_configs (id, entity_type, entity_id, mode, config_json) VALUES (?,?,?,?,?)')
      .run(uuidv4(), 'user', USER_GLOBAL_ID, mode, configJson);
  }
  res.json({ ok: true });
});

// ── Score History ─────────────────────────────────────────────────────────────
// GET /api/scoring/history?entity_type=vs|agent&entity_id=xxx&limit=200
// Returns individual scored events newest-first with their point delta.
router.get('/history', (req, res) => {
  const { entity_type, entity_id } = req.query;
  const limit = Math.min(parseInt(req.query.limit) || 200, 1000);

  let sql = `
    SELECT el.id, el.vs_id, el.log_type, el.level, el.summary, el.data, el.created_at,
           vs.name AS vs_name
    FROM event_log el
    LEFT JOIN virtual_servers vs ON vs.id = el.vs_id
    WHERE el.log_type IN ('proxy_call','interceptor')
      AND (
        el.vs_id IS NULL
        OR vs.features_enabled LIKE '%"interceptors"%'
        OR vs.features_enabled IS NULL
      )
  `;
  const params = [];

  const isUserQuery = entity_type === 'user';

  if (entity_type === 'vs' && entity_id) {
    sql += ' AND el.vs_id = ?';
    params.push(entity_id);
  } else if (entity_type === 'vs') {
    sql += ' AND el.vs_id IS NOT NULL';
  } else if (entity_type === 'agent' && entity_id) {
    sql += " AND json_extract(el.data,'$.agent_id') = ?";
    params.push(entity_id);
  } else if (entity_type === 'agent') {
    sql += " AND json_extract(el.data,'$.agent_id') IS NOT NULL";
  } else if (entity_type === 'user' && entity_id) {
    sql += " AND el.log_type = 'interceptor' AND json_extract(el.data,'$.user_sub') = ?";
    params.push(decodeURIComponent(entity_id));
  } else if (entity_type === 'user') {
    sql += " AND el.log_type = 'interceptor' AND json_extract(el.data,'$.user_sub') IS NOT NULL";
  }

  sql += ' ORDER BY el.created_at DESC LIMIT ?';
  params.push(limit);

  const rows = db.prepare(sql).all(...params);

  // Resolve agent names in one query
  const agentIds = [...new Set(
    rows.map(r => { try { return JSON.parse(r.data || '{}').agent_id; } catch { return null; } }).filter(Boolean)
  )];
  const agentMap = agentIds.length
    ? Object.fromEntries(
        db.prepare(`SELECT id, name FROM agents WHERE id IN (${agentIds.map(() => '?').join(',')})`)
          .all(...agentIds).map(a => [a.id, a.name])
      )
    : {};

  const weights = isUserQuery
    ? { ...USER_DEFAULT_CONFIG.points, ...(loadUserConfig().points || {}) }
    : DEFAULT_CONFIG.points;

  const result = rows.map(row => {
    let data = {};
    try { data = JSON.parse(row.data || '{}'); } catch {}

    const agentId   = data.agent_id || null;
    const agentName = agentId ? (agentMap[agentId] || null) : null;

    let delta = 0;
    let eventLabel = '';
    let category   = 'clean';
    const reasons  = [];

    if (row.log_type === 'proxy_call') {
      const isAllow = data.decision === 'allow' || row.level === 'info';
      if (isAllow) {
        delta = weights.clean_call ?? DEFAULT_CONFIG.points.clean_call;
        eventLabel = 'Clean call';
        category   = 'clean';
      } else {
        delta = weights.policy_deny ?? DEFAULT_CONFIG.points.policy_deny;
        eventLabel = 'Policy denial';
        category   = 'deny';
        if (data.reason) reasons.push(data.reason);
      }
    } else {
      // interceptor
      if (!data.flagged) {
        delta = weights.clean_scan;
        eventLabel = 'Clean scan';
        category   = 'clean';
      } else {
        const cats  = Array.isArray(data.categories) ? data.categories : [];
        const isPii = cats.some(c => ['pii', 'privacy'].includes(c));
        const isInj = cats.some(c => ['prompt_injection', 'injection', 'unsafe'].includes(c));

        if (data.action_taken === 'block') {
          delta      += weights.interceptor_block;
          eventLabel  = 'Interceptor block';
          category    = 'block';
          reasons.push('blocked');
        }
        if (isPii)  { delta += weights.pii_flag;        reasons.push('PII'); if (category === 'clean') { eventLabel = 'PII flag'; category = 'pii'; } }
        if (isInj)  { delta += weights.injection_flag;  reasons.push('Injection'); if (category === 'clean') { eventLabel = 'Injection flag'; category = 'injection'; } }
        if (!eventLabel) { eventLabel = 'Flagged scan'; category = 'flag'; }
      }
    }

    return {
      id:          row.id,
      created_at:  row.created_at,
      log_type:    row.log_type,
      level:       row.level,
      vs_id:       row.vs_id,
      vs_name:     row.vs_name || null,
      agent_id:    agentId,
      agent_name:  agentName,
      user_sub:    data.user_sub   || null,
      user_email:  data.user_email || null,
      user_name:   data.user_name  || null,
      direction:   data.direction  || null,
      scanner:     data.scanner    || null,
      tool_name:   data.tool_name  || null,
      delta,
      event_label: eventLabel,
      category,
      reasons,
    };
  });

  res.json(result);
});

module.exports = router;
