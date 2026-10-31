'use strict';

const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { runFunction } = require('./wardenRunner');

// Called after each interceptor scan. Fires Warden Functions when a user's
// score crosses below a trigger threshold for the first time (dedup via armed state).
async function evaluateUserTriggers(vsId, userSub, userEmail, userName) {
  if (!vsId || !userSub) return;

  const triggers = db.prepare(`
    SELECT wft.*, wf.code, wf.name AS fn_name
    FROM warden_function_triggers wft
    JOIN warden_functions wf ON wf.id = wft.function_id
    WHERE wft.is_active = 1 AND wf.is_active = 1
      AND wft.trigger_type = 'user_score_below'
      AND (wft.vs_id = ? OR wft.vs_id IS NULL)
  `).all(vsId);

  if (!triggers.length) return;

  const score = computeScore(userSub);

  for (const trigger of triggers) {
    const state = db.prepare(
      'SELECT * FROM warden_function_state WHERE trigger_id = ? AND user_sub = ?'
    ).get(trigger.id, userSub);

    const below = score < trigger.threshold;

    if (below && (!state || !state.armed)) {
      // New crossing — fire async (don't block the scan response)
      fireTrigger(trigger, userSub, userEmail, userName, score, vsId).catch(() => {});
      if (state) {
        db.prepare(`UPDATE warden_function_state SET armed=1, score_at_trigger=?, last_triggered_at=datetime('now') WHERE id=?`)
          .run(score, state.id);
      } else {
        db.prepare(`INSERT INTO warden_function_state (id,trigger_id,user_sub,armed,score_at_trigger,last_triggered_at) VALUES (?,?,?,1,?,datetime('now'))`)
          .run(uuidv4(), trigger.id, userSub, score);
      }
    } else if (!below && state?.armed) {
      // Score recovered above threshold — disarm so it can fire again next crossing
      db.prepare('UPDATE warden_function_state SET armed=0 WHERE id=?').run(state.id);
    }
  }
}

function computeScore(userSub) {
  const configRow = db.prepare(
    "SELECT config_json, mode FROM scoring_configs WHERE entity_type='user' AND entity_id='__users_global__'"
  ).get();
  const defaultPts = { clean_scan: 2, pii_flag: -10, injection_flag: -20, interceptor_block: -30 };
  let cfg = { only_inbound: true, time_window_days: 7, points: defaultPts };
  if (configRow && configRow.mode !== 'default') {
    try { const parsed = JSON.parse(configRow.config_json || '{}'); Object.assign(cfg, parsed); } catch {}
  }
  const pts   = { ...defaultPts, ...(cfg.points || {}) };
  const since = new Date(Date.now() - (cfg.time_window_days || 7) * 86400000).toISOString();

  let events = db.prepare(`
    SELECT json_extract(data,'$.direction')    AS direction,
           json_extract(data,'$.flagged')      AS flagged,
           json_extract(data,'$.action_taken') AS action_taken,
           json_extract(data,'$.categories')   AS categories_json
    FROM event_log
    WHERE log_type='interceptor' AND json_extract(data,'$.user_sub')=? AND created_at>=?
  `).all(userSub, since);

  if (cfg.only_inbound) events = events.filter(e => e.direction === 'inbound');

  let score = 500;
  for (const e of events) {
    const flagged = e.flagged === 1 || e.flagged === '1';
    const action  = e.action_taken || 'allow';
    let cats = [];
    try { cats = JSON.parse(e.categories_json || '[]'); } catch {}
    if (!flagged) {
      score += pts.clean_scan;
    } else {
      const isInj = cats.some(c => ['prompt_injection', 'injection', 'unsafe'].includes(c));
      if (action === 'block') score += isInj ? pts.injection_flag : pts.interceptor_block;
      else                    score += isInj ? pts.injection_flag : pts.pii_flag;
    }
  }
  return Math.max(0, Math.min(1000, Math.round(score)));
}

function scoreTier(s) {
  if (s >= 800) return 'Trusted';
  if (s >= 500) return 'Monitored';
  if (s >= 200) return 'At Risk';
  return 'Critical';
}

async function fireTrigger(trigger, userSub, userEmail, userName, score, vsId) {
  const vs = db.prepare('SELECT id, name FROM virtual_servers WHERE id = ?').get(vsId);
  const secretRows = db.prepare('SELECT key, value_b64 FROM warden_function_secrets WHERE function_id = ?').all(trigger.function_id);
  const secrets    = Object.fromEntries(secretRows.map(r => [r.key, Buffer.from(r.value_b64, 'base64').toString('utf8')]));

  const event = {
    type:           'user_score_below_threshold',
    triggered_at:   new Date().toISOString(),
    user:           { sub: userSub, email: userEmail || null, name: userName || null },
    score:          { current: score, threshold: trigger.threshold, tier: scoreTier(score) },
    virtual_server: { id: vsId, name: vs?.name || vsId },
  };

  const run = await runFunction(trigger.code, event, secrets);

  db.prepare(`
    INSERT INTO warden_function_logs
      (id,function_id,trigger_id,user_sub,user_email,score,vs_id,vs_name,status,output,console_logs,error_message,duration_ms)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    uuidv4(), trigger.function_id, trigger.id, userSub, userEmail || null, score,
    vsId, vs?.name || null,
    run.success ? 'success' : 'error',
    run.result  ? JSON.stringify(run.result)      : null,
    run.consoleLogs?.length ? JSON.stringify(run.consoleLogs) : null,
    run.error   || null,
    run.duration,
  );
}

module.exports = { evaluateUserTriggers };
