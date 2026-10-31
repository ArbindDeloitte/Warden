'use strict';

const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');

function applyMasks(text, matches) {
  // Sort descending by start so we process back-to-front (avoids position shifts).
  const sorted = [...matches].sort((a, b) => b.start - a.start);
  let result = text;
  // Track the lowest start we've already written to. Any match whose end falls
  // inside that region is a duplicate (e.g. same span detected by two scanners)
  // — skip it to prevent double-replacement corrupting the JSON.
  let processedStart = Infinity;

  for (const m of sorted) {
    if (typeof m.start !== 'number' || typeof m.end !== 'number' || m.end <= m.start) continue;
    if (m.end > processedStart) continue; // overlaps an already-applied replacement
    const replacement = `[REDACTED: ${m.type}]`;
    result = result.slice(0, m.start) + replacement + result.slice(m.end);
    processedStart = m.start;
  }
  return result;
}

async function decide(results, text, virtualServerId, direction, agentId, callId, user) {
  let rules = [];
  try {
    rules = db.prepare(`
      SELECT * FROM interceptor_rules
      WHERE virtual_server_id = ? AND is_active = 1
      ORDER BY priority DESC
    `).all(virtualServerId);
  } catch { /* table might not exist yet */ }

  let finalAction = 'allow';
  let finalReason = null;
  let finalScanner = null;
  let finalRule = null;
  let finalScore = null;
  const allMatches = [];

  for (const result of results) {
    if (result.degraded || !result.flagged) continue;

    if (result.matches && result.matches.length > 0) {
      allMatches.push(...result.matches);
    }

    for (const rule of rules) {
      const scannerMatch = rule.scanner === '*' || rule.scanner === result.scanner;
      const categoryMatch = rule.category === '*' || (result.categories || []).includes(rule.category);
      const scoreMatch = (result.score || 0) >= (rule.score_min || 0);

      if (scannerMatch && categoryMatch && scoreMatch) {
        if (rule.action === 'block') {
          finalAction = 'block';
          // Use the rule's own category so the reason names the policy that fired,
          // not whichever category happened to be first in the scan result array.
          finalReason = rule.category !== '*' ? rule.category : ((result.categories || [])[0] || 'flagged');
          finalScanner = result.scanner;
          finalRule = rule.name || null;
          finalScore = result.score || null;
          break;
        } else if (rule.action === 'mask' && finalAction !== 'block') {
          finalAction = 'mask';
          finalScanner = result.scanner;
          finalRule = rule.name || null;
          finalScore = result.score || null;
        } else if (rule.action === 'warn' && finalAction === 'allow') {
          finalAction = 'warn';
          finalScanner = result.scanner;
          finalRule = rule.name || null;
          finalScore = result.score || null;
        }
        break;
      }
    }

    if (finalAction === 'block') break;
  }

  // Only apply masking when a rule explicitly set action to 'mask'.
  // No rules → pass-through (scanners detect, rules decide).
  let maskedText = text;
  if (finalAction === 'mask' && allMatches.length > 0) {
    maskedText = applyMasks(text, allMatches);
  }

  writeInterceptorLog({ virtualServerId, direction, results, finalAction, agentId, callId, user });

  return { action: finalAction, text: maskedText, reason: finalReason, scanner: finalScanner, rule: finalRule, score: finalScore };
}

function writeInterceptorLog({ virtualServerId, direction, results, finalAction, agentId, callId, user }) {
  // Write ONE aggregate event per call direction — not one per scanner.
  // Per-scanner writes would count a single blocked call multiple times in scoring
  // when several scanners detect the same content.
  if (!results || results.length === 0) return;
  try {
    const active        = results.filter(r => !r.degraded);
    const flagged       = active.filter(r => r.flagged);
    const anyFlagged    = flagged.length > 0;
    const allCategories = [...new Set(flagged.flatMap(r => r.categories || []))];
    const allPiiTypes   = [...new Set(flagged.flatMap(r => (r.matches || []).map(m => m.type)))];
    const maxScore      = flagged.reduce((m, r) => Math.max(m, r.score || 0), 0);
    const primaryScanner = flagged.length > 0 ? flagged[0].scanner : (active[0]?.scanner || 'unknown');
    const allScanners   = active.map(r => r.scanner);
    const anyDegraded   = results.some(r => r.degraded);

    const level = !anyFlagged       ? 'info'
      : finalAction === 'block'     ? 'block'
      : finalAction === 'mask'      ? 'warn'
      : finalAction === 'warn'      ? 'warn'
      : 'info';

    const summary = `${primaryScanner} · ${finalAction}${anyFlagged ? ` [${allCategories[0] || 'flagged'}]` : ''}`;

    const data = JSON.stringify({
      direction:    direction || null,
      scanner:      primaryScanner,
      scanners:     allScanners,
      flagged:      anyFlagged ? 1 : 0,
      action_taken: finalAction,
      categories:   allCategories,
      pii_types:    allPiiTypes,
      score:        maxScore,
      degraded:     anyDegraded ? 1 : 0,
      agent_id:     agentId || null,
      call_id:      callId  || null,
      user_email:   user?.email || null,
      user_sub:     user?.sub   || null,
      user_name:    user?.name  || null,
    });

    db.prepare(`
      INSERT INTO event_log (id, vs_id, log_type, level, summary, data)
      VALUES (?, ?, 'interceptor', ?, ?, ?)
    `).run(uuidv4(), virtualServerId || null, level, summary, data);
  } catch (err) {
    console.error('[ActionEngine] Log write failed:', err.message);
  }
}

module.exports = { decide };
