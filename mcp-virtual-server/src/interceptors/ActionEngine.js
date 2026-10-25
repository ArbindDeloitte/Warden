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

async function decide(results, text, virtualServerId, direction) {
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
          break;
        } else if (rule.action === 'mask' && finalAction !== 'block') {
          finalAction = 'mask';
        } else if (rule.action === 'warn' && finalAction === 'allow') {
          finalAction = 'warn';
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

  writeInterceptorLog({ virtualServerId, direction, results, finalAction });

  return { action: finalAction, text: maskedText, reason: finalReason };
}

function writeInterceptorLog({ virtualServerId, direction, results, finalAction }) {
  for (const result of results) {
    try {
      db.prepare(`
        INSERT INTO interceptor_log
          (id, virtual_server_id, direction, scanner, flagged, action_taken,
           categories, pii_types, score, degraded)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        uuidv4(), virtualServerId || null, direction || null,
        result.scanner,
        result.flagged ? 1 : 0,
        finalAction,
        JSON.stringify(result.categories || []),
        JSON.stringify((result.matches || []).map(m => m.type).filter((v, i, a) => a.indexOf(v) === i)),
        result.score || 0,
        result.degraded ? 1 : 0
      );
    } catch (err) {
      console.error('[ActionEngine] Log write failed:', err.message);
    }
  }
}

module.exports = { decide };
