'use strict';

const registry = require('./ScannerRegistry');
const actionEngine = require('./ActionEngine');
const db = require('../db/database');

function getEnabledScanners(virtualServerId, direction) {
  try {
    // Check whether any scanner config has been saved for this VS at all
    const allRows = db.prepare(`
      SELECT scanner_name, enabled FROM interceptor_scanners
      WHERE virtual_server_id = ?
        AND (direction = ? OR direction = 'both')
    `).all(virtualServerId, direction);

    // No rows at all → VS has never been configured: use regex as safe default
    if (allRows.length === 0) return ['regex'];

    // Config exists → honour the saved enabled/disabled state for each scanner
    return allRows.filter(r => r.enabled === 1).map(r => r.scanner_name);
  } catch {
    return ['regex'];
  }
}

async function run(text, direction, virtualServerId) {
  if (!text || typeof text !== 'string' || text.trim() === '') {
    return { action: 'allow', text, reason: null };
  }

  const enabledNames = getEnabledScanners(virtualServerId, direction);
  if (enabledNames.length === 0) {
    return { action: 'allow', text, reason: null };
  }

  const syncResults = [];

  for (const scanner of registry.sync()) {
    if (!enabledNames.includes(scanner.name)) continue;
    try {
      const result = await scanner.scan(text, { virtualServerId, direction });
      syncResults.push(result);
    } catch (err) {
      console.warn(`[Pipeline] ${scanner.name} threw:`, err.message);
      syncResults.push({
        scanner: scanner.name, flagged: false, score: 0,
        categories: [], matches: [], metadata: {}, degraded: true,
      });
    }
  }

  const decision = await actionEngine.decide(syncResults, text, virtualServerId, direction);

  // Fire async scanners (non-blocking, audit-log only)
  for (const scanner of registry.async()) {
    if (!enabledNames.includes(scanner.name)) continue;
    scanner.scan(text, { virtualServerId, direction }).then(result => {
      if (result.flagged) {
        actionEngine.decide([result], text, virtualServerId, `${direction}_async`).catch(() => {});
      }
    }).catch(() => {});
  }

  return decision;
}

module.exports = { run };
