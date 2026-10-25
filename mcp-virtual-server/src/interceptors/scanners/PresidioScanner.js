'use strict';

const BaseScanner = require('../BaseScanner');

const ANALYZER_URL = process.env.PRESIDIO_ANALYZER_URL || 'http://localhost:5001';

class PresidioScanner extends BaseScanner {
  get name() { return 'presidio'; }
  get tier() { return 'sync'; }

  async scan(text, context = {}) {
    try {
      const res = await fetch(`${ANALYZER_URL}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, language: 'en' }),
        signal: AbortSignal.timeout(5000),
      });

      if (!res.ok) return degraded(this.name);
      const entities = await res.json();

      if (!Array.isArray(entities) || entities.length === 0) {
        return { scanner: this.name, flagged: false, score: 0, categories: [], matches: [], metadata: {}, degraded: false };
      }

      const matches = entities.map(e => ({
        type: e.entity_type,
        value: '[REDACTED]',
        start: e.start,
        end: e.end,
      }));

      return {
        scanner: this.name,
        flagged: true,
        score: Math.max(...entities.map(e => e.score || 0.8)),
        categories: ['pii'],
        matches,
        metadata: { entityTypes: [...new Set(entities.map(e => e.entity_type))] },
        degraded: false,
      };
    } catch {
      return degraded(this.name);
    }
  }
}

function degraded(name) {
  return { scanner: name, flagged: false, score: 0, categories: [], matches: [], metadata: {}, degraded: true };
}

module.exports = PresidioScanner;
