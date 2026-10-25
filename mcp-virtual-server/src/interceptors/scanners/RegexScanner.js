'use strict';

const BaseScanner = require('../BaseScanner');

const PII_PATTERNS = [
  { type: 'SSN',         regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: 'CREDIT_CARD', regex: /\b(?:\d{4}[- ]?){3}\d{4}\b/g },
  { type: 'EMAIL',       regex: /\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b/gi },
  { type: 'PHONE_US',    regex: /\b(?:\+1\s?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g },
  { type: 'IP_ADDRESS',  regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g },
  { type: 'API_KEY',     regex: /\b(?:sk-|pk-)[A-Za-z0-9_-]{20,}\b/g },
  { type: 'BEARER',      regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g },
  { type: 'IBAN',        regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}\b/g },
];

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
  /forget\s+(everything|all|what)\s+(you('ve|\s+have)\s+)?learned/gi,
  /you\s+are\s+now\s+(a|an)\s+/gi,
  /new\s+(role|persona|personality|instructions?)[:.\s]/gi,
  /system\s*prompt\s*[:=]/gi,
  /\[INST\]|\[\/INST\]|<\|system\|>/g,
  /act\s+as\s+(if\s+)?(you\s+are|a|an)\s+/gi,
  /disregard\s+(your\s+)?(previous|prior|all)\s+(instructions?|training)/gi,
];

class RegexScanner extends BaseScanner {
  get name() { return 'regex'; }
  get tier() { return 'sync'; }

  async scan(text, context = {}) {
    try {
      const matches = [];
      let flagged = false;
      const categories = new Set();
      let injectionHits = 0;

      for (const pattern of PII_PATTERNS) {
        const re = new RegExp(pattern.regex.source, pattern.regex.flags);
        let m;
        while ((m = re.exec(text)) !== null) {
          matches.push({ type: pattern.type, value: '[REDACTED]', start: m.index, end: m.index + m[0].length });
          categories.add('pii');
          flagged = true;
        }
      }

      for (const regex of INJECTION_PATTERNS) {
        const re = new RegExp(regex.source, regex.flags);
        let m;
        while ((m = re.exec(text)) !== null) {
          matches.push({ type: 'prompt_injection', value: '[REDACTED]', start: m.index, end: m.index + m[0].length });
          categories.add('prompt_injection');
          injectionHits++;
          flagged = true;
        }
      }

      const score = flagged
        ? (categories.has('prompt_injection') ? Math.min(0.5 * injectionHits, 1.0) : 0.85)
        : 0;

      return {
        scanner: this.name,
        flagged,
        score,
        categories: Array.from(categories),
        matches,
        metadata: {},
        degraded: false,
      };
    } catch (err) {
      return { scanner: this.name, flagged: false, score: 0, categories: [], matches: [], metadata: {}, degraded: true };
    }
  }
}

module.exports = RegexScanner;
