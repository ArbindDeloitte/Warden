'use strict';

const BaseScanner = require('../BaseScanner');

const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const LLAMA_MODEL = process.env.LLAMA_GUARD_MODEL || 'llama-guard3';

const S_CATEGORIES = {
  S1: 'violent_crimes', S2: 'non_violent_crimes', S3: 'sex_crimes',
  S4: 'child_exploitation', S5: 'defamation', S6: 'specialized_advice',
  S7: 'privacy', S8: 'intellectual_property', S9: 'indiscriminate_weapons',
  S10: 'hate_speech', S11: 'suicide_self_harm', S12: 'sexual_content',
  S13: 'elections', S14: 'code_interpreter_abuse',
};

class LlamaGuardScanner extends BaseScanner {
  get name() { return 'llama-guard'; }
  get tier() { return 'async'; }

  async scan(text, context = {}) {
    try {
      const prompt = `[INST] Task: Check if there is unsafe content in this message.\n\n<message>\n${text}\n</message>\n\nRespond with just "safe" or "unsafe\\nS<number>". [/INST]`;

      const res = await fetch(`${OLLAMA_URL}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: LLAMA_MODEL, prompt, stream: false }),
        signal: AbortSignal.timeout(30000),
      });

      if (!res.ok) return degraded(this.name);
      const data = await res.json();
      const response = (data.response || '').trim();

      if (response.toLowerCase().startsWith('safe')) {
        return { scanner: this.name, flagged: false, score: 0, categories: [], matches: [], metadata: { response }, degraded: false };
      }

      const sMatch = response.match(/unsafe\s*\n?\s*(s\d+)/i);
      const sCode = sMatch ? sMatch[1].toUpperCase() : null;
      const category = sCode ? (S_CATEGORIES[sCode] || 'unsafe') : 'unsafe';

      return {
        scanner: this.name,
        flagged: true,
        score: 0.9,
        categories: [category],
        matches: [],
        metadata: { response, sCode },
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

module.exports = LlamaGuardScanner;
