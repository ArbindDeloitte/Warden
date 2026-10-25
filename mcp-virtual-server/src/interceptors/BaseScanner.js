'use strict';

class BaseScanner {
  get name() { throw new Error('Scanner must implement name getter'); }
  get tier() { return 'sync'; } // 'sync' | 'async'

  async init() {}

  async scan(text, context = {}) {
    return {
      scanner: this.name,
      flagged: false,
      score: 0,
      categories: [],
      matches: [],
      metadata: {},
      degraded: false,
    };
  }
}

module.exports = BaseScanner;
