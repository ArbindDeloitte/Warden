'use strict';

const RegexScanner = require('./scanners/RegexScanner');
const PresidioScanner = require('./scanners/PresidioScanner');
const LlamaGuardScanner = require('./scanners/LlamaGuardScanner');

class ScannerRegistry {
  constructor() {
    this._scanners = new Map();
  }

  register(scanner) {
    this._scanners.set(scanner.name, scanner);
  }

  get(name) {
    return this._scanners.get(name);
  }

  all() {
    return Array.from(this._scanners.values());
  }

  sync() {
    return this.all().filter(s => s.tier === 'sync');
  }

  async() {
    return this.all().filter(s => s.tier === 'async');
  }

  async initAll() {
    for (const scanner of this.all()) {
      try {
        await scanner.init();
        console.log(`[Interceptors] Ready: ${scanner.name}`);
      } catch (err) {
        console.warn(`[Interceptors] ${scanner.name} init failed (degraded):`, err.message);
      }
    }
  }
}

const registry = new ScannerRegistry();
registry.register(new RegexScanner());
registry.register(new PresidioScanner());
registry.register(new LlamaGuardScanner());

module.exports = registry;
