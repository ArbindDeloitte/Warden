'use strict';

// Fixed-window, in-memory rate limiting for the data-plane endpoints. Buckets are per calling agent (hash of the
// X-Agent-Token) and fall back to the client address, so one noisy or hostile caller cannot starve the others.
//   WARDEN_RATE_LIMIT_PER_MIN  requests per minute per caller (default 300; 0 turns the limiter off)

const crypto = require('crypto');

const perMinute = () => {
  const v = process.env.WARDEN_RATE_LIMIT_PER_MIN;
  if (v === undefined || v === '') return 300;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 300;
};

function callerKey(req) {
  const t = req.headers['x-agent-token'];
  return t ? `agent:${crypto.createHash('sha256').update(String(t)).digest('hex').slice(0, 16)}` : `ip:${req.ip}`;
}

/** `scope` separates the buckets of different endpoint groups; `jsonRpc` shapes the 429 body for A2A. */
function createRateLimiter({ scope, windowMs = 60 * 1000, jsonRpc = false }) {
  const buckets = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (b.resetAt <= now) buckets.delete(k); }, windowMs).unref();

  return function rateLimit(req, res, next) {
    const max = perMinute();
    if (max === 0) return next();
    const key = `${scope}:${callerKey(req)}`;
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || b.resetAt <= now) { b = { count: 0, resetAt: now + windowMs }; buckets.set(key, b); }
    if (++b.count <= max) return next();
    const retry = Math.max(1, Math.ceil((b.resetAt - now) / 1000));
    res.setHeader('Retry-After', retry);
    const message = `Rate limit exceeded (${max} requests per minute). Retry in ${retry}s.`;
    if (jsonRpc) {
      return res.status(429).json({ jsonrpc: '2.0', id: req.body?.id ?? null, error: { code: -32012, message: 'Rate limit exceeded', data: { reason: message, retry_after_seconds: retry } } });
    }
    return res.status(429).json({ error: 'Rate limit exceeded', reason: message, retry_after_seconds: retry });
  };
}

module.exports = { createRateLimiter, callerKey };
