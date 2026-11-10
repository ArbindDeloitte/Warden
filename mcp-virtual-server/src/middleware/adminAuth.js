'use strict';

// Authentication for Warden's ADMIN API (everything under /api that is not data-plane).
//
//   WARDEN_ADMIN_TOKEN set   -> the admin API requires it, as X-Admin-Token, `Authorization: Bearer <token>`, or the
//                               session cookie that POST /api/auth/login issues (that is how the Warden UI signs in).
//   WARDEN_ADMIN_TOKEN unset -> "open mode": the previous behaviour (no authentication), with a loud startup warning.
//
// Data-plane routes keep their own credentials and are exempt from this gate: the MCP proxy (API key + agent token +
// user token), A2A (/a2a is not under /api), vault checkout/sign/validate (agent token), health, and the two endpoints the
// banking chat uses (message scan, approval status), which require an agent token themselves in secure mode.

const crypto = require('crypto');
const express = require('express');

const COOKIE = 'warden_admin';
const SESSION_MS = 12 * 60 * 60 * 1000;

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const token = () => (process.env.WARDEN_ADMIN_TOKEN || '').trim();
const enabled = () => token().length > 0;
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

// Sessions are stateless and tied to the token: changing WARDEN_ADMIN_TOKEN invalidates every session.
const sign = (expires) => crypto.createHmac('sha256', Buffer.concat([sha(token()), Buffer.from('warden-admin-session')])).update(String(expires)).digest('hex');
const newSession = () => { const exp = Date.now() + SESSION_MS; return `${exp}.${sign(exp)}`; };

function cookieValue(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

function validSession(value) {
  if (!value) return false;
  const [exp, mac] = String(value).split('.');
  if (!/^\d+$/.test(exp || '') || !mac || Number(exp) <= Date.now()) return false;
  const expected = sign(exp);
  return mac.length === expected.length && crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected));
}

/** True when the request carries valid admin credentials (always true in open mode). */
function isAdmin(req) {
  if (!enabled()) return true;
  const hdr = req.headers['x-admin-token'];
  if (typeof hdr === 'string' && hdr && safeEqual(hdr, token())) return true;
  const m = /^Bearer\s+(\S+)$/i.exec(String(req.headers.authorization || ''));
  if (m && safeEqual(m[1], token())) return true;
  return validSession(cookieValue(req, COOKIE));
}

// Routes under /api that authenticate themselves (see the header comment). Paths are relative to /api.
const EXEMPT = [
  ['GET', /^\/health$/],
  [null, /^\/proxy(\/|$)/],
  ['POST', /^\/vault\/(checkout|sign)$/],
  ['GET', /^\/vault\/validate\/[^/]+$/],
  ['POST', /^\/interceptors\/[^/]+\/scan$/],
  ['GET', /^\/approvals\/[^/]+\/status$/],
];
const exempt = (req) => EXEMPT.some(([method, re]) => (!method || method === req.method) && re.test(req.path));

function gate(req, res, next) {
  if (!enabled() || exempt(req) || isAdmin(req)) return next();
  res.status(401).json({ error: 'Admin authentication required', code: 'admin_auth_required' });
}

// Failed logins are throttled per client address so the token cannot be guessed by brute force.
const failures = new Map();
const MAX_FAILURES = 10, FAIL_WINDOW_MS = 10 * 60 * 1000;
function throttled(ip) {
  const f = failures.get(ip);
  if (!f) return 0;
  if (f.resetAt <= Date.now()) { failures.delete(ip); return 0; }
  return f.count >= MAX_FAILURES ? Math.ceil((f.resetAt - Date.now()) / 1000) : 0;
}
function recordFailure(ip) {
  const f = failures.get(ip);
  if (!f || f.resetAt <= Date.now()) failures.set(ip, { count: 1, resetAt: Date.now() + FAIL_WINDOW_MS });
  else f.count++;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of failures) if (v.resetAt <= now) failures.delete(k); }, 60 * 1000).unref();

const secure = (req) => req.secure || req.headers['x-forwarded-proto'] === 'https';
function setCookie(res, req, value, maxAgeMs) {
  res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(value)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(maxAgeMs / 1000)}${secure(req) ? '; Secure' : ''}`);
}

const routes = express.Router();
routes.get('/status', (req, res) => res.json({ authRequired: enabled(), authenticated: isAdmin(req) }));
routes.post('/login', (req, res) => {
  if (!enabled()) return res.json({ ok: true, authRequired: false });
  const wait = throttled(req.ip);
  if (wait) { res.setHeader('Retry-After', wait); return res.status(429).json({ error: 'Too many failed attempts. Try again later.', retry_after_seconds: wait }); }
  const t = req.body?.token;
  if (typeof t !== 'string' || !t || !safeEqual(t, token())) {
    recordFailure(req.ip);
    return res.status(401).json({ error: 'Invalid admin token' });
  }
  failures.delete(req.ip);
  setCookie(res, req, newSession(), SESSION_MS);
  res.json({ ok: true });
});
routes.post('/logout', (req, res) => { setCookie(res, req, '', 0); res.json({ ok: true }); });

function startupNotice() {
  if (!enabled()) {
    return { level: 'warn', text: 'Admin API is UNAUTHENTICATED (WARDEN_ADMIN_TOKEN is not set): anyone who can reach this port can read and change everything, including minting API keys and agent tokens.' };
  }
  const weak = token().length < 16 ? ' WARNING: the token is shorter than 16 characters; use a long random value.' : '';
  return { level: weak ? 'warn' : 'info', text: `Admin API requires authentication (WARDEN_ADMIN_TOKEN is set).${weak}` };
}

module.exports = { enabled, isAdmin, gate, routes, startupNotice, exempt };
