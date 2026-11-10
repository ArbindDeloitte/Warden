'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const WARDEN_URL = (process.env.WARDEN_URL || 'http://localhost:3003').replace(/\/$/, '');
const DEMO_PORT = Number(process.env.DEMO_PORT || 3050);
const STATE_FILE = process.env.DEMO_STATE_FILE || path.join(__dirname, '.state.json');

// Everything the demo creates carries a "demo-" name so it is easy to spot and to remove.
const NAMES = {
  reportAgent: 'demo-report-agent',
  rogueAgent: 'demo-rogue-agent',
  vs: 'demo-payments-vs',
  mcp: 'demo-payments-api',
  keySecret: 'demo-payments-api-key',
  hookSecret: 'demo-webhook-secret',
  vaultPolicy: 'demo: report-agent may broker on demo-payments-vs',
  toolPolicy: 'demo: allow all tools',
};

// The request the "agent" sends. Note it contains only a vault reference, never a credential.
const AGENT_REQUEST = {
  tool: 'get_report',
  arguments: { account: 'ACME-001', webhook_secret: `vault://${NAMES.hookSecret}` },
};

// Warden's admin API requires WARDEN_ADMIN_TOKEN when it is set there. Taken from the environment, else Warden's .env.
function adminHeaders() {
  let t = process.env.WARDEN_ADMIN_TOKEN; // set but empty = "no token" (tests use this)
  if (t === undefined) {
    try { const m = /^WARDEN_ADMIN_TOKEN=(.+)$/m.exec(fs.readFileSync(path.join(__dirname, '..', '..', '.env'), 'utf8')); if (m) t = m[1].trim(); } catch { /* no .env: Warden is probably open */ }
  }
  return t ? { 'X-Admin-Token': t } : {};
}

async function warden(method, p, body, headers = {}) {
  const res = await fetch(WARDEN_URL + p, {
    method,
    // The demo's own data-plane calls pass explicit headers; the admin token is only added for /api admin routes.
    headers: { 'Content-Type': 'application/json', ...(/^\/api\/(proxy|vault\/(checkout|sign|validate))/.test(p) ? {} : adminHeaders()), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-JSON */ }
  return { status: res.status, json, text };
}

const readState = () => { try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { return null; } };
const writeState = (s) => fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2), { mode: 0o600 });
const clearState = () => { try { fs.unlinkSync(STATE_FILE); } catch { /* already gone */ } };

const newPaymentsKey = () => `sk_live_pay_${crypto.randomBytes(12).toString('hex')}`;
const newWebhookSecret = () => `whsec_${crypto.randomBytes(12).toString('hex')}`;
// Unsigned dev token: the demo virtual server has no JWKS configured, so Warden reads its claims as-is.
const devUserJwt = () => ['{"alg":"none"}', '{"sub":"demo-user"}'].map(j => Buffer.from(j).toString('base64url')).join('.') + '.sig';
const mask = (s) => (typeof s === 'string' && s.length > 14 ? `${s.slice(0, 8)}…${s.slice(-4)}` : s ? '…' : null);

module.exports = { WARDEN_URL, DEMO_PORT, STATE_FILE, NAMES, AGENT_REQUEST, warden, readState, writeState, clearState, newPaymentsKey, newWebhookSecret, devUserJwt, mask };
