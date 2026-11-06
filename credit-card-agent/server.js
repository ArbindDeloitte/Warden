'use strict';

/**
 * Credit Card Agent — a standalone A2A 1.0 agent (JSON-RPC binding) for the SecureBank demo.
 *
 *   node server.js            (PORT=4010, WARDEN_URL=http://localhost:3003)
 *
 * Zero npm dependencies. Rule-based (no LLM), so the demo has no external dependency.
 * Trust model: this agent only accepts calls carrying a Warden delegation token (Ed25519 JWT),
 * verified offline against Warden's JWKS (cached after the first fetch). Calling it directly,
 * bypassing the gateway, is rejected. Set REQUIRE_WARDEN_TOKEN=false to disable for debugging.
 */

const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 4010;
const WARDEN_URL = (process.env.WARDEN_URL || 'http://localhost:3003').replace(/\/$/, '');
const REQUIRE_TOKEN = process.env.REQUIRE_WARDEN_TOKEN !== 'false';
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/$/, '');

// ── Demo data ────────────────────────────────────────────────────────────────
// Keyed by the verified user's `sub`; unknown users (or no user token) get the demo profile.
const nextDue = (() => { const d = new Date(); d.setDate(15); if (d < new Date()) d.setMonth(d.getMonth() + 1); return d.toISOString().slice(0, 10); })();
const DEMO_PROFILE = () => ({
  cards: [
    { last4: '4242', network: 'Visa', product: 'SecureBank Platinum Rewards', cardNumber: '4242 4242 4242 4242',
      status: 'ACTIVE', limit: 15000, balance: 3420.55, minPayment: 85, dueDate: nextDue, apr: 19.99, rewardsPoints: 48210 },
    { last4: '0005', network: 'Mastercard', product: 'SecureBank Everyday Cash', cardNumber: '5555 5555 5555 4444',
      status: 'ACTIVE', limit: 5000, balance: 212.4, minPayment: 25, dueDate: nextDue, apr: 22.49, rewardsPoints: 1830 },
  ],
  transactions: [
    { date: '2026-11-02', card: '4242', merchant: 'Whole Foods Market', amount: 84.17, category: 'Groceries' },
    { date: '2026-11-01', card: '4242', merchant: 'Delta Air Lines', amount: 412.8, category: 'Travel' },
    { date: '2026-10-30', card: '0005', merchant: 'Shell', amount: 52.3, category: 'Fuel' },
    { date: '2026-10-29', card: '4242', merchant: 'Netflix', amount: 15.49, category: 'Subscriptions' },
    { date: '2026-10-27', card: '0005', merchant: 'Starbucks', amount: 6.75, category: 'Dining' },
  ],
});
const profiles = new Map();
const profileFor = (sub) => { const k = sub || 'demo'; if (!profiles.has(k)) profiles.set(k, DEMO_PROFILE()); return profiles.get(k); };

const money = (n) => `$${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

// ── Agent Card (A2A 1.0) ─────────────────────────────────────────────────────
const AGENT_CARD = {
  name: 'credit-card-agent',
  description: 'Answers questions about a customer\'s SecureBank credit cards: limits, balances, due dates, rewards and recent transactions. Can also freeze a card.',
  version: '1.0.0',
  supportedInterfaces: [{ url: `${PUBLIC_URL}/a2a`, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
  provider: { organization: 'SecureBank', url: 'https://securebank.example' },
  capabilities: { streaming: false, pushNotifications: false },
  defaultInputModes: ['text/plain'],
  defaultOutputModes: ['text/plain', 'application/json'],
  skills: [
    { id: 'card-details', name: 'Card details', description: 'Limit, balance, available credit, minimum payment, due date, APR and rewards points for each card.',
      tags: ['credit-card', 'balance', 'rewards'], examples: ['What is my credit limit?', 'When is my card payment due?'] },
    { id: 'card-transactions', name: 'Card transactions', description: 'Recent credit card purchases.',
      tags: ['credit-card', 'transactions'], examples: ['Show my recent card transactions'] },
    { id: 'card-freeze', name: 'Freeze card', description: 'Temporarily freezes a card. Sensitive: restrict with policy.',
      tags: ['credit-card', 'security'], examples: ['Freeze my Visa ending 4242'] },
  ],
};

// ── Warden delegation token verification (offline after first JWKS fetch) ────
let jwksCache = null;
async function getJwks(force = false) {
  if (jwksCache && !force) return jwksCache;
  try {
    const r = await fetch(`${WARDEN_URL}/.well-known/jwks.json`, { signal: AbortSignal.timeout(5000) });
    if (r.ok) jwksCache = await r.json();
  } catch { /* keep any cached keys: Warden being briefly down must not break verification */ }
  return jwksCache;
}

async function verifyWardenToken(raw) {
  try {
    const [h, p, s] = String(raw || '').replace(/^Bearer\s+/i, '').split('.');
    if (!h || !p || !s) return null;
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    if (header.alg !== 'EdDSA') return null;
    let jwk = (await getJwks())?.keys?.find(k => k.kid === header.kid);
    if (!jwk) jwk = (await getJwks(true))?.keys?.find(k => k.kid === header.kid); // key rotation
    if (!jwk) return null;
    const ok = crypto.verify(null, Buffer.from(`${h}.${p}`), crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(s, 'base64url'));
    if (!ok) return null;
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (claims.iss !== 'warden' || claims.exp < Math.floor(Date.now() / 1000)) return null;
    return claims;
  } catch { return null; }
}

// ── Skill handlers ───────────────────────────────────────────────────────────
function inferSkill(text) {
  const t = text.toLowerCase();
  if (/\b(freeze|lock|block|suspend)\b/.test(t)) return 'card-freeze';
  if (/\b(transaction|purchase|spent|spending|recent|statement)\b/.test(t)) return 'card-transactions';
  return 'card-details';
}

function pickCard(profile, text) {
  const m = text.match(/\b(\d{4})\b/);
  if (m) { const c = profile.cards.find(x => x.last4 === m[1]); if (c) return c; }
  const t = text.toLowerCase();
  return profile.cards.find(c => t.includes(c.network.toLowerCase())) || null;
}

function handle(skill, text, profile) {
  if (skill === 'card-details') {
    const lines = profile.cards.map(c =>
      `${c.product} (${c.network} ••••${c.last4}, ${c.status}): limit ${money(c.limit)}, balance ${money(c.balance)}, `
      + `available ${money(c.limit - c.balance)}, minimum payment ${money(c.minPayment)} due ${c.dueDate}, `
      + `APR ${c.apr}%, ${c.rewardsPoints.toLocaleString('en-US')} reward points.`);
    // cardNumber is deliberately included in the structured data (a "legacy" field) so the demo
    // can show the gateway's outbound interceptor redacting the PAN before it reaches the caller.
    return { text: lines.join('\n'), data: { cards: profile.cards.map(c => ({ ...c, available: +(c.limit - c.balance).toFixed(2) })) } };
  }
  if (skill === 'card-transactions') {
    const card = pickCard(profile, text);
    const tx = profile.transactions.filter(x => !card || x.card === card.last4);
    return {
      text: tx.map(x => `${x.date}  ${x.merchant.padEnd(20)} ${money(x.amount).padStart(10)}  (${x.category}, ••••${x.card})`).join('\n') || 'No recent transactions.',
      data: { transactions: tx },
    };
  }
  if (skill === 'card-freeze') {
    const card = pickCard(profile, text);
    if (!card) return { error: 'Please say which card to freeze, e.g. "freeze my Visa ending 4242".' };
    card.status = 'FROZEN';
    return { text: `${card.product} (••••${card.last4}) is now FROZEN. New purchases will be declined until it is unfrozen.`, data: { card: { last4: card.last4, status: card.status } } };
  }
  return { error: `Unknown skill "${skill}"` };
}

// ── JSON-RPC ─────────────────────────────────────────────────────────────────
const tasks = new Map();
const rpcErr = (id, code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
const send = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };

async function onRpc(req, res) {
  let body = ''; for await (const c of req) body += c;
  let rpc; try { rpc = JSON.parse(body); } catch { return send(res, 400, rpcErr(null, -32700, 'Parse error')); }

  let claims = null;
  if (REQUIRE_TOKEN) {
    claims = await verifyWardenToken(req.headers['x-warden-delegation'] || req.headers.authorization);
    if (!claims) {
      console.log('[card-agent] REJECTED request without a valid Warden delegation token');
      return send(res, 401, rpcErr(rpc.id, -32600, 'Unauthorized: this agent only accepts calls routed through the Warden gateway'));
    }
  }

  const ver = req.headers['a2a-version'];
  if (ver && String(ver).split('.').slice(0, 2).join('.') !== '1.0') return send(res, 400, rpcErr(rpc.id, -32009, `Unsupported A2A version ${ver}`));

  if (rpc.method === 'SendMessage') {
    const msg = rpc.params?.message;
    if (!msg || !Array.isArray(msg.parts)) return send(res, 200, rpcErr(rpc.id, -32602, 'params.message with parts is required'));
    const text = msg.parts.map(p => p.text || '').join(' ').trim();
    const skill = rpc.params?.metadata?.skillId || msg.metadata?.skillId || inferSkill(text);
    const profile = profileFor(claims?.user?.sub);
    const out = handle(skill, text, profile);
    const id = crypto.randomUUID();
    console.log(`[card-agent] caller=${claims?.agent_name || '(unverified)'} user=${claims?.user?.sub || '(none)'} skill=${skill} -> ${out.error ? 'FAILED' : 'COMPLETED'}`);
    const task = {
      id, contextId: msg.contextId || crypto.randomUUID(),
      status: { state: out.error ? 'TASK_STATE_FAILED' : 'TASK_STATE_COMPLETED', timestamp: new Date().toISOString(),
        ...(out.error ? { message: { messageId: crypto.randomUUID(), role: 'ROLE_AGENT', parts: [{ text: out.error }] } } : {}) },
      artifacts: out.error ? [] : [{ artifactId: crypto.randomUUID(), name: skill, parts: [{ text: out.text }, { data: out.data, mediaType: 'application/json' }] }],
    };
    tasks.set(id, task);
    return send(res, 200, { jsonrpc: '2.0', id: rpc.id, result: { task } });
  }
  if (rpc.method === 'GetTask') {
    const t = tasks.get(rpc.params?.id);
    return send(res, 200, t ? { jsonrpc: '2.0', id: rpc.id, result: t } : rpcErr(rpc.id, -32001, 'Task not found'));
  }
  if (rpc.method === 'CancelTask') {
    const t = tasks.get(rpc.params?.id);
    return send(res, 200, t ? rpcErr(rpc.id, -32002, 'Task is already in a terminal state') : rpcErr(rpc.id, -32001, 'Task not found'));
  }
  send(res, 200, rpcErr(rpc.id, -32601, `Method not found: ${rpc.method}`));
}

http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/.well-known/agent-card.json') return send(res, 200, AGENT_CARD);
    if (req.method === 'GET' && req.url === '/health') return send(res, 200, { status: 'ok' });
    if (req.method === 'POST' && req.url === '/a2a') return await onRpc(req, res);
    send(res, 404, { error: 'Not found' });
  } catch (e) { console.error(e); if (!res.headersSent) send(res, 500, rpcErr(null, -32603, 'Internal error')); }
}).listen(PORT, () => {
  console.log(`\nCredit Card Agent (A2A 1.0) on ${PUBLIC_URL}`);
  console.log(`  Agent Card : ${PUBLIC_URL}/.well-known/agent-card.json`);
  console.log(`  Auth       : ${REQUIRE_TOKEN ? `Warden delegation token required (JWKS: ${WARDEN_URL}/.well-known/jwks.json)` : 'DISABLED (REQUIRE_WARDEN_TOKEN=false)'}\n`);
});
