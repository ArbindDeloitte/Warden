'use strict';

/**
 * A2A gateway (JSON-RPC binding) for protocol versions 1.0 and 0.3. Warden never hosts agents: it
 * authenticates the caller, applies policy + interceptors, then forwards to the registered remote agent.
 * Each registered agent speaks ONE version (a2a_agents.protocol_version) and its gateway endpoint speaks that
 * same version to both the caller and the remote agent: no translation, so policy, scanning and task
 * ownership behave identically across versions. Self-contained: no Redis/Okta dependency except the
 * OPTIONAL user-token verification.
 */

const express = require('express');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { verifyToken } = require('../middleware/auth');
const pipeline = require('../interceptors/InterceptorPipeline');
const { buildGatewayCard, publicBase, A2A_VERSION } = require('../services/a2aCards');
const { evaluateA2aPolicy } = require('../services/a2aPolicy');
const keys = require('../services/a2aKeys');
const { decrypt } = require('../services/secrets');

const router = express.Router();
const wellKnown = express.Router();

const MAX_DEPTH = 5;
const TIMEOUT_MS = Number(process.env.A2A_TIMEOUT_MS) || 60000;

const ERR = {
  INVALID: -32600, NO_METHOD: -32601, PARAMS: -32602, INTERNAL: -32603,
  TASK_NOT_FOUND: -32001, NOT_CANCELABLE: -32002, PUSH_UNSUPPORTED: -32003, UNSUPPORTED: -32004,
  EXT_CARD: -32007, VERSION: -32009,
  DENIED: -32010, // Warden-specific: auth/policy/interceptor denial
  APPROVAL: -32011, // Warden-specific: held for human approval; data carries the ticket
};

const rpcError = (id, code, message, data) =>
  ({ jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(data ? { data } : {}) } });

// Everything that differs between the two protocol versions lives here; the handler below is version-neutral.
//   1.0: PascalCase methods; results are wrapped ({task} | {message} | {statusUpdate} | {artifactUpdate}).
//   0.3: `message/send` style methods, no ListTasks; results are bare objects discriminated by `kind`
//        (task | message | status-update | artifact-update); task states are lowercase ('submitted', 'working', ...).
const PROTOCOLS = {
  '1.0': {
    send: 'SendMessage', stream: 'SendStreamingMessage', get: 'GetTask', cancel: 'CancelTask',
    subscribe: 'SubscribeToTask', list: 'ListTasks', extCard: 'GetExtendedAgentCard',
    pushRe: /PushNotificationConfigs?$/, sendsVersionHeader: true, submitted: 'TASK_STATE_SUBMITTED',
    taskOfResult: (r) => r?.task || (r?.status && r?.id ? r : null),
    taskOfEvent: (r) => r?.task || null,
    statusOfEvent: (r) => r?.statusUpdate || null,
  },
  '0.3': {
    send: 'message/send', stream: 'message/stream', get: 'tasks/get', cancel: 'tasks/cancel',
    subscribe: 'tasks/resubscribe', list: null, extCard: 'agent/getAuthenticatedExtendedCard',
    pushRe: /^tasks\/pushNotificationConfig\//, sendsVersionHeader: false, submitted: 'submitted',
    taskOfResult: (r) => (r?.kind === 'task' || (r?.status && r?.id && !r?.kind) ? r : null),
    taskOfEvent: (r) => (r?.kind === 'task' ? r : null),
    statusOfEvent: (r) => (r?.kind === 'status-update' ? r : null),
  },
};
const methodsOf = (p) => [p.send, p.stream, p.get, p.cancel, p.subscribe, p.list].filter(Boolean);
const versionOf = (target) => (target?.protocol_version === '0.3' ? '0.3' : '1.0');
const protoOf = (target) => PROTOCOLS[versionOf(target)];

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ── Circuit breaker (in-memory, per target) ──────────────────────────────────
const breaker = new Map();
const circuitOpen = (id) => (breaker.get(id)?.openUntil || 0) > Date.now();
const recordFail = (id) => {
  const b = breaker.get(id) || { fails: 0, openUntil: 0 };
  if (++b.fails >= 3) { b.openUntil = Date.now() + 30000; b.fails = 0; }
  breaker.set(id, b);
};
const recordOk = (id) => breaker.delete(id);

// ── Discovery ────────────────────────────────────────────────────────────────

wellKnown.get('/jwks.json', (_req, res) => res.json(keys.jwks()));

function loadContext(vsId, agentId) {
  const vs = db.prepare('SELECT * FROM virtual_servers WHERE id = ? AND is_active = 1').get(vsId);
  if (!vs || !['a2a', 'both'].includes(vs.protocol)) return null;
  const target = db.prepare(`
    SELECT a.* FROM a2a_agents a
    JOIN virtual_server_a2a_agents v ON v.a2a_agent_id = a.id
    WHERE v.vs_id = ? AND a.id = ? AND a.is_active = 1
  `).get(vs.id, agentId);
  return target ? { vs, target } : null;
}

// A2A 0.2.x/early-0.3 clients look for agent.json; 0.3 agents serve the same card there too.
router.get('/:vsId/:agentId/.well-known/agent.json', (req, res) => {
  const ctx = loadContext(req.params.vsId, req.params.agentId);
  if (!ctx || versionOf(ctx.target) !== '0.3') return res.status(404).json({ error: 'Unknown virtual server or agent' });
  res.json(buildGatewayCard(ctx.target, ctx.vs.id, publicBase(req)));
});

router.get('/:vsId/:agentId/.well-known/agent-card.json', (req, res) => {
  const ctx = loadContext(req.params.vsId, req.params.agentId);
  if (!ctx) return res.status(404).json({ error: 'Unknown virtual server or agent' });
  res.json(buildGatewayCard(ctx.target, ctx.vs.id, publicBase(req)));
});

// ── Auth helpers ─────────────────────────────────────────────────────────────

function checkApiKey(req, vsId) {
  const now = new Date().toISOString();
  const active = db.prepare('SELECT * FROM api_keys WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > ?)')
    .all(now).filter(k => {
      const list = JSON.parse(k.virtual_server_ids || '[]');
      return list.length === 0 || list.includes(vsId);
    });
  if (!active.length) return null;
  const provided = req.headers['x-api-key'];
  if (!provided) return { status: 401, message: 'X-API-Key header required' };
  const matched = active.find(k => k.key_hash === sha256(provided));
  if (!matched) return { status: 401, message: 'Invalid API key' };
  try { db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now, matched.id); } catch {}
  return null;
}

// Unlike the MCP proxy (which fails open on unknown agent tokens), A2A requires a known agent.
function authenticateCaller(req, vsId) {
  const apiErr = checkApiKey(req, vsId);
  if (apiErr) return { err: apiErr };
  // X-Agent-Token wins; the standard "Authorization: Bearer <agent token>" is accepted as a fallback so
  // stock A2A clients (whose auth hooks set Authorization) can authenticate without custom headers.
  let tok = req.headers['x-agent-token'];
  if (!tok) { const m = /^Bearer\s+(\S+)$/i.exec(String(req.headers.authorization || '')); if (m) tok = m[1]; }
  if (!tok) return { err: { status: 401, message: 'Agent token required for A2A calls: send X-Agent-Token, or Authorization: Bearer <agent token>' } };
  const row = db.prepare('SELECT id, name, is_active FROM agents WHERE token_hash = ?').get(sha256(tok));
  if (!row) return { err: { status: 401, message: 'Unknown agent token' } };
  if (!row.is_active) return { err: { status: 403, message: `Agent "${row.name}" is disabled` } };
  try { db.prepare('UPDATE agents SET last_seen_at = ? WHERE id = ?').run(new Date().toISOString(), row.id); } catch {}
  return { caller: { id: row.id, name: row.name } };
}

// Verifies the optional x-user-token with the VS's JWKS (keys are cached by jwks-rsa, so brief IdP
// outages don't break verification of already-seen keys). 'infra' distinguishes "IdP unreachable /
// not configured" from "token is bad" so a per-policy fail mode can treat them differently.
async function resolveUser(req, vs) {
  const h = req.headers['x-user-token'];
  if (!h) return { status: 'absent' };
  const fake = { headers: { authorization: `Bearer ${String(h).replace(/^Bearer\s+/i, '')}` }, virtualServer: vs };
  try {
    await Promise.race([
      new Promise((resolve, reject) => verifyToken(fake, null, (e) => (e ? reject(e) : resolve()))),
      new Promise((_, reject) => setTimeout(() => reject(new Error('user token verification timed out')), 8000)),
    ]);
    if (fake.tokenVerified) return { status: 'verified', user: { sub: fake.tokenClaims.sub, groups: fake.tokenClaims.groups } };
    return { status: 'unverified', infra: true, reason: 'No JWKS configured on this virtual server' };
  } catch (e) {
    const d = String(e.detail || e.message);
    const bad = /jwt|signature|malformed|expired|invalid token|audience|issuer/i.test(d);
    return { status: 'unverified', infra: !bad, reason: d };
  }
}

// ── Interceptors ─────────────────────────────────────────────────────────────

async function scanValue(v, run, depth = 0) {
  if (typeof v === 'string') return v.length >= 3 ? run(v) : v;
  if (depth > 8 || v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) { const out = []; for (const x of v) out.push(await scanValue(x, run, depth + 1)); return out; }
  const out = {};
  for (const [k, x] of Object.entries(v)) out[k] = await scanValue(x, run, depth + 1);
  return out;
}

// Scans text parts and string leaves of data parts individually (never raw JSON).
async function scanParts(parts, run) {
  if (!Array.isArray(parts)) return parts;
  const out = [];
  for (const p of parts) {
    const c = { ...p };
    if (typeof c.text === 'string') c.text = await scanValue(c.text, run);
    if (c.data !== undefined) c.data = await scanValue(c.data, run);
    out.push(c);
  }
  return out;
}

async function scanMessage(m, run) {
  return m && Array.isArray(m.parts) ? { ...m, parts: await scanParts(m.parts, run) } : m;
}

async function scanTask(t, run) {
  if (!t) return t;
  const c = { ...t };
  if (c.status?.message) c.status = { ...c.status, message: await scanMessage(c.status.message, run) };
  if (Array.isArray(c.artifacts)) c.artifacts = await Promise.all(c.artifacts.map(async a => ({ ...a, parts: await scanParts(a.parts, run) })));
  if (Array.isArray(c.history)) c.history = await Promise.all(c.history.map(m => scanMessage(m, run)));
  return c;
}

// 0.3 results are bare objects discriminated by `kind`; a bare Task (tasks/get, tasks/cancel) falls through to scanTask.
async function scanResult03(r, run) {
  switch (r.kind) {
    case 'message': return scanMessage(r, run);
    case 'status-update':
      return r.status?.message ? { ...r, status: { ...r.status, message: await scanMessage(r.status.message, run) } } : r;
    case 'artifact-update':
      return r.artifact ? { ...r, artifact: { ...r.artifact, parts: await scanParts(r.artifact.parts, run) } } : r;
    default: return scanTask(r, run);
  }
}

async function scanResult(r, run, version = '1.0') {
  if (!r || typeof r !== 'object') return r;
  if (version === '0.3') return scanResult03(r, run);
  const out = { ...r };
  const scanTaskInner = (t) => scanTask(t, run);
  if (out.task) out.task = await scanTaskInner(out.task);
  if (out.message) out.message = await scanMessage(out.message, run);
  if (out.statusUpdate?.status?.message) {
    out.statusUpdate = { ...out.statusUpdate, status: { ...out.statusUpdate.status, message: await scanMessage(out.statusUpdate.status.message, run) } };
  }
  if (out.artifactUpdate?.artifact) {
    out.artifactUpdate = { ...out.artifactUpdate, artifact: { ...out.artifactUpdate.artifact, parts: await scanParts(out.artifactUpdate.artifact.parts, run) } };
  }
  // GetTask / CancelTask return a bare Task
  if (!out.task && !out.message && !out.statusUpdate && !out.artifactUpdate && (out.status || out.artifacts || out.history)) {
    return scanTaskInner(out);
  }
  return out;
}

// ── Task store (ownership-bound) ─────────────────────────────────────────────

const ownedTask = (vsId, targetId, callerId, remoteId) => db.prepare(
  'SELECT * FROM a2a_tasks WHERE vs_id=? AND target_agent_id=? AND caller_agent_id=? AND remote_task_id=?'
).get(vsId, targetId, callerId, String(remoteId));

function saveTask(vsId, targetId, callerId, task, fallbackState = 'TASK_STATE_SUBMITTED') {
  if (!task?.id) return true;
  const existing = db.prepare('SELECT * FROM a2a_tasks WHERE target_agent_id=? AND remote_task_id=?').get(targetId, String(task.id));
  const state = task.status?.state || fallbackState;
  if (existing) {
    if (existing.caller_agent_id !== callerId) return false;
    db.prepare(`UPDATE a2a_tasks SET state=?, task_json=?, context_id=?, updated_at=datetime('now') WHERE id=?`)
      .run(state, JSON.stringify(task), task.contextId || existing.context_id, existing.id);
  } else {
    db.prepare(`INSERT INTO a2a_tasks (id,context_id,vs_id,caller_agent_id,target_agent_id,remote_task_id,state,task_json)
                VALUES (?,?,?,?,?,?,?,?)`)
      .run(uuidv4(), task.contextId || null, vsId, callerId, targetId, String(task.id), state, JSON.stringify(task));
  }
  return true;
}

function updateTaskState(targetId, callerId, remoteId, state) {
  db.prepare(`UPDATE a2a_tasks SET state=?, updated_at=datetime('now') WHERE target_agent_id=? AND caller_agent_id=? AND remote_task_id=?`)
    .run(state, targetId, callerId, String(remoteId));
}

// ── Audit ────────────────────────────────────────────────────────────────────

function audit(c, level, summary, extra = {}) {
  try {
    db.prepare('INSERT INTO event_log (id, vs_id, log_type, level, summary, data) VALUES (?,?,?,?,?,?)')
      .run(uuidv4(), c.vs.id, 'a2a_call', level, summary, JSON.stringify({
        agent_id: c.caller.id, agent_name: c.caller.name,
        target_agent_id: c.target.id, target_name: c.target.name,
        a2a_version: versionOf(c.target), method: c.method, user_status: c.user?.status, chain_depth: c.chain.length + 1, ...extra,
      }));
  } catch (e) { console.error('[A2A] audit failed:', e.message); }
}

// ── Remote call ──────────────────────────────────────────────────────────────

// Warden's identity always travels in X-Warden-Delegation. The agent's own credential (if configured)
// takes the Authorization header (bearer/basic) or its custom header; with no credential configured,
// Authorization carries the delegation token so agents that only verify Warden's JWT keep working.
// A decrypt failure throws, so a call never silently goes out without the credential it needs.
function outboundHeaders(target, delegation) {
  const h = { 'X-Warden-Delegation': delegation };
  const type = target.outbound_auth_type || 'none';
  if (type === 'none') { h.Authorization = `Bearer ${delegation}`; return h; }
  let secret;
  try { secret = decrypt(target.outbound_secret_enc); }
  catch { throw Object.assign(new Error('Stored credential for this agent cannot be decrypted (check WARDEN_SECRETS_KEY / key file)'), { config: true }); }
  if (type === 'bearer') h.Authorization = `Bearer ${secret}`;
  else if (type === 'basic') h.Authorization = `Basic ${Buffer.from(secret).toString('base64')}`;
  else if (type === 'header') h[target.outbound_auth_header] = secret;
  return h;
}

function callRemote(c, method, params, { stream = false, signal } = {}) {
  const token = keys.mintDelegationToken({
    callerId: c.caller.id, callerName: c.caller.name, targetId: c.target.id, vsId: c.vs.id,
    chain: c.chain, user: c.user?.status === 'verified' ? c.user.user : null,
  });
  const headers = {
    'Content-Type': 'application/json',
    ...(protoOf(c.target).sendsVersionHeader ? { 'A2A-Version': A2A_VERSION } : {}), // 0.3 has no such header
    Accept: stream ? 'text/event-stream' : 'application/json',
    ...outboundHeaders(c.target, token),
  };
  // The timeout bounds connect + time-to-response-headers. It is cleared once headers arrive so a
  // long-lived SSE stream is not cut off mid-body (non-stream bodies are small and arrive with headers).
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  return fetch(c.target.endpoint_url, {
    method: 'POST',
    headers,
    redirect: 'error', // never forward the credential to a redirect target
    body: JSON.stringify({ jsonrpc: '2.0', id: uuidv4(), method, params }),
    signal: signal ? AbortSignal.any([signal, ctl.signal]) : ctl.signal,
  }).finally(() => clearTimeout(timer));
}

// ── Streaming ────────────────────────────────────────────────────────────────

async function* sseEvents(body) {
  const dec = new TextDecoder();
  let buf = '';
  for await (const chunk of body) {
    buf += dec.decode(chunk, { stream: true });
    let m;
    while ((m = buf.match(/\r?\n\r?\n/))) {
      const raw = buf.slice(0, m.index);
      buf = buf.slice(m.index + m[0].length);
      const data = raw.split(/\r?\n/).filter(l => l.startsWith('data:')).map(l => l.slice(5).trimStart()).join('\n');
      if (data) yield data;
    }
  }
}

async function handleStream(req, res, rpc, c, method, params, outRun) {
  const ac = new AbortController();
  res.on('close', () => ac.abort());

  let r;
  try { r = await callRemote(c, method, params, { stream: true, signal: ac.signal }); }
  catch (e) {
    if (!e.config) recordFail(c.target.id);
    audit(c, 'error', `A2A ${method} target unreachable`, { decision: 'error', reason: e.message });
    return res.status(502).json(rpcError(rpc.id, ERR.INTERNAL, 'Target agent unreachable', { reason: e.message }));
  }
  if (!r.ok || !r.body || !(r.headers.get('content-type') || '').includes('text/event-stream')) {
    const j = r.ok ? await r.json().catch(() => null) : null;
    if (!r.ok) recordFail(c.target.id);
    return res.status(r.ok ? 200 : 502).json(j?.error ? { ...j, id: rpc.id } : rpcError(rpc.id, ERR.INTERNAL, 'Target did not return an event stream'));
  }
  recordOk(c.target.id);

  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  const send = (obj) => res.write(`data: ${JSON.stringify(obj)}\n\n`);
  const hb = setInterval(() => res.write(': keep-alive\n\n'), 15000);
  let events = 0;
  try {
    for await (const data of sseEvents(r.body)) {
      let msg; try { msg = JSON.parse(data); } catch { continue; }
      if (msg.error) { send({ ...msg, id: rpc.id }); break; }
      const proto = protoOf(c.target);
      const result = await scanResult(msg.result, outRun, versionOf(c.target));
      const evTask = proto.taskOfEvent(result);
      if (evTask && !saveTask(c.vs.id, c.target.id, c.caller.id, evTask, proto.submitted)) {
        send(rpcError(rpc.id, ERR.INTERNAL, 'Task id conflict')); break;
      }
      const evStatus = proto.statusOfEvent(result);
      if (evStatus?.taskId) updateTaskState(c.target.id, c.caller.id, evStatus.taskId, evStatus.status?.state);
      send({ jsonrpc: '2.0', id: rpc.id, result });
      events++;
    }
    audit(c, 'info', `A2A ${method} stream completed`, { stream_events: events }); // no decision: not scored twice
  } catch (e) {
    if (e.blocked) {
      ac.abort();
      audit(c, 'block', `A2A ${method} stream blocked by interceptor`, { decision: 'block', reason: e.message });
      send(rpcError(rpc.id, ERR.DENIED, 'Response blocked by interceptor', { reason: e.message }));
    } else if (!ac.signal.aborted) {
      recordFail(c.target.id);
      audit(c, 'error', `A2A ${method} stream failed`, { decision: 'error', reason: e.message });
      send(rpcError(rpc.id, ERR.INTERNAL, 'Stream from target failed', { reason: e.message }));
    }
  } finally {
    clearInterval(hb);
    res.end();
  }
}

// ── JSON-RPC endpoint ────────────────────────────────────────────────────────

router.post('/:vsId/:agentId', async (req, res) => {
  const rpc = req.body;
  if (!rpc || rpc.jsonrpc !== '2.0' || typeof rpc.method !== 'string') {
    return res.status(400).json(rpcError(rpc?.id, ERR.INVALID, 'Invalid JSON-RPC 2.0 request'));
  }
  const base = loadContext(req.params.vsId, req.params.agentId);
  if (!base) return res.status(404).json(rpcError(rpc.id, ERR.INVALID, 'Unknown virtual server or agent'));

  // This agent speaks one version. A2A-Version is optional (0.3 has no such header); when sent it must match.
  const version = versionOf(base.target);
  const proto = PROTOCOLS[version];
  const ver = req.headers['a2a-version'];
  if (ver && String(ver).split('.').slice(0, 2).join('.') !== version) {
    return res.status(400).json(rpcError(rpc.id, ERR.VERSION, `Unsupported A2A version "${ver}"; this agent speaks A2A ${version}`));
  }

  const auth = authenticateCaller(req, base.vs.id);
  if (auth.err) {
    // decision 'auth_failed' is deliberately not 'allow'/'deny', so failed logins are logged but never scored.
    audit({ ...base, caller: { id: null, name: null }, chain: [], method: rpc.method }, 'block',
      `A2A ${rpc.method} rejected: ${auth.err.message}`, { decision: 'auth_failed', reason: auth.err.message });
    return res.status(auth.err.status).json(rpcError(rpc.id, ERR.DENIED, auth.err.message));
  }

  // Loop/depth guard — best effort: only effective when agents forward Warden's delegation token.
  const fwdToken = req.headers['x-warden-delegation'] || req.headers.authorization;
  const inbound = fwdToken ? keys.verifyDelegationToken(fwdToken) : null;
  const chain = Array.isArray(inbound?.chain) ? inbound.chain : [];
  const c = { ...base, caller: auth.caller, chain, method: rpc.method };
  if (chain.includes(c.caller.id) || chain.length >= MAX_DEPTH) {
    audit(c, 'block', 'A2A call rejected: loop or depth limit', { decision: 'deny', reason: chain.includes(c.caller.id) ? 'cycle' : 'max depth' });
    return res.status(400).json(rpcError(rpc.id, ERR.DENIED, 'A2A delegation loop or maximum depth exceeded'));
  }

  const params = rpc.params || {};
  const INITIATING = [proto.send, proto.stream];
  const STREAMING = [proto.stream, proto.subscribe];
  const KNOWN = methodsOf(proto);
  if (!KNOWN.includes(rpc.method)) {
    if (proto.pushRe.test(rpc.method)) return res.json(rpcError(rpc.id, ERR.PUSH_UNSUPPORTED, 'Push notifications are not supported by this gateway'));
    if (rpc.method === proto.extCard) return res.json(rpcError(rpc.id, ERR.EXT_CARD, 'Extended agent card is not configured'));
    // A caller using the other version's method names is told which version this agent speaks.
    const other = Object.keys(PROTOCOLS).find(v => v !== version && methodsOf(PROTOCOLS[v]).includes(rpc.method));
    return res.json(rpcError(rpc.id, ERR.NO_METHOD, `Method not found: ${rpc.method}`,
      other ? { reason: `This agent is registered as A2A ${version}, but "${rpc.method}" is an A2A ${other} method. Use "${proto.send}" to send a message.` } : undefined));
  }

  // Policy
  const skill = params.metadata?.skillId || params.message?.metadata?.skillId;
  const verdict = evaluateA2aPolicy({
    vsId: c.vs.id, callerId: c.caller.id, targetId: c.target.id, skill, anySkill: !INITIATING.includes(rpc.method),
  });
  if (verdict.decision === 'deny') {
    audit(c, 'block', `A2A ${rpc.method} denied: ${verdict.reason}`, { decision: 'deny', reason: verdict.reason, policy_id: verdict.policy?.id, skill });
    return res.status(403).json(rpcError(rpc.id, ERR.DENIED, verdict.reason));
  }

  // User delegation (optional unless the matched policy requires it)
  c.user = await resolveUser(req, c.vs);
  const p = verdict.policy;
  if (p?.require_user && c.user.status !== 'verified') {
    const degradable = p.user_fail_mode === 'open' && c.user.status === 'unverified' && c.user.infra;
    if (!degradable) {
      const reason = c.user.status === 'absent' ? 'User token required by policy' : `User token could not be verified: ${c.user.reason}`;
      audit(c, 'block', `A2A ${rpc.method} denied: ${reason}`, { decision: 'deny', reason, policy_id: p.id, fail_mode: p.user_fail_mode });
      return res.status(401).json(rpcError(rpc.id, ERR.DENIED, reason));
    }
    c.userDegraded = true; // proceeding agent-only because the IdP is unavailable (policy opted in)
  }

  const featureOn = (f) => { try { return JSON.parse(c.vs.features_enabled || '["interceptors","policy"]').includes(f); } catch { return true; } };
  const callId = uuidv4();
  const mkRun = (direction) => async (text) => {
    const r = await pipeline.run(text, direction, c.vs.id, c.caller.id, callId, null);
    if (r.action === 'block') throw Object.assign(new Error(r.reason || 'Blocked by interceptor'), { blocked: true });
    return r.action === 'mask' ? r.text : text;
  };
  const noop = async (t) => t;
  const inRun  = featureOn('interceptors') ? mkRun('inbound')  : noop;
  const outRun = featureOn('interceptors') ? mkRun('outbound') : noop;
  const done = { policy_id: p?.id, skill, user_degraded: c.userDegraded || undefined };

  try {
    // Local-only method
    if (proto.list && rpc.method === proto.list) {
      const rows = db.prepare(`SELECT task_json FROM a2a_tasks WHERE vs_id=? AND target_agent_id=? AND caller_agent_id=? ORDER BY updated_at DESC LIMIT 100`)
        .all(c.vs.id, c.target.id, c.caller.id);
      const tasks = rows.map(r => JSON.parse(r.task_json));
      audit(c, 'info', 'A2A ListTasks', { decision: 'allow', ...done });
      return res.json({ jsonrpc: '2.0', id: rpc.id, result: { tasks, nextPageToken: '', pageSize: tasks.length, totalSize: tasks.length } });
    }

    // Ownership for task-addressed methods
    const taskId = INITIATING.includes(rpc.method) ? params.message?.taskId : params.id;
    if (taskId && !ownedTask(c.vs.id, c.target.id, c.caller.id, taskId)) {
      audit(c, 'warn', `A2A ${rpc.method}: task not found for caller`, { decision: 'deny', reason: 'task not owned', task_id: taskId });
      return res.json(rpcError(rpc.id, ERR.TASK_NOT_FOUND, 'Task not found'));
    }
    if (!taskId && !INITIATING.includes(rpc.method)) return res.json(rpcError(rpc.id, ERR.PARAMS, 'params.id is required'));

    let fwd = params;
    if (INITIATING.includes(rpc.method)) {
      if (!params.message || !Array.isArray(params.message.parts)) return res.json(rpcError(rpc.id, ERR.PARAMS, 'params.message with parts is required'));
      fwd = { ...params, message: await scanMessage(params.message, inRun) };
    }

    // Approval policy: hold the (already scanned) call as a ticket instead of forwarding it. Only initiating
    // calls get here; follow-ups on an owned task are allowed by the same policy.
    if (verdict.decision === 'approval') {
      const ttl = Number(p.approval_ttl_minutes) > 0 ? Number(p.approval_ttl_minutes) : 30;
      const timeoutAction = p.approval_timeout_action === 'approve' ? 'approve' : 'deny';
      const ticketId = uuidv4();
      const expiresAt = new Date(Date.now() + ttl * 60 * 1000).toISOString();
      const userOk = c.user.status === 'verified';
      db.prepare(`INSERT INTO approval_tickets
          (id, virtual_server_id, mcp_server_id, tool_name, tool_arguments, user_sub, user_groups, matched_policy_id,
           ttl_minutes, timeout_action, expires_at, agent_id, agent_name, kind, a2a_agent_id, a2a_method, a2a_params, a2a_chain, a2a_user)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'a2a',?,?,?,?,?)`).run(
        ticketId, c.vs.id, c.target.id, skill || rpc.method,
        JSON.stringify({ method: rpc.method, skill: skill || null, message: fwd.message }),
        userOk ? (c.user.user.sub || null) : null, JSON.stringify(userOk ? (c.user.user.groups || []) : []),
        p.id, ttl, timeoutAction, expiresAt, c.caller.id, c.caller.name,
        c.target.id, rpc.method, JSON.stringify(fwd), JSON.stringify(c.chain), userOk ? JSON.stringify(c.user.user) : null);
      audit(c, 'info', `A2A ${rpc.method} pending approval`, { decision: 'approval', reason: verdict.reason, ticket_id: ticketId, ...done });
      return res.status(202).json(rpcError(rpc.id, ERR.APPROVAL, 'Approval required', {
        reason: verdict.reason, ticket_id: ticketId, poll_url: `/api/approvals/${ticketId}/status`,
        expires_at: expiresAt, timeout_action: timeoutAction,
        ...(STREAMING.includes(rpc.method) ? { note: 'Streaming is not available for approval-gated calls: once approved, the call runs as a normal request and the ticket returns its result.' } : {}),
      }));
    }

    if (circuitOpen(c.target.id)) {
      audit(c, 'error', `A2A ${rpc.method}: circuit open`, { decision: 'error', reason: 'circuit open', ...done });
      return res.status(503).json(rpcError(rpc.id, ERR.INTERNAL, 'Target agent temporarily unavailable', { reason: 'circuit open' }));
    }

    if (STREAMING.includes(rpc.method)) {
      audit(c, 'info', `A2A ${rpc.method} started`, { decision: 'allow', ...done });
      return handleStream(req, res, rpc, c, rpc.method, fwd, outRun);
    }

    // Request/response
    let r;
    try { r = await callRemote(c, rpc.method, fwd); }
    catch (e) {
      if (!e.config) recordFail(c.target.id);
      audit(c, 'error', `A2A ${rpc.method} target unreachable`, { decision: 'error', reason: e.message, ...done });
      if (rpc.method === proto.get) {
        const row = ownedTask(c.vs.id, c.target.id, c.caller.id, params.id);
        if (row) return res.json({ jsonrpc: '2.0', id: rpc.id, result: { ...JSON.parse(row.task_json), metadata: { ...(JSON.parse(row.task_json).metadata || {}), 'warden.stale': true } } });
      }
      return res.status(502).json(rpcError(rpc.id, ERR.INTERNAL, 'Target agent unreachable', { reason: e.message }));
    }
    const j = await r.json().catch(() => null);
    if (!r.ok && !j?.error) {
      recordFail(c.target.id);
      return res.status(502).json(rpcError(rpc.id, ERR.INTERNAL, `Target returned HTTP ${r.status}`));
    }
    recordOk(c.target.id);
    if (j?.error) {
      audit(c, 'warn', `A2A ${rpc.method} remote error`, { decision: 'allow', remote_error: j.error.code, ...done });
      return res.json({ ...j, id: rpc.id });
    }

    const result = await scanResult(j.result, outRun, version);
    const task = proto.taskOfResult(result);
    if (task && !saveTask(c.vs.id, c.target.id, c.caller.id, task, proto.submitted)) {
      return res.status(409).json(rpcError(rpc.id, ERR.INTERNAL, 'Task id conflict'));
    }
    audit(c, 'info', `A2A ${rpc.method} ok`, { decision: 'allow', task_id: task?.id, task_state: task?.status?.state, ...done });
    return res.json({ jsonrpc: '2.0', id: rpc.id, result });
  } catch (e) {
    if (e.blocked) {
      audit(c, 'block', `A2A ${rpc.method} blocked by interceptor`, { decision: 'block', reason: e.message, ...done });
      return res.status(403).json(rpcError(rpc.id, ERR.DENIED, 'Blocked by interceptor', { reason: e.message }));
    }
    console.error('[A2A]', e);
    audit(c, 'error', `A2A ${rpc.method} internal error`, { decision: 'error', reason: e.message });
    if (!res.headersSent) return res.status(500).json(rpcError(rpc.id, ERR.INTERNAL, 'Internal error'));
  }
});

// ── Approved tickets ─────────────────────────────────────────────────────────

// Lifecycle events for a ticket (denied / expired / failed), without a live request to take context from.
function auditTicket(ticket, level, summary, extra = {}) {
  try {
    const target = db.prepare('SELECT id, name, protocol_version FROM a2a_agents WHERE id = ?').get(ticket.a2a_agent_id) || {};
    db.prepare('INSERT INTO event_log (id, vs_id, log_type, level, summary, data) VALUES (?,?,?,?,?,?)')
      .run(uuidv4(), ticket.virtual_server_id, 'a2a_call', level, summary, JSON.stringify({
        agent_id: ticket.agent_id, agent_name: ticket.agent_name, target_agent_id: ticket.a2a_agent_id, target_name: target.name,
        a2a_version: versionOf(target), method: ticket.a2a_method, ticket_id: ticket.id, ...extra,
      }));
  } catch (e) { console.error('[A2A] ticket audit failed:', e.message); }
}

/**
 * Forwards an approved ticket to the remote agent and returns the (scanned) JSON-RPC result.
 * Runs later, with no caller connection, so a streaming request is sent as the version's plain send.
 * Everything that could have changed since the request is re-checked, and any failure throws (the caller of
 * this function records it on the ticket): the agent still exists and is active, it is still assigned to the
 * virtual server, the calling agent is still active, and no forbid has been added in the meantime.
 */
async function executeApprovedTicket(ticket) {
  const target = db.prepare('SELECT * FROM a2a_agents WHERE id = ?').get(ticket.a2a_agent_id);
  if (!target || !target.is_active) throw new Error('The A2A agent is no longer available');
  const vs = db.prepare('SELECT * FROM virtual_servers WHERE id = ? AND is_active = 1').get(ticket.virtual_server_id);
  if (!vs || !['a2a', 'both'].includes(vs.protocol)) throw new Error('The virtual server is no longer available for A2A');
  if (!db.prepare('SELECT 1 FROM virtual_server_a2a_agents WHERE vs_id = ? AND a2a_agent_id = ?').get(vs.id, target.id)) {
    throw new Error('The A2A agent is no longer assigned to this virtual server');
  }
  const caller = db.prepare('SELECT id, name, is_active FROM agents WHERE id = ?').get(ticket.agent_id);
  if (!caller || !caller.is_active) throw new Error('The calling agent is disabled or no longer exists');

  const params = JSON.parse(ticket.a2a_params || '{}');
  const skill = params.metadata?.skillId || params.message?.metadata?.skillId;
  const verdict = evaluateA2aPolicy({ vsId: vs.id, callerId: caller.id, targetId: target.id, skill });
  if (verdict.decision === 'deny') throw new Error(`No longer permitted: ${verdict.reason}`);

  const version = versionOf(target);
  const proto = PROTOCOLS[version];
  const user = ticket.a2a_user ? JSON.parse(ticket.a2a_user) : null;
  const c = { vs, target, caller: { id: caller.id, name: caller.name }, chain: JSON.parse(ticket.a2a_chain || '[]'),
    user: user ? { status: 'verified', user } : { status: 'absent' }, method: proto.send };
  if (circuitOpen(target.id)) throw new Error('The A2A agent is temporarily unavailable (circuit open)');

  const interceptorsOn = (() => { try { return JSON.parse(vs.features_enabled || '["interceptors","policy"]').includes('interceptors'); } catch { return true; } })();
  const callId = uuidv4();
  const outRun = interceptorsOn
    ? async (text) => {
      const r = await pipeline.run(text, 'outbound', vs.id, caller.id, callId, null);
      if (r.action === 'block') throw Object.assign(new Error(r.reason || 'Blocked by interceptor'), { blocked: true });
      return r.action === 'mask' ? r.text : text;
    }
    : async (t) => t;

  let r;
  try { r = await callRemote(c, proto.send, params); }
  catch (e) { if (!e.config) recordFail(target.id); throw new Error(`Target agent unreachable: ${e.message}`); }
  const j = await r.json().catch(() => null);
  if (!r.ok && !j?.error) { recordFail(target.id); throw new Error(`Target returned HTTP ${r.status}`); }
  recordOk(target.id);
  if (j?.error) throw new Error(`The A2A agent returned an error (${j.error.code}): ${j.error.message}`);

  let result;
  try { result = await scanResult(j.result, outRun, version); }
  catch (e) {
    if (e.blocked) {
      audit(c, 'block', `A2A ${proto.send} response blocked by interceptor (after approval)`, { decision: 'block', reason: e.message, ticket_id: ticket.id });
      throw new Error(`Response blocked by interceptor: ${e.message}`);
    }
    throw e;
  }
  const task = proto.taskOfResult(result);
  if (task && !saveTask(vs.id, target.id, caller.id, task, proto.submitted)) throw new Error('Task id conflict');
  audit(c, 'info', `A2A ${proto.send} executed after approval`, { decision: 'allow', ticket_id: ticket.id, skill, task_id: task?.id, task_state: task?.status?.state });
  return result;
}

module.exports = router;
module.exports.wellKnown = wellKnown;
module.exports.executeApprovedTicket = executeApprovedTicket;
module.exports.auditTicket = auditTicket;
