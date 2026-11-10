'use strict';

// Credential Vault. Secrets are global; every read is gated by vault_policies (deny-by-default) and
// audited to event_log as 'vault_access'. Audit rows never contain secret values.
//
//   reveal  - agent fetches the value at runtime (POST /api/vault/checkout) and gets a lease
//   broker  - Warden injects the value itself (vault:// refs in tool arguments / upstream auth);
//             the agent never sees it
//   sign    - Warden signs a JWT with a stored private key; only the JWT leaves the vault

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { encrypt, decrypt } = require('./secrets');
const { evaluateVaultPolicy } = require('./vaultPolicy');

const REF_PREFIX = 'vault://';
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SECRET_TYPES = ['generic', 'api_key', 'password', 'bearer_token', 'oauth_client', 'private_key'];
const OPERATIONS = ['reveal', 'broker', 'sign'];
const SIGN_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'];
const DEFAULT_TTL = 300;
const MAX_TTL = 3600;
// Redacting very short values would mangle ordinary text, so they are exempt.
const MIN_REDACT_LEN = 8;

const DENIED_MESSAGE = 'Vault access denied: the secret does not exist or this agent is not permitted to use it';

class VaultError extends Error {
  constructor(message, { status = 403, code = 'denied', secret = null } = {}) {
    super(message);
    this.name = 'VaultError';
    this.status = status;
    this.code = code;
    this.secret = secret;
  }
}

function audit(level, summary, vsId, data) {
  try {
    db.prepare('INSERT INTO event_log (id, vs_id, log_type, level, summary, data) VALUES (?,?,?,?,?,?)')
      .run(uuidv4(), vsId || null, 'vault_access', level, summary, JSON.stringify(data));
  } catch (e) { console.error('[Vault] audit failed:', e.message); }
}

function parseJson(raw, fallback) {
  try { return raw ? JSON.parse(raw) : fallback; } catch { return fallback; }
}

function refName(v) {
  return typeof v === 'string' && v.startsWith(REF_PREFIX) && NAME_RE.test(v.slice(REF_PREFIX.length))
    ? v.slice(REF_PREFIX.length) : null;
}
const isRef = (v) => refName(v) !== null;

function issueLease(secret, ctx, op, policy, requestedTtl) {
  const policyMax = Math.min(policy?.max_ttl_seconds > 0 ? policy.max_ttl_seconds : DEFAULT_TTL, MAX_TTL);
  let ttl = Number(requestedTtl) > 0 ? Math.min(Math.floor(Number(requestedTtl)), policyMax) : policyMax;
  if (secret.expires_at) {
    ttl = Math.min(ttl, Math.max(1, Math.floor((Date.parse(secret.expires_at) - Date.now()) / 1000)));
  }
  const issued = new Date();
  const lease = {
    id: uuidv4(), issued_at: issued.toISOString(),
    expires_at: new Date(issued.getTime() + ttl * 1000).toISOString(), ttl_seconds: ttl,
  };
  db.prepare(`INSERT INTO vault_leases (id, secret_id, secret_version, agent_id, vs_id, operation, policy_id, issued_at, expires_at)
              VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(lease.id, secret.id, secret.version, ctx.agentId, ctx.vsId || null, op, policy?.id || null, lease.issued_at, lease.expires_at);
  return lease;
}

/**
 * Policy-checked, audited secret read.
 * ctx = { agentId, agentName, vsId } for an agent, or { system: true } for Warden's own use
 * (e.g. the virtual server's OBO client secret), which bypasses agent policy but is still audited.
 * Throws VaultError. For agents, "not found", "disabled", "expired" and "denied" are deliberately
 * indistinguishable so a caller cannot enumerate secret names; the audit log keeps the real reason.
 */
function access(ctx, name, op, via, { ttl } = {}) {
  const base = {
    operation: op, via, secret_name: name,
    agent_id: ctx.agentId || null, agent_name: ctx.agentName || null,
    principal: ctx.system ? 'system' : 'agent',
  };
  const who = ctx.system ? 'system' : (ctx.agentName || ctx.agentId || 'anonymous');

  const deny = (reason, secret, status = 403, code = 'denied') => {
    audit('warn', `${op} denied: ${name} (${who})`, ctx.vsId, { ...base, secret_id: secret?.id || null, decision: 'deny', reason });
    throw new VaultError(ctx.system ? `Vault secret "${name}" unavailable: ${reason}` : DENIED_MESSAGE, { status, code, secret: name });
  };

  const secret = db.prepare('SELECT * FROM vault_secrets WHERE name = ?').get(name);
  if (!secret) deny('Secret not found');
  if (!secret.is_active) deny('Secret is disabled', secret);
  if (secret.expires_at && Date.parse(secret.expires_at) <= Date.now()) deny('Secret has expired', secret);

  let policy = null;
  if (!ctx.system) {
    if (!ctx.agentId) deny('Agent identity required (X-Agent-Token)', secret);
    const verdict = evaluateVaultPolicy({ agentId: ctx.agentId, secretId: secret.id, vsId: ctx.vsId || null, op });
    if (verdict.decision !== 'allow') deny(verdict.reason, secret);
    policy = verdict.policy;
  }

  let value;
  try { value = decrypt(secret.value_enc); }
  catch {
    audit('error', `${op} failed: ${name} (${who})`, ctx.vsId, { ...base, secret_id: secret.id, decision: 'error', reason: 'Stored value cannot be decrypted' });
    throw new VaultError('Stored secret cannot be decrypted (check WARDEN_SECRETS_KEY / key file)', { status: 500, code: 'decrypt', secret: name });
  }

  const lease = op === 'reveal' ? issueLease(secret, ctx, op, policy, ttl) : null;
  db.prepare('UPDATE vault_secrets SET last_accessed_at = ?, access_count = access_count + 1 WHERE id = ?')
    .run(new Date().toISOString(), secret.id);
  audit('info', `${op}: ${name} (${who})`, ctx.vsId, {
    ...base, secret_id: secret.id, version: secret.version, decision: 'allow',
    policy_id: policy?.id || null, policy_name: policy?.name || null, lease_id: lease?.id || null,
  });
  return { secret, value, policy, lease };
}

// ── Brokered injection ───────────────────────────────────────────────────────

function resolveOnce(ref, ctx, via, memo, injected) {
  const name = refName(ref);
  if (memo.has(name)) return memo.get(name);
  const { value } = access(ctx, name, 'broker', via);
  memo.set(name, value);
  injected.push({ name, value });
  return value;
}

// A string that is EXACTLY `vault://name` is replaced; embedded occurrences are left alone so ordinary
// text (URLs, prose) can never trigger a vault read. Object keys are never substituted.
function substitute(node, ctx, via, memo, injected) {
  if (typeof node === 'string') return isRef(node) ? resolveOnce(node, ctx, via, memo, injected) : node;
  if (Array.isArray(node)) return node.map(n => substitute(n, ctx, via, memo, injected));
  if (node && typeof node === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(node)) out[k] = substitute(v, ctx, via, memo, injected);
    return out;
  }
  return node;
}

function configHasRefs(config) {
  return !!config && typeof config === 'object' && Object.values(config).some(isRef);
}

function resolveConfig(config, ctx, via, memo = new Map(), injected = []) {
  const out = { ...config };
  for (const [k, v] of Object.entries(out)) if (isRef(v)) out[k] = resolveOnce(v, ctx, via, memo, injected);
  return out;
}

// Bearer/Basic would replace the OBO Authorization header, so they only apply when OBO is off.
function upstreamAuthHeaders(authType, config, hasObo) {
  if (authType === 'apikey' && config.header && config.key) return { [config.header]: config.key };
  if (hasObo) return {};
  if (authType === 'bearer' && config.token) return { Authorization: `Bearer ${config.token}` };
  if (authType === 'basic' && config.username && config.password) {
    return { Authorization: `Basic ${Buffer.from(`${config.username}:${config.password}`).toString('base64')}` };
  }
  return {};
}

/**
 * Resolves every vault:// reference a tool call needs: whole-string references inside the arguments and
 * the MCP server's auth_config. All-or-nothing — the first denied reference throws VaultError.
 * Plain (non-vault) auth_config is untouched, so existing servers behave exactly as before.
 */
function prepareToolCall({ args, mcpServer, ctx, hasObo, vaultEnabled = true }) {
  if (!vaultEnabled) {
    // The virtual server has the vault switched off: never consult it. `vault://` text in the arguments is
    // just text and passes through untouched. A server that NEEDS a vault credential is refused outright,
    // because sending the call without its credential would be worse than a clear error.
    if (configHasRefs(parseJson(mcpServer.auth_config, {}))) {
      const reason = 'The Credential Vault is disabled on this virtual server, but this MCP server is configured with a vault credential. Enable the vault on this virtual server, or use an MCP server entry without vault references.';
      audit('warn', `broker blocked: vault disabled (${ctx.agentName || ctx.agentId || 'anonymous'})`, ctx.vsId, {
        operation: 'broker', via: 'upstream_auth', principal: 'agent', agent_id: ctx.agentId || null, agent_name: ctx.agentName || null, decision: 'deny', reason,
      });
      throw new VaultError(reason, { status: 403, code: 'vault_disabled' });
    }
    return { args: args ?? {}, extraHeaders: {}, injected: [] };
  }
  const memo = new Map();
  const injected = [];
  const resolvedArgs = substitute(args ?? {}, ctx, 'tool_args', memo, injected);

  let extraHeaders = {};
  const config = parseJson(mcpServer.auth_config, {});
  if (configHasRefs(config)) {
    extraHeaders = upstreamAuthHeaders(mcpServer.auth_type, resolveConfig(config, ctx, 'upstream_auth', memo, injected), hasObo);
  }
  return { args: resolvedArgs, extraHeaders, injected };
}

/** Warden-owned secrets (OBO client secret, discovery credentials): resolve a ref, pass plain values through. */
function resolveSystemValue(value, via = 'system') {
  return isRef(value) ? access({ system: true }, refName(value), 'broker', via).value : value;
}

function resolveSystemConfig(config, via = 'discovery') {
  return configHasRefs(config) ? resolveConfig(config, { system: true }, via) : config;
}

/** Replaces injected secret values anywhere in strings of `node` so they cannot flow back to the caller. */
function redact(node, injected) {
  const targets = (injected || []).filter(i => i.value && i.value.length >= MIN_REDACT_LEN);
  if (!targets.length) return node;
  const walk = (n) => {
    if (typeof n === 'string') {
      let s = n;
      for (const t of targets) if (s.includes(t.value)) s = s.split(t.value).join(`[REDACTED:${REF_PREFIX}${t.name}]`);
      return s;
    }
    if (Array.isArray(n)) return n.map(walk);
    if (n && typeof n === 'object') return Object.fromEntries(Object.entries(n).map(([k, v]) => [k, walk(v)]));
    return n;
  };
  return walk(node);
}

// ── Sign-on-behalf ───────────────────────────────────────────────────────────

/**
 * Signs a JWT with a stored private key. iat/exp/jti are always set by Warden. For OAuth client
 * assertions, `client_id` and `token_url` in the secret's metadata supply default iss/sub and aud.
 */
function signJwt(ctx, name, { claims = {}, algorithm = 'RS256', expiresIn } = {}) {
  if (!SIGN_ALGORITHMS.includes(algorithm)) throw new VaultError(`algorithm must be one of ${SIGN_ALGORITHMS.join(', ')}`, { status: 400, code: 'bad_request' });
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) throw new VaultError('claims must be an object', { status: 400, code: 'bad_request' });

  const { secret, value } = access(ctx, name, 'sign', 'sign');
  if (secret.type !== 'private_key') {
    throw new VaultError(`Secret "${name}" is not a private_key and cannot sign`, { status: 400, code: 'bad_type', secret: name });
  }
  const meta = parseJson(secret.metadata, {});
  const payload = { ...claims };
  if (meta.client_id) { payload.iss = payload.iss ?? meta.client_id; payload.sub = payload.sub ?? meta.client_id; }
  if (meta.token_url) payload.aud = payload.aud ?? meta.token_url;

  const ttl = Math.min(Math.max(Math.floor(Number(expiresIn)) || DEFAULT_TTL, 1), MAX_TTL);
  const now = Math.floor(Date.now() / 1000);
  payload.iat = now;
  payload.exp = now + ttl;
  payload.jti = uuidv4();

  let token;
  try {
    token = jwt.sign(payload, value, { algorithm, header: meta.kid ? { kid: meta.kid } : undefined });
  } catch (e) {
    throw new VaultError(`Signing failed: ${e.message}`, { status: 400, code: 'sign_failed', secret: name });
  }
  return { token, expires_at: new Date((now + ttl) * 1000).toISOString(), kid: meta.kid || null, algorithm };
}

// ── Admin helpers ────────────────────────────────────────────────────────────

/** Rejects a private_key that cannot be parsed so a bad paste fails at write time, not at sign time. */
function validateSecretValue(type, value) {
  if (typeof value !== 'string' || !value.length) return 'value is required';
  if (value.length > 65536) return 'value is too large (max 64 KB)';
  if (type === 'private_key') {
    try { crypto.createPrivateKey(value); } catch { return 'value is not a valid PEM private key'; }
  }
  return null;
}

module.exports = {
  VaultError, REF_PREFIX, NAME_RE, SECRET_TYPES, OPERATIONS, SIGN_ALGORITHMS, DEFAULT_TTL, MAX_TTL,
  isRef, refName, access, prepareToolCall, resolveSystemValue, resolveSystemConfig, redact, signJwt,
  validateSecretValue, encrypt, parseJson, audit,
};
