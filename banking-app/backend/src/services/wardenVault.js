// Runtime client for the Warden Credential Vault. It authenticates as one Warden agent (the agent's own
// token is the bootstrap credential); everything else is checked out on demand under that agent's vault
// policy and kept in memory only until its lease is about to expire. Values are never logged.

export class WardenVaultError extends Error {
  constructor(message, { status = null } = {}) {
    super(message);
    this.name = 'WardenVaultError';
    this.status = status;
  }
}

const MAX_SKEW_MS = 5000;

export function createVaultClient({ baseUrl, agentToken, fetchImpl = fetch, now = () => Date.now(), timeoutMs = 8000 }) {
  const cache = new Map();    // secret name -> { value, freshUntil }
  const inflight = new Map(); // secret name -> Promise<string>, so concurrent callers share one checkout

  async function checkout(name) {
    if (!agentToken) {
      throw new WardenVaultError('No Warden agent token is available to read the vault');
    }
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    let res;
    try {
      res = await fetchImpl(`${baseUrl}/api/vault/checkout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Agent-Token': agentToken },
        body: JSON.stringify({ secret: name }),
        redirect: 'error', // never forward the agent token to a redirect target
        signal: ctl.signal,
      });
    } catch (e) {
      throw new WardenVaultError(`Could not reach the Warden vault (${e.name === 'AbortError' ? 'timed out' : e.message})`);
    } finally {
      clearTimeout(timer);
    }

    let body = null;
    try { body = await res.json(); } catch { /* handled below */ }
    if (!res.ok) throw new WardenVaultError(body?.error || `Vault request failed (HTTP ${res.status})`, { status: res.status });
    if (typeof body?.value !== 'string' || !(body.ttl_seconds > 0)) throw new WardenVaultError('Unexpected response from the Warden vault');

    // Use the lease length (not expires_at) so clock skew between hosts cannot extend or shorten the cache.
    const ttlMs = body.ttl_seconds * 1000;
    cache.set(name, { value: body.value, freshUntil: now() + ttlMs - Math.min(MAX_SKEW_MS, ttlMs * 0.2) });
    return body.value;
  }

  async function getSecret(name) {
    const hit = cache.get(name);
    if (hit && now() < hit.freshUntil) return hit.value;
    if (inflight.has(name)) return inflight.get(name);
    const p = checkout(name).finally(() => inflight.delete(name));
    inflight.set(name, p);
    return p;
  }

  return {
    getSecret,
    invalidate: (name) => (name ? cache.delete(name) : cache.clear()),
  };
}
