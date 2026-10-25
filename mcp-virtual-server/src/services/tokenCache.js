const crypto = require('crypto');
const { createClient } = require('redis');

const REFRESH_THRESHOLD = parseFloat(process.env.OBO_REFRESH_THRESHOLD || '0.8');

let redisClient = null;
let redisAvailable = false;
// After a connection failure, wait before retrying so every request
// doesn't block waiting for a timeout when Redis is not running.
let redisNextRetry = 0;
const REDIS_RETRY_INTERVAL_MS = 30_000;

// Fallback in-memory cache when Redis is unavailable
const memCache = new Map();

async function getRedisClient() {
  // Already connected and healthy
  if (redisClient && redisAvailable) return redisClient;

  // Back-off: skip retry until the interval has elapsed
  if (Date.now() < redisNextRetry) return null;

  try {
    redisClient = createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      socket: {
        connectTimeout: 2000,    // give up after 2 s if Redis isn't there
        reconnectStrategy: false, // don't retry — fall back to in-memory immediately
      },
    });
    redisClient.on('error', (err) => {
      if (redisAvailable) {
        console.warn('[TokenCache] Redis disconnected, falling back to in-memory cache:', err.message);
        redisAvailable = false;
        redisNextRetry = Date.now() + REDIS_RETRY_INTERVAL_MS;
      }
    });
    redisClient.on('ready', () => {
      redisAvailable = true;
      redisNextRetry = 0;
      console.log('[TokenCache] Redis connected');
    });
    await redisClient.connect();
    redisAvailable = true;
  } catch (err) {
    console.warn('[TokenCache] Redis unavailable, using in-memory cache:', err.message);
    redisClient = null;
    redisAvailable = false;
    // Don't retry for 30 s — use in-memory cache until then
    redisNextRetry = Date.now() + REDIS_RETRY_INTERVAL_MS;
  }

  return redisClient;
}

// Hash the user access token — never store raw tokens as keys
function cacheKey(accessToken) {
  return 'obo:' + crypto.createHash('sha256').update(accessToken).digest('hex');
}

async function getOboToken(accessToken) {
  const key = cacheKey(accessToken);
  let entry = null;

  try {
    const client = await getRedisClient();
    if (redisAvailable && client) {
      const raw = await client.get(key);
      if (raw) entry = JSON.parse(raw);
    } else {
      entry = memCache.get(key);
    }
  } catch (err) {
    console.warn('[TokenCache] Cache read error:', err.message);
    entry = memCache.get(key);
  }

  if (!entry) return null;

  const now = Date.now();
  const lifetime = entry.expires_at - entry.issued_at;
  const elapsed = now - entry.issued_at;

  // Return null if past refresh threshold — caller should do OBO exchange
  if (elapsed >= lifetime * REFRESH_THRESHOLD) return null;

  return entry.obo_token;
}

async function setOboToken(accessToken, oboToken, expiresInSeconds) {
  const key = cacheKey(accessToken);
  const now = Date.now();
  const entry = {
    obo_token: oboToken,
    issued_at: now,
    expires_at: now + expiresInSeconds * 1000,
  };

  try {
    const client = await getRedisClient();
    if (redisAvailable && client) {
      // Expire the Redis key at the same time the token expires
      await client.set(key, JSON.stringify(entry), { EX: expiresInSeconds });
    } else {
      memCache.set(key, entry);
      // Clean up in-memory after expiry
      setTimeout(() => memCache.delete(key), expiresInSeconds * 1000);
    }
  } catch (err) {
    console.warn('[TokenCache] Cache write error:', err.message);
    memCache.set(key, entry);
    setTimeout(() => memCache.delete(key), expiresInSeconds * 1000);
  }
}

async function invalidateOboToken(accessToken) {
  const key = cacheKey(accessToken);
  try {
    const client = await getRedisClient();
    if (redisAvailable && client) await client.del(key);
    memCache.delete(key);
  } catch (err) {
    console.warn('[TokenCache] Cache delete error:', err.message);
    memCache.delete(key);
  }
}

module.exports = { getOboToken, setOboToken, invalidateOboToken };
