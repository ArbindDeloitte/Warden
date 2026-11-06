'use strict';

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');

db.exec(`
  CREATE TABLE IF NOT EXISTS a2a_keys (
    kid         TEXT PRIMARY KEY,
    private_pem TEXT NOT NULL,
    public_jwk  TEXT NOT NULL,
    is_active   INTEGER DEFAULT 1,
    created_at  TEXT DEFAULT (datetime('now'))
  );
`);

const b64u = (b) => Buffer.from(b).toString('base64url');

function activeKey() {
  let row = db.prepare('SELECT * FROM a2a_keys WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1').get();
  if (!row) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const kid = uuidv4();
    const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'EdDSA', use: 'sig' };
    db.prepare('INSERT INTO a2a_keys (kid, private_pem, public_jwk) VALUES (?,?,?)')
      .run(kid, privateKey.export({ format: 'pem', type: 'pkcs8' }), JSON.stringify(jwk));
    row = db.prepare('SELECT * FROM a2a_keys WHERE kid = ?').get(kid);
  }
  return row;
}

// Short-lived token Warden sends to the target agent. Targets verify it offline via /.well-known/jwks.json.
function mintDelegationToken({ callerId, callerName, targetId, vsId, chain = [], user = null, ttlSec = 60 }) {
  const key = activeKey();
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'EdDSA', typ: 'JWT', kid: key.kid };
  const payload = {
    iss: 'warden', sub: callerId, agent_name: callerName, aud: targetId, vs: vsId,
    iat: now, exp: now + ttlSec, jti: uuidv4(),
    chain: [...chain, callerId], depth: chain.length + 1,
    ...(user ? { user } : {}),
  };
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const sig = crypto.sign(null, Buffer.from(signingInput), crypto.createPrivateKey(key.private_pem));
  return `${signingInput}.${b64u(sig)}`;
}

function verifyDelegationToken(token) {
  try {
    const [h, p, s] = String(token || '').replace(/^Bearer\s+/i, '').split('.');
    if (!h || !p || !s) return null;
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    if (header.alg !== 'EdDSA') return null;
    const row = db.prepare('SELECT public_jwk FROM a2a_keys WHERE kid = ?').get(header.kid);
    if (!row) return null;
    const pub = crypto.createPublicKey({ key: JSON.parse(row.public_jwk), format: 'jwk' });
    if (!crypto.verify(null, Buffer.from(`${h}.${p}`), pub, Buffer.from(s, 'base64url'))) return null;
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (payload.iss !== 'warden' || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

function jwks() {
  activeKey();
  const keys = db.prepare('SELECT public_jwk FROM a2a_keys ORDER BY created_at DESC').all()
    .map(r => JSON.parse(r.public_jwk));
  return { keys };
}

module.exports = { mintDelegationToken, verifyDelegationToken, jwks };
