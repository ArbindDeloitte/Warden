'use strict';

// AES-256-GCM encryption for credentials stored in SQLite. The key lives OUTSIDE the database
// (env WARDEN_SECRETS_KEY, or an auto-generated key file) so a leaked DB alone exposes nothing.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let cachedKey = null;

function getKey() {
  if (cachedKey) return cachedKey;
  if (process.env.WARDEN_SECRETS_KEY) {
    cachedKey = crypto.createHash('sha256').update(process.env.WARDEN_SECRETS_KEY).digest();
    return cachedKey;
  }
  const dir = process.env.SQLITE_PATH ? path.dirname(path.resolve(process.env.SQLITE_PATH)) : path.join(__dirname, '../../data');
  const file = path.join(dir, '.warden-secrets.key');
  fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(file)) fs.writeFileSync(file, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  cachedKey = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex');
  return cachedKey;
}

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return ['v1', iv.toString('base64'), c.getAuthTag().toString('base64'), ct.toString('base64')].join(':');
}

function decrypt(blob) {
  const [v, iv, tag, ct] = String(blob).split(':');
  if (v !== 'v1') throw new Error('Unsupported secret format');
  const d = crypto.createDecipheriv('aes-256-gcm', getKey(), Buffer.from(iv, 'base64'));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64')), d.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt };
