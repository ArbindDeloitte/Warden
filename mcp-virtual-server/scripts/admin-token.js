'use strict';

// Creates (or rotates) Warden's admin token and stores it in mcp-virtual-server/.env as WARDEN_ADMIN_TOKEN.
// The token is never printed unless you ask (--show). Restart Warden afterwards: it reads .env at startup.
//
//   node scripts/admin-token.js            create one if none exists
//   node scripts/admin-token.js --rotate   replace it (every signed-in session ends)
//   node scripts/admin-token.js --show     print the current token
//   node scripts/admin-token.js --status   say whether one is set, and its length
//   node scripts/admin-token.js --env-file <path>   use another .env (tests)

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const envFile = args.includes('--env-file') ? path.resolve(args[args.indexOf('--env-file') + 1]) : path.join(__dirname, '..', '.env');
const KEY = 'WARDEN_ADMIN_TOKEN';

const text = fs.existsSync(envFile) ? fs.readFileSync(envFile, 'utf8') : '';
const lineRe = new RegExp(`^${KEY}=(.*)$`, 'm');
const current = (lineRe.exec(text)?.[1] || '').trim();

if (flag('--status')) {
  console.log(current ? `WARDEN_ADMIN_TOKEN is set (${current.length} characters) in ${envFile}` : `WARDEN_ADMIN_TOKEN is NOT set in ${envFile}: the admin API is unauthenticated.`);
  process.exit(0);
}
if (flag('--show')) {
  if (!current) { console.error('No admin token is set.'); process.exit(1); }
  console.log(current);
  process.exit(0);
}
if (current && !flag('--rotate')) {
  console.log(`An admin token is already set in ${envFile}. Use --rotate to replace it, or --show to read it.`);
  process.exit(0);
}

const token = crypto.randomBytes(32).toString('hex');
const next = current
  ? text.replace(lineRe, `${KEY}=${token}`)
  : `${text}${text && !text.endsWith('\n') ? '\n' : ''}\n# Warden admin API token. Required (X-Admin-Token, or sign in to the UI) once set. Keep this file private.\n${KEY}=${token}\n`;
fs.writeFileSync(envFile, next, { mode: 0o600 });
console.log(`${current ? 'Rotated' : 'Created'} the admin token in ${envFile} (${token.length} characters; not shown).`);
console.log('Restart Warden so it takes effect, then sign in to the UI with the value from that file.');
