'use strict';
/**
 * reset_user_score.js
 *
 * Resets a user's interceptor event history so their computed risk score
 * lands at TARGET_SCORE, then disarms all Warden Function trigger states
 * so the trigger will fire again on the next crossing.
 *
 * Usage:
 *   node scripts/reset_user_score.js
 *
 * Run from: mcp-virtual-server/
 */

const { DatabaseSync } = require('node:sqlite');
const { randomUUID }   = require('crypto');
const path             = require('path');

// ── CONFIGURE ─────────────────────────────────────────────────────────────────
const USER_EMAIL   = 'arbindtest@gmail.com';   // ← change to target user
const TARGET_SCORE = 402;                       // ← set above your trigger threshold
// ─────────────────────────────────────────────────────────────────────────────

const BANKING_DB = path.resolve(__dirname, '../../banking-app/backend/banking.db');
const WARDEN_DB  = path.resolve(__dirname, '../data/virtual-server.db');

const wardenDb = new DatabaseSync(WARDEN_DB);

// ── 1. Look up the REAL user_sub from event_log (most reliable source) ────────
//    The event_log captures the actual Okta sub from the JWT as it passes
//    through the gateway — this is the canonical identity used for scoring.
let userRow = wardenDb.prepare(`
  SELECT
    json_extract(data,'$.user_sub')  AS user_sub,
    json_extract(data,'$.user_name') AS user_name
  FROM event_log
  WHERE log_type = 'interceptor'
    AND json_extract(data,'$.user_email') = ?
    AND json_extract(data,'$.user_sub') IS NOT NULL
  LIMIT 1
`).get(USER_EMAIL);

let userSub  = userRow?.user_sub  || null;
let userName = userRow?.user_name || null;

// ── 2. Fall back to banking DB if not seen in event_log yet ──────────────────
if (!userSub) {
  console.log(`No events found for ${USER_EMAIL} in event_log — trying banking DB…`);
  const bankingDb = new DatabaseSync(BANKING_DB);
  const bankRow   = bankingDb.prepare('SELECT okta_sub, name FROM users WHERE email = ?').get(USER_EMAIL);
  bankingDb.close();

  if (!bankRow) {
    console.error(`✗ No user found with email: ${USER_EMAIL}`);
    process.exit(1);
  }
  if (!bankRow.okta_sub) {
    console.error(`✗ User "${USER_EMAIL}" has no okta_sub — they have never authenticated.`);
    process.exit(1);
  }
  userSub  = bankRow.okta_sub;
  userName = bankRow.name;
}

console.log(`✓ User    : ${USER_EMAIL} (${userName || '?'})`);
console.log(`✓ user_sub: ${userSub}`);
console.log(`✓ Target  : ${TARGET_SCORE}\n`);

// ── 3. Calculate events needed ────────────────────────────────────────────────
// Score formula: starts at 500. pii_flag=-10, clean_scan=+2.
// To reach TARGET_SCORE: insert events that sum to (TARGET_SCORE - 500).
const BASE  = 500;
const PII   = -10;
const CLEAN = 2;
const delta = TARGET_SCORE - BASE;

let piiCount   = 0;
let cleanCount = 0;

if (delta < 0) {
  piiCount   = Math.ceil(-delta / -PII);
  cleanCount = Math.round((piiCount * -PII + delta) / CLEAN);
} else {
  cleanCount = Math.ceil(delta / CLEAN);
}

const computed = BASE + piiCount * PII + cleanCount * CLEAN;
console.log(`Events to insert: ${piiCount} pii_flag + ${cleanCount} clean_scan → score = ${computed}`);
if (computed !== TARGET_SCORE) {
  console.warn(`⚠ Cannot reach exactly ${TARGET_SCORE} — landing at ${computed}`);
}

// ── 4. Clear existing interceptor events for this user ────────────────────────
const del = wardenDb.prepare(`
  DELETE FROM event_log
  WHERE log_type = 'interceptor'
    AND json_extract(data, '$.user_sub') = ?
`).run(userSub);
console.log(`\n✓ Cleared ${del.changes} old interceptor event(s)`);

// ── 5. Insert pii_flag events ────────────────────────────────────────────────
const insEvent = wardenDb.prepare(
  `INSERT INTO event_log (id, log_type, level, summary, data) VALUES (?,?,?,?,?)`
);
for (let i = 0; i < piiCount; i++) {
  insEvent.run(
    randomUUID(), 'interceptor', 'warn', '[score-reset] PII detected',
    JSON.stringify({
      user_sub:    userSub,
      user_email:  USER_EMAIL,
      user_name:   userName || null,
      direction:   'inbound',
      flagged:     1,
      action_taken:'warn',
      categories:  ['pii'],
    })
  );
}

// ── 6. Insert clean_scan events ───────────────────────────────────────────────
for (let i = 0; i < cleanCount; i++) {
  insEvent.run(
    randomUUID(), 'interceptor', 'info', '[score-reset] Clean scan',
    JSON.stringify({
      user_sub:    userSub,
      user_email:  USER_EMAIL,
      user_name:   userName || null,
      direction:   'inbound',
      flagged:     0,
      action_taken:'allow',
      categories:  [],
    })
  );
}
console.log(`✓ Inserted ${piiCount} pii + ${cleanCount} clean event(s)`);

// ── 7. Disarm all trigger states for this user ────────────────────────────────
const disarm = wardenDb.prepare(
  `UPDATE warden_function_state SET armed = 0 WHERE user_sub = ?`
).run(userSub);
console.log(`✓ Disarmed ${disarm.changes} trigger state(s)`);

wardenDb.close();

console.log(`\n✅ Done — ${USER_EMAIL} score is now ~${computed}`);
console.log(`   Make one request through the gateway to evaluate triggers.`);
