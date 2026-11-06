'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { fetchCard, parseCard } = require('../services/a2aCards');

const { encrypt } = require('../services/secrets');

const router = express.Router();

const AUTH_TYPES = ['none', 'bearer', 'header', 'basic'];
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/;
const FORBIDDEN_HEADERS = ['host', 'content-length', 'content-type', 'accept', 'a2a-version', 'x-warden-delegation', 'transfer-encoding', 'connection'];

// Validates an {type, header, secret} object. Returns {error} or the column values.
// secret undefined = keep the stored secret (only meaningful on update).
function parseAuth(a, cur = {}) {
  if (!a || typeof a !== 'object') return { error: 'auth must be an object' };
  const type = a.type ?? cur.outbound_auth_type ?? 'none';
  if (!AUTH_TYPES.includes(type)) return { error: `auth.type must be one of ${AUTH_TYPES.join(', ')}` };
  if (type === 'none') return { type, header: null, enc: null };
  let header = null;
  if (type === 'header') {
    header = String(a.header ?? cur.outbound_auth_header ?? '').trim();
    if (!HEADER_NAME.test(header)) return { error: 'auth.header must be a valid header name' };
    if (FORBIDDEN_HEADERS.includes(header.toLowerCase())) return { error: `auth.header "${header}" is reserved` };
  }
  let enc = cur.outbound_secret_enc || null;
  if (a.secret !== undefined && a.secret !== '') {
    if (type === 'basic' && !String(a.secret).includes(':')) return { error: 'For basic auth the secret must be "username:password"' };
    enc = encrypt(a.secret);
  }
  if (!enc) return { error: 'auth.secret is required' };
  return { type, header, enc };
}

function shape(row) {
  let skills = [];
  try { skills = parseCard(JSON.parse(row.card_json)).skills; } catch {}
  return {
    id: row.id, name: row.name, description: row.description,
    card_url: row.card_url, endpoint_url: row.endpoint_url, skills,
    is_active: row.is_active, card_fetched_at: row.card_fetched_at, card_error: row.card_error,
    created_at: row.created_at, vs_count: row.vs_count ?? 0,
    auth_type: row.outbound_auth_type || 'none',
    auth_header: row.outbound_auth_header || null,
    has_secret: !!row.outbound_secret_enc, // the secret itself is never returned
  };
}

const LIST_SQL = `
  SELECT a.*, (SELECT COUNT(*) FROM virtual_server_a2a_agents v WHERE v.a2a_agent_id = a.id) AS vs_count
  FROM a2a_agents a`;

router.get('/', (_req, res) => {
  res.json(db.prepare(`${LIST_SQL} ORDER BY a.created_at DESC`).all().map(shape));
});

router.get('/:id', (req, res) => {
  const row = db.prepare(`${LIST_SQL} WHERE a.id = ?`).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'A2A agent not found' });
  res.json({ ...shape(row), card: JSON.parse(row.card_json) });
});

// Register by card URL (fetched server-side) or by pasted card_json.
router.post('/', async (req, res) => {
  const { name, card_url, card_json, auth } = req.body;
  if (!card_url && !card_json) return res.status(400).json({ error: 'card_url or card_json is required' });
  const a = auth ? parseAuth(auth) : { type: 'none', header: null, enc: null };
  if (a.error) return res.status(400).json({ error: a.error });
  let card;
  try {
    card = card_json ? (typeof card_json === 'string' ? JSON.parse(card_json) : card_json) : await fetchCard(card_url);
  } catch (e) {
    return res.status(502).json({ error: e.message });
  }
  let parsed;
  try { parsed = parseCard(card); } catch (e) { return res.status(400).json({ error: e.message }); }

  const id = uuidv4();
  try {
    db.prepare(`INSERT INTO a2a_agents (id,name,description,card_url,card_json,endpoint_url,card_fetched_at,outbound_auth_type,outbound_auth_header,outbound_secret_enc)
                VALUES (?,?,?,?,?,?,?,?,?,?)`)
      .run(id, (name || parsed.name).trim(), parsed.description, card_url || null,
           JSON.stringify(card), parsed.endpoint_url, new Date().toISOString(), a.type, a.header, a.enc);
    res.status(201).json({ id });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'An A2A agent with that name already exists' });
    throw err;
  }
});

// Re-fetch the card. On failure the cached card is kept and the error is recorded.
router.post('/:id/refresh', async (req, res) => {
  const row = db.prepare('SELECT * FROM a2a_agents WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'A2A agent not found' });
  if (!row.card_url) return res.status(400).json({ error: 'Agent was registered from pasted JSON; no card_url to refresh' });
  try {
    const card = await fetchCard(row.card_url);
    const parsed = parseCard(card);
    db.prepare(`UPDATE a2a_agents SET card_json=?, endpoint_url=?, description=?, card_fetched_at=?, card_error=NULL WHERE id=?`)
      .run(JSON.stringify(card), parsed.endpoint_url, parsed.description, new Date().toISOString(), row.id);
    res.json({ ok: true });
  } catch (e) {
    db.prepare('UPDATE a2a_agents SET card_error=? WHERE id=?').run(e.message, row.id);
    res.status(502).json({ error: e.message, note: 'Cached card retained' });
  }
});

// Set / change / clear the credential Warden presents to this remote agent.
// Omit auth.secret to keep the stored one (e.g. when only changing the header name).
router.put('/:id/auth', (req, res) => {
  const cur = db.prepare('SELECT * FROM a2a_agents WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'A2A agent not found' });
  const a = parseAuth(req.body, cur);
  if (a.error) return res.status(400).json({ error: a.error });
  db.prepare('UPDATE a2a_agents SET outbound_auth_type=?, outbound_auth_header=?, outbound_secret_enc=? WHERE id=?')
    .run(a.type, a.header, a.enc, cur.id);
  res.json({ ok: true });
});

router.patch('/:id/toggle', (req, res) => {
  const row = db.prepare('SELECT id, is_active FROM a2a_agents WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'A2A agent not found' });
  const next = row.is_active ? 0 : 1;
  db.prepare('UPDATE a2a_agents SET is_active=? WHERE id=?').run(next, row.id);
  res.json({ is_active: next === 1 });
});

router.delete('/:id', (req, res) => {
  db.prepare('DELETE FROM a2a_agents WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

module.exports = router;
