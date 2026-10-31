'use strict';

const { DatabaseSync } = require('node:sqlite');
const express = require('express');
const path    = require('path');

const db = new DatabaseSync(path.join(__dirname, 'tickets.db'));

// ── Schema ────────────────────────────────────────────────────────────────────
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS tickets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    description TEXT    DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'open',
    priority    TEXT    NOT NULL DEFAULT 'medium',
    assignee    TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id  INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author     TEXT    NOT NULL DEFAULT 'Anonymous',
    body       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// ── Seed demo data on first run ───────────────────────────────────────────────
const count = db.prepare('SELECT COUNT(*) AS n FROM tickets').get().n;
if (count === 0) {
  const ins = db.prepare(`INSERT INTO tickets (title, description, status, priority, assignee) VALUES (?, ?, ?, ?, ?)`);
  ins.run('Login page crashes on mobile Safari',      'Users on iOS 17 report a blank screen after submitting the login form. Reproducible on Safari 17.',          'open',        'critical', 'arbmishra@deloitte.com');
  ins.run('Add dark mode support',                    'Design has approved the dark mode palette. Implement CSS variables across all pages.',                        'in_progress', 'medium',   '');
  ins.run('Improve search performance',               'Full-text search is timing out on queries > 3 words. Needs index tuning.',                                   'open',        'high',     '');
  ins.run('Update privacy policy page',               'Legal has sent updated GDPR text. Replace existing copy.',                                                    'resolved',    'low',      'arbmishra@deloitte.com');
  ins.run('Export tickets to CSV',                    'Users need to download their open tickets as a spreadsheet.',                                                 'open',        'medium',   '');
  ins.run('Fix broken pagination on audit log',       'Page 2 returns the same results as page 1.',                                                                  'in_progress', 'high',     'arbmishra@deloitte.com');
}

const app  = express();
const PORT = process.env.PORT || 4001;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Tickets ───────────────────────────────────────────────────────────────────

app.get('/api/tickets', (req, res) => {
  const { status, priority, q } = req.query;
  let sql    = 'SELECT * FROM tickets WHERE 1=1';
  const args = [];
  if (status   && status   !== 'all') { sql += ' AND status = ?';   args.push(status); }
  if (priority && priority !== 'all') { sql += ' AND priority = ?'; args.push(priority); }
  if (q) { sql += ' AND (title LIKE ? OR description LIKE ? OR assignee LIKE ?)'; args.push(`%${q}%`, `%${q}%`, `%${q}%`); }
  sql += ` ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC`;
  res.json(db.prepare(sql).all(...args));
});

app.get('/api/tickets/:id', (req, res) => {
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(req.params.id);
  if (!ticket) return res.status(404).json({ error: 'Not found' });
  const comments = db.prepare('SELECT * FROM comments WHERE ticket_id = ? ORDER BY created_at').all(Number(req.params.id));
  res.json({ ...ticket, comments });
});

app.post('/api/tickets', (req, res) => {
  const { title, description, status, priority, assignee } = req.body;
  if (!title?.trim()) return res.status(400).json({ error: 'title is required' });
  const result = db.prepare(`INSERT INTO tickets (title, description, status, priority, assignee) VALUES (?, ?, ?, ?, ?)`)
    .run(title.trim(), description || '', status || 'open', priority || 'medium', assignee || '');
  res.status(201).json({ id: Number(result.lastInsertRowid) });
});

app.put('/api/tickets/:id', (req, res) => {
  if (!db.prepare('SELECT id FROM tickets WHERE id = ?').get(req.params.id)) return res.status(404).json({ error: 'Not found' });
  const { title, description, status, priority, assignee } = req.body;
  db.prepare(`UPDATE tickets SET
    title       = COALESCE(?, title),
    description = COALESCE(?, description),
    status      = COALESCE(?, status),
    priority    = COALESCE(?, priority),
    assignee    = COALESCE(?, assignee),
    updated_at  = datetime('now')
    WHERE id = ?`).run(title ?? null, description ?? null, status ?? null, priority ?? null, assignee ?? null, Number(req.params.id));
  res.json({ ok: true });
});

app.delete('/api/tickets/:id', (req, res) => {
  db.prepare('DELETE FROM tickets WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// ── Comments ──────────────────────────────────────────────────────────────────

app.post('/api/tickets/:id/comments', (req, res) => {
  if (!db.prepare('SELECT id FROM tickets WHERE id = ?').get(req.params.id)) return res.status(404).json({ error: 'Not found' });
  const { body, author } = req.body;
  if (!body?.trim()) return res.status(400).json({ error: 'body is required' });
  const result = db.prepare('INSERT INTO comments (ticket_id, author, body) VALUES (?, ?, ?)')
    .run(Number(req.params.id), author?.trim() || 'Anonymous', body.trim());
  res.status(201).json({ id: Number(result.lastInsertRowid) });
});

app.delete('/api/tickets/:id/comments/:cid', (req, res) => {
  db.prepare('DELETE FROM comments WHERE id = ? AND ticket_id = ?').run(Number(req.params.cid), Number(req.params.id));
  res.json({ ok: true });
});

// ── Stats ─────────────────────────────────────────────────────────────────────

app.get('/api/stats', (_req, res) => {
  res.json({
    total:      db.prepare('SELECT COUNT(*) AS n FROM tickets').get().n,
    byStatus:   db.prepare('SELECT status, COUNT(*) AS n FROM tickets GROUP BY status').all(),
    byPriority: db.prepare('SELECT priority, COUNT(*) AS n FROM tickets GROUP BY priority').all(),
  });
});

// ── SPA fallback ──────────────────────────────────────────────────────────────
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

app.listen(PORT, () => console.log(`\n✅  Warden Tickets  →  http://localhost:${PORT}\n`));
