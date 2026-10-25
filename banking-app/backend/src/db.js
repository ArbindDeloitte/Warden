/**
 * db.js — SQLite database layer using Node.js built-in `node:sqlite`
 *
 * Node.js 22.5+ ships with a synchronous SQLite API (DatabaseSync) that
 * requires no native compilation.  The API is almost identical to
 * better-sqlite3:  prepare / .get / .all / .run / .transaction all work
 * the same way.
 */
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'url';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbPath = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.resolve(__dirname, '..', 'banking.db');

/** @type {DatabaseSync | undefined} */
let db;

export function getDb() {
  if (!db) {
    db = new DatabaseSync(dbPath);
    db.exec("PRAGMA journal_mode = WAL");
    db.exec("PRAGMA foreign_keys = ON");
  }
  return db;
}

export function initDatabase() {
  const database = getDb();

  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      okta_sub TEXT UNIQUE NOT NULL,
      email TEXT,
      name TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      account_number TEXT UNIQUE NOT NULL,
      account_name TEXT NOT NULL,
      account_type TEXT NOT NULL CHECK(account_type IN ('checking','savings','credit')),
      currency TEXT NOT NULL DEFAULT 'USD',
      balance REAL NOT NULL DEFAULT 0,
      available_balance REAL NOT NULL DEFAULT 0,
      sort_code TEXT,
      iban TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id),
      amount REAL NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      type TEXT NOT NULL CHECK(type IN ('debit','credit')),
      category TEXT,
      description TEXT NOT NULL,
      merchant TEXT,
      status TEXT NOT NULL DEFAULT 'completed',
      reference TEXT,
      transaction_date TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS payments (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      from_account_id TEXT NOT NULL REFERENCES accounts(id),
      to_account TEXT NOT NULL,
      to_name TEXT NOT NULL,
      amount REAL NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      reference TEXT,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','completed','rejected')),
      initiated_at TEXT DEFAULT (datetime('now')),
      approved_at TEXT,
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS standing_orders (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      from_account_id TEXT NOT NULL REFERENCES accounts(id),
      to_account TEXT NOT NULL,
      to_name TEXT NOT NULL,
      amount REAL NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      frequency TEXT NOT NULL CHECK(frequency IN ('daily','weekly','monthly','quarterly')),
      start_date TEXT NOT NULL,
      end_date TEXT,
      next_payment_date TEXT,
      reference TEXT,
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','cancelled')),
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS statements (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL REFERENCES accounts(id),
      period_start TEXT NOT NULL,
      period_end TEXT NOT NULL,
      opening_balance REAL NOT NULL,
      closing_balance REAL NOT NULL,
      total_credits REAL NOT NULL,
      total_debits REAL NOT NULL,
      generated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS external_transfers (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      from_account_id TEXT NOT NULL REFERENCES accounts(id),
      to_iban TEXT NOT NULL,
      to_name TEXT NOT NULL,
      to_bank TEXT,
      amount REAL NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      reference TEXT,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','completed','failed')),
      created_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT
    );
  `);

  console.log('Database initialized successfully');
  return database;
}

export function getOrCreateUser(db, oktaSub, email, name) {
  let user = db.prepare('SELECT * FROM users WHERE okta_sub = ?').get(oktaSub);

  if (!user) {
    const result = db
      .prepare('INSERT INTO users (okta_sub, email, name) VALUES (?, ?, ?)')
      .run(oktaSub, email ?? null, name ?? null);

    // node:sqlite returns lastInsertRowid as BigInt — coerce to Number
    const newId = Number(result.lastInsertRowid);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(newId);
  } else {
    const needsUpdate = (email && email !== user.email) || (name && name !== user.name);
    if (needsUpdate) {
      db.prepare('UPDATE users SET email = ?, name = ? WHERE id = ?')
        .run(email ?? user.email, name ?? user.name, user.id);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    }
  }

  return user;
}
