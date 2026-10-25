#!/usr/bin/env node
/**
 * export-db.js
 *
 * Exports both SQLite databases to portable SQL dump files.
 * Run from the project root:
 *
 *   node scripts/export-db.js
 *
 * Output:
 *   scripts/exports/virtual-server.sql   — MCP Virtual Server config + policies
 *   scripts/exports/banking.sql          — Banking app users / accounts / transactions
 *
 * On the new machine, import with:
 *   node scripts/import-db.js
 */

const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');

const EXPORTS_DIR = path.join(__dirname, 'exports');
fs.mkdirSync(EXPORTS_DIR, { recursive: true });

// ── Database locations ────────────────────────────────────────────────────────

const DATABASES = [
  {
    label: 'MCP Virtual Server',
    dbPath: path.join(__dirname, '../mcp-virtual-server/data/virtual-server.db'),
    outFile: path.join(EXPORTS_DIR, 'virtual-server.sql'),
    // Audit log can be large and isn't needed on a fresh machine — set to true to include it
    skipTables: process.argv.includes('--with-audit') ? [] : ['audit_log'],
  },
  {
    label: 'Banking App',
    dbPath: path.join(__dirname, '../banking-app/backend/banking.db'),
    outFile: path.join(EXPORTS_DIR, 'banking.sql'),
    skipTables: [],
  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function escapeValue(v) {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'bigint') return String(v);
  // Escape single quotes for SQL
  return `'${String(v).replace(/'/g, "''")}'`;
}

function dumpTable(db, table) {
  const rows = db.prepare(`SELECT * FROM "${table}"`).all();
  if (rows.length === 0) return `-- (no rows in ${table})\n`;

  const lines = [];
  for (const row of rows) {
    const cols = Object.keys(row).map(c => `"${c}"`).join(', ');
    const vals = Object.values(row).map(escapeValue).join(', ');
    lines.push(`INSERT OR IGNORE INTO "${table}" (${cols}) VALUES (${vals});`);
  }
  return lines.join('\n') + '\n';
}

function getTableNames(db) {
  return db
    .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
    .all()
    .map(r => r.name);
}

// ── Main ──────────────────────────────────────────────────────────────────────

for (const { label, dbPath, outFile, skipTables } of DATABASES) {
  if (!fs.existsSync(dbPath)) {
    console.warn(`⚠️  Skipping "${label}" — database not found at:\n   ${dbPath}`);
    continue;
  }

  console.log(`\n📦 Exporting: ${label}`);
  console.log(`   From: ${dbPath}`);
  console.log(`   To:   ${outFile}`);

  const db = new DatabaseSync(dbPath, { readOnly: true });
  const tables = getTableNames(db).filter(t => !skipTables.includes(t));

  const header = [
    `-- ${label} — SQL dump`,
    `-- Generated: ${new Date().toISOString()}`,
    `-- Source: ${dbPath}`,
    skipTables.length ? `-- Skipped tables: ${skipTables.join(', ')}` : '',
    '',
    'PRAGMA foreign_keys = OFF;',
    'BEGIN TRANSACTION;',
    '',
  ].filter(l => l !== undefined).join('\n');

  const footer = '\nCOMMIT;\nPRAGMA foreign_keys = ON;\n';

  let body = '';
  for (const table of tables) {
    const count = db.prepare(`SELECT COUNT(*) as n FROM "${table}"`).get().n;
    console.log(`   · ${table.padEnd(30)} ${count} rows`);
    body += `\n-- Table: ${table}\n`;
    body += dumpTable(db, table);
  }

  fs.writeFileSync(outFile, header + body + footer, 'utf8');
  console.log(`   ✅ Written`);
}

console.log(`\n✅ Export complete. Files are in: scripts/exports/`);
console.log(`   To import on the new machine, run:\n   node scripts/import-db.js\n`);
