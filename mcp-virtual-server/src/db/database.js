const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const dbPath = process.env.SQLITE_PATH
  ? path.resolve(process.env.SQLITE_PATH)
  : path.join(__dirname, '../../data/virtual-server.db');

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new DatabaseSync(dbPath);

db.exec(`PRAGMA journal_mode = WAL`);
db.exec(`PRAGMA foreign_keys = ON`);

db.exec(`
  CREATE TABLE IF NOT EXISTS mcp_servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    description TEXT,
    auth_type TEXT DEFAULT 'none',
    auth_config TEXT DEFAULT '{}',
    is_active INTEGER DEFAULT 1,
    last_synced TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS mcp_tools (
    id TEXT PRIMARY KEY,
    mcp_server_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    input_schema TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE,
    UNIQUE(mcp_server_id, name)
  );

  CREATE TABLE IF NOT EXISTS virtual_servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    okta_issuer TEXT,
    okta_client_id TEXT,
    okta_client_secret TEXT,
    okta_audience TEXT,
    jwks_uri TEXT,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS virtual_server_tools (
    id TEXT PRIMARY KEY,
    virtual_server_id TEXT NOT NULL,
    mcp_server_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (virtual_server_id) REFERENCES virtual_servers(id) ON DELETE CASCADE,
    FOREIGN KEY (mcp_server_id) REFERENCES mcp_servers(id) ON DELETE CASCADE,
    UNIQUE(virtual_server_id, mcp_server_id, tool_name)
  );

  CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    virtual_server_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    effect TEXT NOT NULL CHECK(effect IN ('permit', 'forbid')),
    priority INTEGER DEFAULT 0,
    policy_json TEXT NOT NULL DEFAULT '{}',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (virtual_server_id) REFERENCES virtual_servers(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    virtual_server_id TEXT,
    mcp_server_id TEXT,
    tool_name TEXT,
    user_sub TEXT,
    user_token_jti TEXT,
    user_scopes TEXT DEFAULT '[]',
    user_groups TEXT DEFAULT '[]',
    decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny')),
    matched_policy_id TEXT,
    reason TEXT,
    request_payload TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_audit_user_sub ON audit_log(user_sub);
  CREATE INDEX IF NOT EXISTS idx_audit_vs ON audit_log(virtual_server_id);
  CREATE INDEX IF NOT EXISTS idx_tools_server ON mcp_tools(mcp_server_id);
  CREATE INDEX IF NOT EXISTS idx_vst_vs ON virtual_server_tools(virtual_server_id);
  CREATE INDEX IF NOT EXISTS idx_policies_vs ON policies(virtual_server_id);

  CREATE TABLE IF NOT EXISTS interceptor_scanners (
    id                TEXT PRIMARY KEY,
    virtual_server_id TEXT NOT NULL,
    scanner_name      TEXT NOT NULL,
    direction         TEXT NOT NULL DEFAULT 'both',
    enabled           INTEGER DEFAULT 1,
    config_json       TEXT DEFAULT '{}',
    created_at        TEXT DEFAULT (datetime('now')),
    UNIQUE(virtual_server_id, scanner_name)
  );

  CREATE TABLE IF NOT EXISTS interceptor_rules (
    id                TEXT PRIMARY KEY,
    virtual_server_id TEXT NOT NULL,
    name              TEXT,
    scanner           TEXT DEFAULT '*',
    category          TEXT DEFAULT '*',
    score_min         REAL DEFAULT 0.7,
    action            TEXT NOT NULL,
    priority          INTEGER DEFAULT 0,
    is_active         INTEGER DEFAULT 1,
    created_at        TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS interceptor_log (
    id                TEXT PRIMARY KEY,
    virtual_server_id TEXT,
    direction         TEXT,
    scanner           TEXT,
    flagged           INTEGER DEFAULT 0,
    action_taken      TEXT,
    categories        TEXT DEFAULT '[]',
    pii_types         TEXT DEFAULT '[]',
    score             REAL DEFAULT 0,
    degraded          INTEGER DEFAULT 0,
    created_at        TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS injection_embeddings (
    id          TEXT PRIMARY KEY,
    label       TEXT,
    embedding   BLOB,
    source      TEXT DEFAULT 'seed',
    created_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_ilog_created ON interceptor_log(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_ilog_vs ON interceptor_log(virtual_server_id);
  CREATE INDEX IF NOT EXISTS idx_irules_vs ON interceptor_rules(virtual_server_id);
  CREATE INDEX IF NOT EXISTS idx_iscanners_vs ON interceptor_scanners(virtual_server_id);
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS api_keys (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    key_hash            TEXT NOT NULL UNIQUE,
    key_prefix          TEXT NOT NULL,
    key_suffix          TEXT NOT NULL,
    virtual_server_ids  TEXT NOT NULL DEFAULT '[]',
    expires_at          TEXT,
    is_active           INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT DEFAULT (datetime('now')),
    last_used_at        TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_apikeys_hash ON api_keys(key_hash);
  CREATE INDEX IF NOT EXISTS idx_apikeys_active ON api_keys(is_active);
`);

// Migrations — safe to run on existing DBs
try { db.exec(`ALTER TABLE virtual_servers ADD COLUMN require_obo INTEGER DEFAULT 1`); } catch {}
// features_enabled: JSON array of active pipeline steps. Default = all on (backward-compatible).
try { db.exec(`ALTER TABLE virtual_servers ADD COLUMN features_enabled TEXT DEFAULT '["interceptors","policy"]'`); } catch {}

// Approval tickets table
db.exec(`
  CREATE TABLE IF NOT EXISTS approval_tickets (
    id                TEXT PRIMARY KEY,
    virtual_server_id TEXT NOT NULL,
    mcp_server_id     TEXT NOT NULL,
    tool_name         TEXT NOT NULL,
    tool_arguments    TEXT DEFAULT '{}',
    user_sub          TEXT,
    user_jti          TEXT,
    user_groups       TEXT DEFAULT '[]',
    user_token        TEXT,
    status            TEXT DEFAULT 'pending',
    matched_policy_id TEXT,
    ttl_minutes       INTEGER DEFAULT 30,
    timeout_action    TEXT DEFAULT 'deny',
    result            TEXT,
    exec_error        TEXT,
    decided_by        TEXT,
    decided_at        TEXT,
    executed_at       TEXT,
    expires_at        TEXT NOT NULL,
    created_at        TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_atickets_status  ON approval_tickets(status);
  CREATE INDEX IF NOT EXISTS idx_atickets_expires ON approval_tickets(expires_at);
  CREATE INDEX IF NOT EXISTS idx_atickets_vs      ON approval_tickets(virtual_server_id);
  CREATE INDEX IF NOT EXISTS idx_atickets_created ON approval_tickets(created_at DESC);
`);

// Migrate policies table to allow 'approval' effect.
// SQLite can't ALTER CHECK constraints, so we recreate the table when needed.
try {
  db.exec(`INSERT INTO policies (id, name, virtual_server_id, effect, policy_json)
           VALUES ('__probe__', '__probe__', '__probe__', 'approval', '{}')`);
  db.exec(`DELETE FROM policies WHERE id = '__probe__'`);
} catch {
  // Constraint rejects 'approval' — recreate table with updated constraint
  db.exec(`
    CREATE TABLE IF NOT EXISTS policies_v2 (
      id TEXT PRIMARY KEY,
      virtual_server_id TEXT NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      effect TEXT NOT NULL CHECK(effect IN ('permit', 'forbid', 'approval')),
      priority INTEGER DEFAULT 0,
      policy_json TEXT NOT NULL DEFAULT '{}',
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (virtual_server_id) REFERENCES virtual_servers(id) ON DELETE CASCADE
    );
    INSERT INTO policies_v2 SELECT * FROM policies;
    DROP TABLE policies;
    ALTER TABLE policies_v2 RENAME TO policies;
    CREATE INDEX IF NOT EXISTS idx_policies_vs ON policies(virtual_server_id);
  `);
}

// Migrate audit_log to allow 'approval' decision
try {
  db.exec(`INSERT INTO audit_log (id, decision) VALUES ('__probe2__', 'approval')`);
  db.exec(`DELETE FROM audit_log WHERE id = '__probe2__'`);
} catch {
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log_v2 (
      id TEXT PRIMARY KEY,
      virtual_server_id TEXT,
      mcp_server_id TEXT,
      tool_name TEXT,
      user_sub TEXT,
      user_token_jti TEXT,
      user_scopes TEXT DEFAULT '[]',
      user_groups TEXT DEFAULT '[]',
      decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny', 'approval')),
      matched_policy_id TEXT,
      reason TEXT,
      request_payload TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    INSERT INTO audit_log_v2 SELECT * FROM audit_log;
    DROP TABLE audit_log;
    ALTER TABLE audit_log_v2 RENAME TO audit_log;
    CREATE INDEX IF NOT EXISTS idx_audit_created  ON audit_log(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_user_sub ON audit_log(user_sub);
    CREATE INDEX IF NOT EXISTS idx_audit_vs       ON audit_log(virtual_server_id);
  `);
}

module.exports = db;
