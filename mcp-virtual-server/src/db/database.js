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

// ── Agent Identity Hub ────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS agents (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    description  TEXT,
    token_hash   TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    metadata     TEXT DEFAULT '{}',
    is_active    INTEGER DEFAULT 1,
    created_at   TEXT DEFAULT (datetime('now')),
    last_seen_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_agents_hash   ON agents(token_hash);
  CREATE INDEX IF NOT EXISTS idx_agents_active ON agents(is_active);
`);

// Phase 2: VS-level agent enforcement
try { db.exec(`ALTER TABLE virtual_servers ADD COLUMN require_agent_token INTEGER DEFAULT 0`); } catch {}

// Phase 2: Per-VS agent allowlist (junction table)
db.exec(`
  CREATE TABLE IF NOT EXISTS virtual_server_agents (
    id         TEXT PRIMARY KEY,
    vs_id      TEXT NOT NULL,
    agent_id   TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(vs_id, agent_id)
  );
  CREATE INDEX IF NOT EXISTS idx_vsa_vs    ON virtual_server_agents(vs_id);
  CREATE INDEX IF NOT EXISTS idx_vsa_agent ON virtual_server_agents(agent_id);
`);

// Enrich audit_log with agent identity columns
try { db.exec(`ALTER TABLE audit_log ADD COLUMN agent_id TEXT`);   } catch {}
try { db.exec(`ALTER TABLE audit_log ADD COLUMN agent_name TEXT`); } catch {}

// ── Unified Event Log ─────────────────────────────────────────────────────────
// Single table for all log types. log_type discriminates the schema of `data`.
// log_type values: 'proxy_call' | 'interceptor' | (future: 'system', 'auth', ...)
// level values: 'info' | 'warn' | 'block' | 'error'
db.exec(`
  CREATE TABLE IF NOT EXISTS event_log (
    id         TEXT PRIMARY KEY,
    created_at TEXT DEFAULT (datetime('now')),
    vs_id      TEXT,
    log_type   TEXT NOT NULL,
    level      TEXT DEFAULT 'info',
    summary    TEXT,
    data       TEXT DEFAULT '{}'
  );
  CREATE INDEX IF NOT EXISTS idx_elog_created ON event_log(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_elog_vs      ON event_log(vs_id);
  CREATE INDEX IF NOT EXISTS idx_elog_type    ON event_log(log_type);
  CREATE INDEX IF NOT EXISTS idx_elog_level   ON event_log(level);
`);

// ── Scoring configuration ─────────────────────────────────────────────────────
// entity_type: 'vs' | 'agent'   mode: 'default' | 'custom'
db.exec(`
  CREATE TABLE IF NOT EXISTS scoring_configs (
    id           TEXT PRIMARY KEY,
    entity_type  TEXT NOT NULL CHECK(entity_type IN ('vs','agent')),
    entity_id    TEXT NOT NULL,
    mode         TEXT NOT NULL DEFAULT 'default' CHECK(mode IN ('default','custom')),
    config_json  TEXT DEFAULT '{}',
    updated_at   TEXT DEFAULT (datetime('now')),
    UNIQUE(entity_type, entity_id)
  );
  CREATE INDEX IF NOT EXISTS idx_scoring_entity ON scoring_configs(entity_type, entity_id);
`);

// ── IDP Connect — trusted issuers per VS ──────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS vs_idp_configs (
    id                TEXT PRIMARY KEY,
    virtual_server_id TEXT NOT NULL,
    name              TEXT NOT NULL,
    provider          TEXT NOT NULL DEFAULT 'okta',
    issuer            TEXT NOT NULL,
    audience          TEXT,
    jwks_uri          TEXT,
    full_verification INTEGER DEFAULT 0,
    is_active         INTEGER DEFAULT 1,
    created_at        TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (virtual_server_id) REFERENCES virtual_servers(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_idp_vs ON vs_idp_configs(virtual_server_id);
`);

// ── Warden Functions ──────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS warden_functions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    code        TEXT NOT NULL DEFAULT '',
    is_active   INTEGER DEFAULT 1,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS warden_function_secrets (
    id          TEXT PRIMARY KEY,
    function_id TEXT NOT NULL,
    key         TEXT NOT NULL,
    value_b64   TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (function_id) REFERENCES warden_functions(id) ON DELETE CASCADE,
    UNIQUE(function_id, key)
  );

  CREATE TABLE IF NOT EXISTS warden_function_triggers (
    id           TEXT PRIMARY KEY,
    function_id  TEXT NOT NULL,
    vs_id        TEXT,
    trigger_type TEXT NOT NULL DEFAULT 'user_score_below',
    threshold    INTEGER NOT NULL DEFAULT 200,
    is_active    INTEGER DEFAULT 1,
    created_at   TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (function_id) REFERENCES warden_functions(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS warden_function_state (
    id                TEXT PRIMARY KEY,
    trigger_id        TEXT NOT NULL,
    user_sub          TEXT NOT NULL,
    armed             INTEGER DEFAULT 0,
    score_at_trigger  INTEGER,
    last_triggered_at TEXT,
    UNIQUE(trigger_id, user_sub),
    FOREIGN KEY (trigger_id) REFERENCES warden_function_triggers(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS warden_function_logs (
    id            TEXT PRIMARY KEY,
    function_id   TEXT NOT NULL,
    trigger_id    TEXT,
    user_sub      TEXT,
    user_email    TEXT,
    score         INTEGER,
    vs_id         TEXT,
    vs_name       TEXT,
    status        TEXT NOT NULL,
    output        TEXT,
    console_logs  TEXT,
    error_message TEXT,
    duration_ms   INTEGER,
    created_at    TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (function_id) REFERENCES warden_functions(id) ON DELETE CASCADE
  );
`);

// function_type: 'user_risk' | 'vs_risk' | 'scheduled' | (future)
try { db.exec(`ALTER TABLE warden_functions ADD COLUMN function_type TEXT NOT NULL DEFAULT 'user_risk'`); } catch {}
// interval_minutes for scheduled triggers
try { db.exec(`ALTER TABLE warden_function_triggers ADD COLUMN interval_minutes INTEGER`); } catch {}
// trigger_scope: 'agent' | 'group' — for agent_risk functions
try { db.exec(`ALTER TABLE warden_function_triggers ADD COLUMN trigger_scope TEXT DEFAULT 'agent'`); } catch {}
try { db.exec(`ALTER TABLE warden_function_triggers ADD COLUMN group_id TEXT`); } catch {}

// ── Agent Groups ──────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS agent_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    owner       TEXT DEFAULT '',
    color_tag   TEXT DEFAULT '#6366f1',
    is_active   INTEGER DEFAULT 1,
    created_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS agent_group_members (
    id        TEXT PRIMARY KEY,
    group_id  TEXT NOT NULL,
    agent_id  TEXT NOT NULL,
    joined_at TEXT DEFAULT (datetime('now')),
    UNIQUE(group_id, agent_id),
    FOREIGN KEY (group_id) REFERENCES agent_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES agents(id)       ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_agm_group ON agent_group_members(group_id);
  CREATE INDEX IF NOT EXISTS idx_agm_agent ON agent_group_members(agent_id);

  CREATE TABLE IF NOT EXISTS agent_group_rules (
    id         TEXT PRIMARY KEY,
    group_id   TEXT NOT NULL,
    name       TEXT DEFAULT '',
    match_mode TEXT DEFAULT 'all',
    conditions TEXT DEFAULT '[]',
    is_active  INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (group_id) REFERENCES agent_groups(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_agr_group ON agent_group_rules(group_id);
`);

// source: 'manual' | 'rule' — tracks how the agent was added to the group
try { db.exec(`ALTER TABLE agent_group_members ADD COLUMN source TEXT DEFAULT 'manual'`); } catch {}
try { db.exec(`ALTER TABLE agent_group_members ADD COLUMN rule_id TEXT`);                 } catch {}

// ── A2A (Agent2Agent) gateway ────────────────────────────────────────────────
// protocol: 'mcp' | 'a2a' | 'both'
try { db.exec(`ALTER TABLE virtual_servers ADD COLUMN protocol TEXT DEFAULT 'mcp'`); } catch {}

// Outbound credential Warden presents to a remote agent: none | bearer | header | basic
// (secret is AES-GCM encrypted by services/secrets.js; header name is only used for type 'header')
function _addCol(sql) { try { db.exec(sql); } catch {} }

db.exec(`
  -- Remote A2A agents that Warden proxies TO (gateway-only: Warden never hosts agents)
  CREATE TABLE IF NOT EXISTS a2a_agents (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT DEFAULT '',
    card_url        TEXT,
    card_json       TEXT NOT NULL,
    endpoint_url    TEXT NOT NULL,
    card_fetched_at TEXT,
    card_error      TEXT,
    is_active       INTEGER DEFAULT 1,
    created_at      TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS virtual_server_a2a_agents (
    id           TEXT PRIMARY KEY,
    vs_id        TEXT NOT NULL,
    a2a_agent_id TEXT NOT NULL,
    created_at   TEXT DEFAULT (datetime('now')),
    UNIQUE(vs_id, a2a_agent_id),
    FOREIGN KEY (vs_id)        REFERENCES virtual_servers(id) ON DELETE CASCADE,
    FOREIGN KEY (a2a_agent_id) REFERENCES a2a_agents(id)      ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_vsa2a_vs ON virtual_server_a2a_agents(vs_id);

  -- Tasks are bound to the calling Warden agent so other callers cannot read/cancel them
  CREATE TABLE IF NOT EXISTS a2a_tasks (
    id               TEXT PRIMARY KEY,
    context_id       TEXT,
    vs_id            TEXT NOT NULL,
    caller_agent_id  TEXT NOT NULL,
    target_agent_id  TEXT NOT NULL,
    remote_task_id   TEXT,
    state            TEXT NOT NULL DEFAULT 'TASK_STATE_SUBMITTED',
    task_json        TEXT,
    created_at       TEXT DEFAULT (datetime('now')),
    updated_at       TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_a2at_caller ON a2a_tasks(caller_agent_id);
  CREATE INDEX IF NOT EXISTS idx_a2at_vs     ON a2a_tasks(vs_id);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_a2at_remote ON a2a_tasks(target_agent_id, remote_task_id);

  -- A2A access rules (deny-by-default). Subjects/targets are agent or group; '*' = any.
  CREATE TABLE IF NOT EXISTS a2a_policies (
    id                TEXT PRIMARY KEY,
    virtual_server_id TEXT NOT NULL,
    name              TEXT NOT NULL,
    effect            TEXT NOT NULL DEFAULT 'permit',
    priority          INTEGER DEFAULT 0,
    caller_type       TEXT DEFAULT 'any',
    caller_value      TEXT DEFAULT '*',
    target_type       TEXT DEFAULT 'any',
    target_value      TEXT DEFAULT '*',
    skills            TEXT DEFAULT '["*"]',
    require_user      INTEGER DEFAULT 0,
    user_fail_mode    TEXT DEFAULT 'closed',
    is_active         INTEGER DEFAULT 1,
    created_at        TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (virtual_server_id) REFERENCES virtual_servers(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_a2ap_vs ON a2a_policies(virtual_server_id);
`);
_addCol(`ALTER TABLE a2a_agents ADD COLUMN outbound_auth_type TEXT DEFAULT 'none'`);
_addCol(`ALTER TABLE a2a_agents ADD COLUMN outbound_auth_header TEXT`);
_addCol(`ALTER TABLE a2a_agents ADD COLUMN outbound_secret_enc TEXT`);

module.exports = db;
