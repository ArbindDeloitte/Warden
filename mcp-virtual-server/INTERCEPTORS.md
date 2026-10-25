# Interceptors — Design Specification

Bidirectional message filtering between User and Agent. All scanning and block/mask/allow decisions happen inside Warden — no external or paid services.
### My top pick: Interceptors "Ingress Interceptor" → filters User → Agent messages "Egress Interceptor" → filters Agent → User messages

## Why Self-Hosted Only

External APIs (Azure Content Safety, Lakera, Bedrock Guardrails) create a hard dependency: if they go down or rate-limit the app, the entire proxy stops working. All scanners in this design run on your own infrastructure.

---

## How It Fits Into the Proxy Flow

```
POST /api/proxy/:vsId
        │
        ▼
[Inbound scan]    ← runs BEFORE forwarding to MCP server
        │ block → 403 | mask → sanitized text | allow → original
        ▼
  OBO token exchange (existing)
        │
        ▼
  MCP server call (existing)
        │
        ▼
[Outbound scan]   ← runs BEFORE returning response to caller
        │ block → 403 | mask → sanitized text | allow → original
        ▼
  Response to caller
```

---

## Scanner Stack

| Layer | Scanner | Runtime | Latency | Sync? |
|---|---|---|---|---|
| 1 | Regex + Keyword | In-process Node.js | <1ms | Yes |
| 2 | Embedding similarity | In-process WASM | ~30ms | Yes |
| 3 | Presidio | Docker loopback :5001/:5002 | ~50ms | Yes |
| 4 | Action Engine | In-process Node.js | <1ms | Yes |
| 5 | Llama Guard 3 | Ollama loopback :11434 | ~300ms | **No — async only** |

Layers 1–4 are synchronous and blocking. Layer 5 (Llama Guard) is fire-and-forget — it never delays a response, only enriches the audit log.

---

## File Structure

```
src/interceptors/
  BaseScanner.js              ← interface all scanners must implement
  ScannerRegistry.js          ← Map<name, scanner>, populated at startup
  InterceptorPipeline.js      ← runs tiers in order, calls Action Engine
  ActionEngine.js             ← reads DB rules → block / mask / allow
  scanners/
    RegexScanner.js           ← PII regex + injection heuristics
    KeywordScanner.js         ← blocklist (Trie-based)
    EmbeddingScanner.js       ← @xenova/transformers, cosine similarity
    PresidioScanner.js        ← HTTP to localhost:5001 + 5002
    LlamaGuardScanner.js      ← HTTP to localhost:11434, async only
```

---

## BaseScanner Interface

```javascript
class BaseScanner {
  get name()  { throw new Error('Must implement'); }
  get tier()  { return 'sync'; } // 'sync' | 'api' | 'async'

  async init() {}

  async scan(text, context) {
    return {
      scanner:    this.name,
      flagged:    false,
      score:      0,          // 0.0–1.0
      categories: [],         // ['pii', 'prompt_injection', 'toxicity', ...]
      matches:    [],         // [{ type, value, start, end }] — for masking
      metadata:   {},
      degraded:   false,      // true if scanner failed gracefully
    };
  }
}
```

---

## Action Engine

Reads `interceptor_rules` from SQLite (priority DESC). For each rule:

- `scanner` — which scanner must have flagged (`'*'` = any)
- `category` — which category (`'*'` = any)
- `score_min` — trigger if `score >= this`
- `action` — `'block'` | `'mask'` | `'warn'` | `'log'`

**Masking** uses `matches[].{start, end}` — replaces character ranges with `[REDACTED: <type>]`. Process matches in reverse index order to preserve offsets.

**Block** → proxy returns HTTP 403 `{ error: 'intercepted', reason, category }`.

**Degraded rule:** if `result.degraded === true`, skip that result entirely and log a warning. Never block because a scanner was unavailable.

---

## Database Schema

```sql
CREATE TABLE interceptor_scanners (
  id                TEXT PRIMARY KEY,
  virtual_server_id TEXT NOT NULL,
  scanner_name      TEXT NOT NULL,   -- 'regex' | 'keyword' | 'embedding' | 'presidio' | 'llama-guard'
  direction         TEXT NOT NULL,   -- 'inbound' | 'outbound' | 'both'
  enabled           INTEGER DEFAULT 1,
  config_json       TEXT DEFAULT '{}',
  created_at        TEXT DEFAULT (datetime('now'))
);

CREATE TABLE interceptor_rules (
  id                TEXT PRIMARY KEY,
  virtual_server_id TEXT NOT NULL,
  scanner           TEXT DEFAULT '*',
  category          TEXT DEFAULT '*',
  score_min         REAL DEFAULT 0.7,
  action            TEXT NOT NULL,   -- 'block' | 'mask' | 'warn' | 'log'
  priority          INTEGER DEFAULT 0,
  is_active         INTEGER DEFAULT 1,
  created_at        TEXT DEFAULT (datetime('now'))
);

CREATE TABLE interceptor_log (
  id                TEXT PRIMARY KEY,
  virtual_server_id TEXT,
  direction         TEXT,
  scanner           TEXT,
  flagged           INTEGER,
  action_taken      TEXT,
  categories        TEXT,            -- JSON array of strings
  pii_types         TEXT,            -- JSON array — types ONLY, never values
  score             REAL,
  degraded          INTEGER DEFAULT 0,
  created_at        TEXT DEFAULT (datetime('now'))
);

CREATE TABLE injection_embeddings (
  id          TEXT PRIMARY KEY,
  label       TEXT,
  embedding   BLOB,                  -- Float32Array as binary
  source      TEXT,                  -- 'seed' | 'audit'
  created_at  TEXT DEFAULT (datetime('now'))
);
```

---

## PII Regex Patterns (RegexScanner seed)

```javascript
const PII_PATTERNS = [
  { type: 'SSN',           regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: 'CREDIT_CARD',   regex: /\b(?:\d{4}[- ]?){3}\d{4}\b/g },
  { type: 'EMAIL',         regex: /\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b/gi },
  { type: 'PHONE_US',      regex: /\b(?:\+1\s?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g },
  { type: 'IP_ADDRESS',    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
  { type: 'API_KEY',       regex: /\b(sk-|pk-|Bearer\s)[A-Za-z0-9_-]{20,}\b/g },
  { type: 'ROUTING_NUM',   regex: /\b\d{9}\b/g },
  { type: 'IBAN',          regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}/g },
];

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
  /forget\s+(everything|all|what)\s+(you('ve|\s+have)\s+)?learned/gi,
  /you\s+are\s+now\s+(a|an)\s+/gi,
  /new\s+(role|persona|personality|instructions?)[:.\s]/gi,
  /system\s*prompt\s*[:=]/gi,
  /\[INST\]|\[\/INST\]|<\|system\|>/g,
  /act\s+as\s+(if\s+)?(you\s+are|a|an)\s+/gi,
  /disregard\s+(your\s+)?(previous|prior|all)\s+(instructions?|training)/gi,
];
```

---

## Infrastructure Setup

### Presidio (Docker)
```yaml
# docker-compose.yml
services:
  presidio-analyzer:
    image: mcr.microsoft.com/presidio-analyzer
    ports: ["5001:3000"]
  presidio-anonymizer:
    image: mcr.microsoft.com/presidio-anonymizer
    ports: ["5002:3000"]
```

Call flow:
1. `POST localhost:5001/analyze` → `[{ entity_type, start, end, score }]`
2. `POST localhost:5002/anonymize` → `{ text }` with PII replaced

### Llama Guard 3 (Ollama)
```bash
ollama pull llama-guard3
# HTTP server at localhost:11434
```
`POST localhost:11434/api/generate` → `{ model: 'llama-guard3', prompt, stream: false }`

Response: `"safe"` or `"unsafe\n<S-code>"` (e.g. `"unsafe\nS1"` = violent crimes)

### Embedding Scanner
```bash
npm install @xenova/transformers
```
Model: `Xenova/all-MiniLM-L6-v2` (~80MB, downloads once, runs in-process WASM)

---

## npm Package to Add

```json
"@xenova/transformers": "^2.17.0"
```

No other new packages needed. Presidio and Ollama are external binaries/Docker.

---

## UI Surface

New page in Virtual Dashboard sidebar: **Interceptors** (`#interceptors`)

Sections:
- Scanner configuration (toggle per virtual server, per direction)
- Interceptor rules (same builder pattern as Policies)
- Interceptor audit log (separate from tool-call audit log)

---

## Constraint

**No external or paid APIs.** Do not use Azure Content Safety, Lakera Guard, AWS Bedrock Guardrails, or OpenAI Moderation API — even as optional scanners. These create external dependencies that can take down the gateway.
