/**
 * Call the PointGuard MCP gateway.
 * Equivalent to:
 *   curl -X POST "$GW/servers/$VS/mcp" \
 *     -H "Authorization: Bearer $GW_TOKEN" \
 *     -H "Content-Type: application/json" \
 *     -H "Accept: application/json, text/event-stream" \
 *     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
 *
 * Usage:
 *   node call_pg_gateway.js                    # tools/list (default)
 *   node call_pg_gateway.js tools/list
 *   node call_pg_gateway.js initialize
 *   USER_TOKEN=eyJ... node call_pg_gateway.js  # include x-user-token (OBO)
 */

// Load .env from the same directory as this script
import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dir = dirname(fileURLToPath(import.meta.url));
const envPath = resolve(__dir, '.env');
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim();
    if (!(key in process.env)) process.env[key] = val;
  }
}

const GW_URL     = (process.env.PG_GATEWAY_URL    ?? '').replace(/\/$/, '');
const VS_ID      = process.env.PG_VIRTUAL_SERVER_ID ?? '';
const GW_TOKEN   = process.env.PG_ADMIN_TOKEN       ?? '';
const USER_TOKEN = process.env.USER_TOKEN           ?? '';
const AGENT_NAME = process.env.PG_AGENT_NAME        ?? 'banking-agent';

const MCP_URL = `${GW_URL}/servers/${VS_ID}/mcp`;
const method  = process.argv[2] ?? 'tools/list';
console.log('Endpoint:', MCP_URL);
console.log('Method:  ', method);
console.log();

const headers = {
  'Authorization': `Bearer ${GW_TOKEN}`,
  'Content-Type':  'application/json',
  'Accept':        'application/json, text/event-stream',
};

if (USER_TOKEN) {
  headers['x-user-token'] = `Bearer ${USER_TOKEN}`;
  headers['X-Agent-Token'] = AGENT_NAME;
  console.log('x-user-token: present (OBO will be attempted)');
}

const body = {
  jsonrpc: '2.0',
  id: 1,
  method,
  ...(method === 'initialize' ? {
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: AGENT_NAME, version: '1' },
    },
  } : {}),
};

console.log('Sending:', JSON.stringify(body));
console.log();

const res = await fetch(MCP_URL, {
  method: 'POST',
  headers,
  body: JSON.stringify(body),
});

console.log('Status:', res.status, res.statusText);
console.log('Response headers:', Object.fromEntries(res.headers.entries()));

const text = await res.text();
try {
  const json = JSON.parse(text);
  console.log('\nResponse body:');
  console.log(JSON.stringify(json, null, 2));

  if (json.result?.tools) {
    console.log(`\n✓ ${json.result.tools.length} tools returned:`);
    json.result.tools.forEach(t => console.log(`  • ${t.name}`));
  }
} catch {
  console.log('\nResponse body (raw):');
  console.log(text.slice(0, 500));
}
