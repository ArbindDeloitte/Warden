// End-to-end test of what the SecureBank chat does when an A2A approval policy holds a Credit Card Agent call:
// the REAL frontend A2A client (frontend/src/services/a2aClient.js) -> the REAL banking relay -> a REAL Warden
// (throwaway database) -> a fake A2A agent. The chat page itself is React and is not run here; this exercises
// everything it relies on: detecting the hold, polling the ticket, and turning the status into a result/message.
//   node scripts/test-a2a-approval-chat.js

import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import { createRequire } from 'module';
import { fileURLToPath, pathToFileURL } from 'url';
import express from 'express';

const here = path.dirname(fileURLToPath(import.meta.url));
const wardenDir = path.join(here, '..', '..', '..', 'mcp-virtual-server');
const clientUrl = pathToFileURL(path.join(here, '..', '..', 'frontend', 'src', 'services', 'a2aClient.js')).href;

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'chat-a2a-approval-'));
const WARDEN_PORT = 3036, RELAY_PORT = 3037;
Object.assign(process.env, { SQLITE_PATH: path.join(tmp, 'warden.db'), PORT: String(WARDEN_PORT), NODE_ENV: 'development', JWKS_URI: '', REDIS_URL: 'redis://127.0.0.1:1' });
delete process.env.WARDEN_SECRETS_KEY;
process.chdir(tmp);

const W = `http://127.0.0.1:${WARDEN_PORT}`;
const { sendA2AMessage, interpretApprovalStatus, normaliseA2AResult, A2AError, A2AApprovalPendingError } = await import(clientUrl);
const { createWardenGateway, loadWardenConfig } = await import('../src/services/wardenGateway.js');
const { createWardenRouter } = await import('../src/routes/warden.js');

let passed = 0; const failures = [];
function check(name, cond, detail) {
  if (cond) { passed++; console.log(`  ok   ${name}`); }
  else { failures.push(name); console.log(`  FAIL ${name}${detail !== undefined ? '  -> ' + (typeof detail === 'string' ? detail : JSON.stringify(detail)) : ''}`); }
}
const section = (t) => console.log(`\n== ${t}`);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const userJwt = `${b64({ alg: 'none' })}.${b64({ sub: 'user-1' })}.sig`;
async function warden(method, p, body) {
  const res = await fetch(W + p, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text };
}
// what the chat page's pollApprovalStatus does (it cannot be imported here: it pulls in the Okta/Vite env)
const pollStatus = async (ticketId) => (await fetch(`${W}/api/approvals/${ticketId}/status`)).json();

const CARDS = [{ last4: '4242', brand: 'Visa', status: 'ACTIVE' }];
const agentCalls = [];
const agentServer = http.createServer((req, res) => {
  let b = ''; req.on('data', d => { b += d; });
  req.on('end', () => {
    const m = JSON.parse(b || '{}'); agentCalls.push(m.method);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { task: { id: `t-${agentCalls.length}`, status: { state: 'TASK_STATE_COMPLETED' }, artifacts: [{ parts: [{ text: 'Here are your cards' }, { data: { cards: CARDS } }] }] } } }));
  });
});

let relayServer;
async function main() {
  await new Promise(r => agentServer.listen(0, '127.0.0.1', r));
  const agentUrl = `http://127.0.0.1:${agentServer.address().port}/rpc`;
  const { createRequire: cr } = await import('module');
  const require = cr(import.meta.url);
  require(path.join(wardenDir, 'src', 'app.js'));
  for (let i = 0; i < 80; i++) { try { if ((await fetch(W + '/api/health')).ok) break; } catch {} await sleep(100); }
  const wdb = require(path.join(wardenDir, 'src', 'db', 'database.js'));
  const { processExpiredTickets } = require(path.join(wardenDir, 'src', 'routes', 'approvals.js'));

  // ── Warden: the SecureBank A2A agent, the card agent, an A2A virtual server and an approval policy ──
  const bank = await warden('POST', '/api/agents', { name: 'securebank-a2a-agent' });
  const target = (await warden('POST', '/api/a2a-agents', { name: 'credit-card-agent', card_json: { name: 'credit-card-agent', supportedInterfaces: [{ url: agentUrl, protocolBinding: 'JSONRPC', protocolVersion: '1.0' }], skills: [] } })).json.id;
  const vs = (await warden('POST', '/api/virtual-servers', { name: 'securebank-a2a', protocol: 'a2a', features_enabled: [] })).json.id;
  await warden('POST', `/api/virtual-servers/${vs}/a2a-agents`, { a2a_agent_id: target });
  const policy = async (body) => (await warden('POST', '/api/a2a-policies', { virtual_server_id: vs, caller_type: 'agent', caller_value: bank.json.id, target_type: 'any', ...body })).json.id;

  // ── the banking relay, exactly as index.js wires it (fake Okta check only) ──
  const cfg = loadWardenConfig({ WARDEN_URL: W, WARDEN_A2A_VS_ID: vs, WARDEN_A2A_TARGET_ID: target, WARDEN_A2A_AGENT_TOKEN: bank.json.token });
  const app = express(); app.use(express.json());
  app.use('/api/warden', createWardenRouter({ gateway: createWardenGateway({ config: cfg }), authMiddleware: (req, res, next) => (req.headers.authorization === `Bearer ${userJwt}` ? next() : res.status(401).json({ success: false, error: 'Invalid or expired token' })) }));
  relayServer = http.createServer(app); await new Promise(r => relayServer.listen(RELAY_PORT, '127.0.0.1', r));
  const ask = (q, skill) => sendA2AMessage({ relayUrl: `http://127.0.0.1:${RELAY_PORT}/api/warden/a2a`, authToken: userJwt, question: q, skillId: skill, contextId: 'ctx-1' });
  const clearPolicies = () => wdb.exec('DELETE FROM a2a_policies');
  const waitFor = async (fn, ms = 4000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { const v = await fn(); if (v) return v; await sleep(100); } return fn(); };

  // ═══ 1. no approval policy: unchanged ═════════════════════════════════════
  section('1. without an approval policy the chat behaves exactly as before');
  await policy({ name: 'permit', effect: 'permit' });
  const direct = await ask('show my cards', 'card-details');
  check('a normal call returns the parsed answer straight away', direct.text === 'Here are your cards' && direct.data[0].cards[0].last4 === '4242' && direct.state === 'TASK_STATE_COMPLETED', direct);
  clearPolicies();

  // ═══ 2. held, polled, approved ════════════════════════════════════════════
  section('2. held -> chat polls -> admin approves -> the answer appears');
  await policy({ name: 'approve card details', effect: 'approval', approval_ttl_minutes: 7, approval_timeout_action: 'deny' });
  const callsBefore = agentCalls.length;
  let pending;
  try { await ask('show my cards', 'card-details'); } catch (e) { pending = e; }
  check('the client raises A2AApprovalPendingError (an A2AError subclass) instead of a generic failure', pending instanceof A2AApprovalPendingError && pending instanceof A2AError, String(pending));
  check('it carries what the chat shows: ticket, expiry, timeout action, reason', !!pending.ticketId && !!pending.expiresAt && pending.timeoutAction === 'deny' && /Approval required/.test(pending.reason) && pending.status === 202 && pending.code === -32011, pending);
  const minutes = Math.round((new Date(pending.expiresAt).getTime() - Date.now()) / 60000);
  check('the expiry parses to the policy window (the "~N min" in the bubble)', minutes >= 6 && minutes <= 7, minutes);
  check('the Credit Card Agent has not been called yet', agentCalls.length === callsBefore);
  const s0 = interpretApprovalStatus(await pollStatus(pending.ticketId));
  check('polling while pending keeps polling', s0.state === 'pending', s0);
  await warden('POST', `/api/approvals/${pending.ticketId}/decide`, { action: 'approve', decided_by: 'admin-1' });
  const doneOutcome = await waitFor(async () => { const o = interpretApprovalStatus(await pollStatus(pending.ticketId)); return o.state === 'done' ? o : null; });
  check('after approval the poll yields the parsed answer in the same shape as a direct reply', doneOutcome?.state === 'done' && doneOutcome.result.text === 'Here are your cards' && doneOutcome.result.data[0].cards[0].last4 === '4242' && doneOutcome.result.state === 'TASK_STATE_COMPLETED', doneOutcome);
  check('the card data is exactly what the chat renders as cards (data.find(d => d.cards).cards)', doneOutcome.result.data.find(d => d?.cards)?.cards[0].brand === 'Visa');
  check('the agent was called exactly once, after approval', agentCalls.length === callsBefore + 1);
  const mid = interpretApprovalStatus({ ticket_id: 'x', status: 'approved', message: 'Approved — forwarding to the A2A agent, check back shortly' });
  check('an approved ticket that is still being forwarded keeps polling', mid.state === 'pending');

  // ═══ 3. denied, timed out, failed ═════════════════════════════════════════
  section('3. denied, timed out, and approved-but-failed');
  let p2; try { await ask('show my cards', 'card-details'); } catch (e) { p2 = e; }
  await warden('POST', `/api/approvals/${p2.ticketId}/decide`, { action: 'deny', decided_by: 'admin-2' });
  const den = interpretApprovalStatus(await pollStatus(p2.ticketId));
  check('a denied ticket tells the chat it was denied', den.state === 'denied' && /denied by admin-2/.test(den.message), den);

  let p3; try { await ask('show my cards', 'card-details'); } catch (e) { p3 = e; }
  wdb.prepare("UPDATE approval_tickets SET expires_at = ?, timeout_action = 'deny' WHERE id = ?").run(new Date(Date.now() - 1000).toISOString(), p3.ticketId);
  processExpiredTickets();
  const exp = interpretApprovalStatus(await pollStatus(p3.ticketId));
  check('an unattended ticket tells the chat it timed out and was auto-denied', exp.state === 'expired' && exp.autoAction === 'denied', exp);

  let p4; try { await ask('show my cards', 'card-details'); } catch (e) { p4 = e; }
  const forbid = await policy({ name: 'forbid now', effect: 'forbid', priority: 99 });
  await warden('POST', `/api/approvals/${p4.ticketId}/decide`, { action: 'approve' });
  const failed = await waitFor(async () => { const o = interpretApprovalStatus(await pollStatus(p4.ticketId)); return o.state === 'failed' ? o : null; });
  check('approved but no longer permitted: the chat is told it failed and why (instead of polling forever)', failed?.state === 'failed' && /No longer permitted/.test(failed.message), failed);
  await warden('DELETE', `/api/a2a-policies/${forbid}`);
  check('a result the remote agent marked failed is reported as a failure, not as an answer', interpretApprovalStatus({ status: 'executed', result: { task: { id: 't', status: { state: 'TASK_STATE_FAILED', message: { parts: [{ text: 'card service down' }] } } } } }).message === 'card service down');

  // ═══ 4. parsing edge cases ════════════════════════════════════════════════
  section('4. parsing');
  check('nothing / junk payloads keep polling instead of crashing', interpretApprovalStatus(null).state === 'pending' && interpretApprovalStatus('x').state === 'pending' && interpretApprovalStatus({}).state === 'pending');
  const r03 = normaliseA2AResult({ kind: 'task', id: 'b', status: { state: 'completed' }, artifacts: [{ parts: [{ kind: 'text', text: 'bare 0.3 task' }, { kind: 'data', data: { cards: [] } }] }] });
  check('a bare A2A 0.3 task (no wrapper) parses too', r03.text === 'bare 0.3 task' && r03.state === 'completed' && r03.taskId === 'b');
  const msgOnly = normaliseA2AResult({ message: { parts: [{ text: 'direct message reply' }] } });
  check('a plain Message reply parses', msgOnly.text === 'direct message reply');
  let hostile = null; try { hostile = normaliseA2AResult({ task: { status: { state: 'failed' } } }); } catch (e) { hostile = e; }
  check('a failed 0.3 state raises A2AError', hostile instanceof A2AError);
  // other relay errors are still ordinary errors
  const noTok = await sendA2AMessage({ relayUrl: `http://127.0.0.1:${RELAY_PORT}/api/warden/a2a`, authToken: 'bad', question: 'x' }).catch(e => e);
  check('an auth failure from the relay is still a plain A2AError, not an approval', noTok instanceof A2AError && !(noTok instanceof A2AApprovalPendingError) && noTok.status === 401);
  clearPolicies();
  const denyAll = await ask('x', 'card-details').catch(e => e);
  check('a policy denial is still a plain A2AError with the reason', denyAll instanceof A2AError && !(denyAll instanceof A2AApprovalPendingError) && denyAll.status === 403, String(denyAll));

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length) console.log('Failed:\n - ' + failures.join('\n - '));
  return failures.length;
}

function finish(code) {
  try { relayServer?.close(); agentServer.close(); } catch {}
  setTimeout(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} process.exit(code ? 1 : 0); }, 400);
}
main().then(n => finish(n), e => { console.error('\nTEST HARNESS ERROR:', e); finish(1); });
