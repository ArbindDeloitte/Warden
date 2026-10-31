'use strict';

const vm = require('vm');

const TIMEOUT_MS = 30_000;

const TEMPLATE_CODE = `// Warden Function — triggered when a user's risk score crosses below threshold
// ─────────────────────────────────────────────────────────────────────────────
// Available globals:
//   event    — trigger context (see below)
//   secrets  — key-value map you configure in the Secrets tab
//   fetch    — standard Fetch API (Node.js built-in)
//   console  — console.log / .error / .warn (captured in execution log)
//   JSON, Math, Date, URL, btoa, atob, encodeURIComponent
//
// event shape:
// {
//   type:           'user_score_below_threshold',
//   triggered_at:  '2024-01-01T12:00:00.000Z',
//   user:          { sub, email, name },
//   score:         { current, threshold, tier },
//   virtual_server: { id, name },
// }
// ─────────────────────────────────────────────────────────────────────────────

const { user, score, virtual_server } = event;

console.log(\`[Warden] \${user.email} scored \${score.current} on "\${virtual_server.name}" (threshold: \${score.threshold})\`);

// ── Example: Suspend user in Okta ────────────────────────────────────────────
// const res = await fetch(
//   \`\${secrets.OKTA_DOMAIN}/api/v1/users/\${user.sub}/lifecycle/suspend\`,
//   {
//     method: 'POST',
//     headers: {
//       'Authorization': \`SSWS \${secrets.OKTA_API_TOKEN}\`,
//       'Accept': 'application/json',
//     },
//   }
// );
// console.log('Okta suspend status:', res.status);

// ── Example: Create a Jira ticket ────────────────────────────────────────────
// const jira = await fetch(\`\${secrets.JIRA_BASE_URL}/rest/api/3/issue\`, {
//   method: 'POST',
//   headers: {
//     'Authorization': 'Basic ' + btoa(\`\${secrets.JIRA_EMAIL}:\${secrets.JIRA_API_TOKEN}\`),
//     'Content-Type': 'application/json',
//   },
//   body: JSON.stringify({
//     fields: {
//       project:   { key: secrets.JIRA_PROJECT_KEY || 'SEC' },
//       summary:   \`High-risk user detected: \${user.email} (score \${score.current})\`,
//       issuetype: { name: 'Task' },
//       description: {
//         type: 'doc', version: 1,
//         content: [{ type: 'paragraph', content: [{ type: 'text',
//           text: \`User \${user.email} scored \${score.current}/1000 on VS "\${virtual_server.name}". Threshold: \${score.threshold}.\`
//         }] }],
//       },
//     },
//   }),
// });
// console.log('Jira response:', jira.status);

// ── Return value is stored in the execution log ───────────────────────────────
return { status: 'ok', user: user.email, score: score.current };
`;

async function runFunction(code, event, secrets = {}) {
  const consoleLogs = [];
  const capture = {
    log:   (...a) => consoleLogs.push(a.map(x => typeof x === 'object' ? JSON.stringify(x) : String(x)).join(' ')),
    error: (...a) => consoleLogs.push('[error] ' + a.map(x => typeof x === 'object' ? JSON.stringify(x) : String(x)).join(' ')),
    warn:  (...a) => consoleLogs.push('[warn] '  + a.map(x => typeof x === 'object' ? JSON.stringify(x) : String(x)).join(' ')),
    info:  (...a) => consoleLogs.push('[info] '  + a.map(x => typeof x === 'object' ? JSON.stringify(x) : String(x)).join(' ')),
  };

  const sandbox = {
    event,
    secrets,
    fetch:              globalThis.fetch,
    console:            capture,
    JSON, Math, Date, URL,
    btoa:               s => Buffer.from(s).toString('base64'),
    atob:               s => Buffer.from(s, 'base64').toString('utf8'),
    encodeURIComponent, decodeURIComponent,
    parseInt, parseFloat, isNaN, isFinite,
    Promise, Error, TypeError, RangeError,
    setTimeout, clearTimeout,
  };

  const start = Date.now();
  try {
    const wrapped = `(async function __warden__() {\n${code}\n})()`;
    const script  = new vm.Script(wrapped, { filename: 'warden-fn.js' });
    const ctx     = vm.createContext(sandbox);
    const result  = await script.runInContext(ctx, { timeout: TIMEOUT_MS });
    return { success: true, result: result ?? null, consoleLogs, duration: Date.now() - start };
  } catch (err) {
    return { success: false, error: err.message, consoleLogs, duration: Date.now() - start };
  }
}

const VS_TEMPLATE_CODE = `// Warden Function — triggered when a Virtual Server's risk score crosses below threshold
// ─────────────────────────────────────────────────────────────────────────────
// Available globals:
//   event    — trigger context (see below)
//   secrets  — key-value map you configure in the Secrets tab
//   fetch    — standard Fetch API (Node.js built-in)
//   console  — console.log / .error / .warn (captured in execution log)
//   JSON, Math, Date, URL, btoa, atob, encodeURIComponent
//
// event shape:
// {
//   type:           'vs_score_below_threshold',
//   triggered_at:  '2024-01-01T12:00:00.000Z',
//   virtual_server: { id, name },
//   score:          { current, threshold, tier },
// }
// ─────────────────────────────────────────────────────────────────────────────

const { virtual_server, score } = event;

console.log(\`[Warden] VS "\${virtual_server.name}" scored \${score.current} (threshold: \${score.threshold})\`);

// ── Example: Send a Slack alert ───────────────────────────────────────────────
// const slack = await fetch(secrets.SLACK_WEBHOOK_URL, {
//   method: 'POST',
//   headers: { 'Content-Type': 'application/json' },
//   body: JSON.stringify({
//     text: \`⚠️ *Virtual Server at risk*: "\${virtual_server.name}" scored \${score.current}/1000 (below threshold \${score.threshold}).\`,
//   }),
// });
// console.log('Slack status:', slack.status);

// ── Example: Disable the VS via Warden API ────────────────────────────────────
// const res = await fetch(\`\${secrets.WARDEN_API_URL}/api/virtual-servers/\${virtual_server.id}\`, {
//   method: 'PUT',
//   headers: {
//     'Authorization': \`Bearer \${secrets.WARDEN_API_TOKEN}\`,
//     'Content-Type': 'application/json',
//   },
//   body: JSON.stringify({ is_active: false }),
// });
// console.log('VS disable status:', res.status);

// ── Return value is stored in the execution log ───────────────────────────────
return { status: 'ok', virtual_server: virtual_server.name, score: score.current };
`;

const SCHEDULED_TEMPLATE_CODE = `// Warden Function — triggered on a recurring schedule
// ─────────────────────────────────────────────────────────────────────────────
// Available globals:
//   event    — trigger context (see below)
//   secrets  — key-value map you configure in the Secrets tab
//   fetch    — standard Fetch API (Node.js built-in)
//   console  — console.log / .error / .warn (captured in execution log)
//   JSON, Math, Date, URL, btoa, atob, encodeURIComponent
//
// event shape:
// {
//   type:         'scheduled',
//   triggered_at: '2024-01-01T12:00:00.000Z',
//   schedule:     { label, interval_minutes },
// }
// ─────────────────────────────────────────────────────────────────────────────

const { schedule } = event;

console.log(\`[Warden] Scheduled run: \${schedule.label} at \${event.triggered_at}\`);

// ── Example: Fetch and log a daily summary ────────────────────────────────────
// const res = await fetch(\`\${secrets.WARDEN_API_URL}/api/audit-log?limit=50\`, {
//   headers: { 'Authorization': \`Bearer \${secrets.WARDEN_API_TOKEN}\` },
// });
// const data = await res.json();
// console.log('Recent events:', data.total);

// ── Example: Post a daily digest to Slack ────────────────────────────────────
// await fetch(secrets.SLACK_WEBHOOK_URL, {
//   method: 'POST',
//   headers: { 'Content-Type': 'application/json' },
//   body: JSON.stringify({ text: \`🕐 Scheduled Warden run: \${schedule.label}\` }),
// });

// ── Return value is stored in the execution log ───────────────────────────────
return { status: 'ok', schedule: schedule.label, ran_at: event.triggered_at };
`;

const AGENT_TEMPLATE_CODE = `// Warden Function — triggered when an Agent's risk score crosses below threshold
// ─────────────────────────────────────────────────────────────────────────────
// Available globals:
//   event    — trigger context (see below)
//   secrets  — key-value map you configure in the Secrets tab
//   fetch    — standard Fetch API (Node.js built-in)
//   console  — console.log / .error / .warn (captured in execution log)
//   JSON, Math, Date, URL, btoa, atob, encodeURIComponent
//
// event shape:
// {
//   type:           'agent_score_below_threshold',
//   triggered_at:  '2024-01-01T12:00:00.000Z',
//   agent:          { id, name },
//   score:          { current, threshold, tier },
//   virtual_server: { id, name },   // VS the agent was operating on
// }
// ─────────────────────────────────────────────────────────────────────────────

const { agent, score, virtual_server } = event;

console.log(\`[Warden] Agent "\${agent.name}" scored \${score.current} on "\${virtual_server.name}" (threshold: \${score.threshold})\`);

// ── Example: Revoke the agent's API key via Warden API ───────────────────────
// const res = await fetch(\`\${secrets.WARDEN_API_URL}/api/agents/\${agent.id}\`, {
//   method: 'PUT',
//   headers: {
//     'Authorization': \`Bearer \${secrets.WARDEN_API_TOKEN}\`,
//     'Content-Type': 'application/json',
//   },
//   body: JSON.stringify({ is_active: false }),
// });
// console.log('Agent disable status:', res.status);

// ── Example: Send a Slack alert ───────────────────────────────────────────────
// await fetch(secrets.SLACK_WEBHOOK_URL, {
//   method: 'POST',
//   headers: { 'Content-Type': 'application/json' },
//   body: JSON.stringify({
//     text: \`🤖 *Agent at risk*: "\${agent.name}" scored \${score.current}/1000 on VS "\${virtual_server.name}" (threshold \${score.threshold}). Consider revoking its key.\`,
//   }),
// });

// ── Return value is stored in the execution log ───────────────────────────────
return { status: 'ok', agent: agent.name, score: score.current };
`;

const TEMPLATES = {
  user_risk:  TEMPLATE_CODE,
  vs_risk:    VS_TEMPLATE_CODE,
  agent_risk: AGENT_TEMPLATE_CODE,
  scheduled:  SCHEDULED_TEMPLATE_CODE,
};

module.exports = { runFunction, TEMPLATE_CODE, TEMPLATES };
