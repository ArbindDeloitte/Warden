import { getToken, getIdToken, API_BASE_URL } from './api.js';
import { sendA2AMessage, A2AError, A2AApprovalPendingError, interpretApprovalStatus } from './a2aClient.js';

// Nothing in this file is a credential. MCP tool calls and A2A messages go to the banking backend
// (/api/warden/*), which verifies the user's Okta token and adds the Warden agent token and API key
// server-side, read from the Warden Credential Vault. Do not add VITE_* secrets here: Vite inlines
// them into the public JavaScript bundle.

// The browser never talks to Warden at all (not even for message scanning or approval status): everything goes to
// the banking backend, which checks the Okta token and acts as the right Warden agent.

// ── A2A: ask the Credit Card Agent through Warden ─────────────────────────────
// Agent name used to attribute chat-scan findings while the A2A agent is selected
export const A2A_AGENT_NAME = import.meta.env.VITE_WARDEN_A2A_AGENT_NAME || 'securebank-a2a-agent';
export { A2AError, A2AApprovalPendingError };
// What the chat should do with the status payload of an approval-gated A2A call (pending / done / denied / ...).
export const interpretA2aApproval = interpretApprovalStatus;

// Whether the backend relay has the Credit Card Agent configured (asked once, then cached).
let a2aConfiguredPromise = null;
export function isA2AConfigured() {
  a2aConfiguredPromise ??= (async () => {
    try {
      const token = await getToken();
      const res = await fetch(`${API_BASE_URL}/warden/config`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return !!(await res.json()).a2aConfigured;
    } catch {
      a2aConfiguredPromise = null; // transient failure: ask again next time
      return false;
    }
  })();
  return a2aConfiguredPromise;
}

let a2aContextId = null; // one A2A conversation per chat session

export async function askCreditCardAgent(question, skillId) {
  const authToken = await getToken();
  a2aContextId ??= globalThis.crypto?.randomUUID?.() ?? String(Date.now());
  return sendA2AMessage({
    relayUrl: `${API_BASE_URL}/warden/a2a`, authToken, question, skillId, contextId: a2aContextId,
  });
}

/**
 * Thrown by callTool when the virtual server returns 202 pending_approval.
 * Carry ticket metadata so the caller can show status and start polling.
 */
export class ApprovalPendingError extends Error {
  constructor(data) {
    super('Tool call pending admin approval');
    this.name = 'ApprovalPendingError';
    this.ticketId = data.ticket_id;
    this.pollUrl = data.poll_url;
    this.expiresAt = data.expires_at;
    this.timeoutAction = data.timeout_action;
    this.approvalMessage = data.message;
  }
}

/**
 * Poll the status of an approval ticket, through the banking backend (which asks Warden as the agent that made the
 * call; Warden only shows a ticket to its own agent). `kind` is 'mcp' (banking tools) or 'a2a' (Credit Card Agent).
 * Returns the raw JSON of Warden's GET /api/approvals/:id/status.
 */
export async function pollApprovalStatus(ticketId, kind = 'mcp') {
  const token = await getToken();
  const res = await fetch(`${API_BASE_URL}/warden/approvals/${encodeURIComponent(ticketId)}/status?kind=${kind === 'a2a' ? 'a2a' : 'mcp'}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  return res.json();
}

/**
 * Scan a chat message through Warden's interceptor pipeline.
 * Returns { action: 'allow'|'mask'|'block'|'warn', text, reason }.
 * `agentName` is the agent the findings (and score changes) are attributed to.
 * Fails open (allow) if Warden is unreachable.
 */
export async function scanMessage(text, direction = 'inbound', agentName) {
  try {
    const [token, idToken] = await Promise.all([getToken(), getIdToken()]);
    const res = await fetch(`${API_BASE_URL}/warden/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(idToken ? { 'X-Id-Token': idToken } : {}),
      },
      // The backend scans as the right Warden agent; the browser only says which one is selected.
      body: JSON.stringify({ text, direction, agent: agentName === A2A_AGENT_NAME ? 'a2a' : 'mcp' }),
    });
    if (!res.ok) {
      console.warn(`[chat scan] the backend could not scan this message (HTTP ${res.status}); continuing unscanned`);
      return { action: 'allow', text };
    }
    return res.json();
  } catch {
    // Backend/Warden unavailable — fail open so the chatbot still works
    return { action: 'allow', text };
  }
}

/**
 * Call a banking MCP tool through the Warden virtual server proxy, relayed by the banking backend.
 * The user's Okta access token is the only credential sent from the browser. The backend verifies it
 * and adds the agent token and API key (from the vault); Warden then verifies the user token,
 * evaluates Cedar policies, performs the OBO exchange with Okta, and forwards the call to the MCP
 * server with the OBO token.
 *
 * @param {string} toolName  - MCP tool name (e.g. 'get_accounts')
 * @param {object} args      - Tool arguments
 * @returns {*}              - Parsed tool result (JSON parsed from MCP content)
 */
export async function callTool(toolName, args = {}) {
  const [token, idToken] = await Promise.all([getToken(), getIdToken()]);

  const response = await fetch(`${API_BASE_URL}/warden/tool`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token   ? { Authorization: `Bearer ${token}` } : {}),
      ...(idToken ? { 'X-Id-Token': idToken }            : {}),
    },
    body: JSON.stringify({ tool_name: toolName, arguments: args }),
  });

  const data = await response.json();

  // 202 = tool call queued for admin approval
  if (data?.status === 'pending_approval') {
    throw new ApprovalPendingError(data);
  }

  if (!response.ok) {
    const msg = data.reason || data.error || `Proxy call failed (${response.status})`;
    const detail = data.detail ? `: ${data.detail}` : '';
    throw new Error(msg + detail);
  }

  // MCP response: { jsonrpc, result: { content: [{ type:'text', text:'...' }] } }
  const text = data?.result?.content?.[0]?.text;
  if (text === undefined) {
    throw new Error(`Unexpected response from virtual server: ${JSON.stringify(data)}`);
  }

  const parsed = JSON.parse(text);

  // Surface MCP-level errors (isError: true from the tool handler)
  if (parsed?.error) throw new Error(parsed.error);

  return parsed;
}

/**
 * Drop-in replacement for the `banking` service — routes all calls
 * through the MCP virtual server proxy instead of the REST API.
 */
export const mcpBanking = {
  getAccounts: () =>
    callTool('get_accounts'),

  getAccountBalance: (accountId) =>
    callTool('get_account_balance', { accountId }),

  getTransactions: (accountId, params = {}) =>
    callTool('get_transactions', {
      accountId,
      limit: params.limit || 20,
      ...(params.from ? { from: params.from } : {}),
      ...(params.to   ? { to:   params.to   } : {}),
    }),

  getStatements: (accountId) =>
    callTool('get_statements', { accountId }),

  listPayments: () =>
    callTool('list_payments'),

  initiatePayment: (data) =>
    callTool('initiate_payment', {
      fromAccountId: data.fromAccountId,
      toAccount:     data.toAccount,
      toName:        data.toName,
      amount:        data.amount,
      currency:      data.currency || 'USD',
      reference:     data.reference,
    }),

  approvePayment: (paymentId) =>
    callTool('approve_payment', { paymentId }),

  createStandingOrder: (data) =>
    callTool('create_standing_order', data),

  manageStandingOrder: (action, orderId, updates = {}) =>
    callTool('manage_standing_order', { action, orderId, ...updates }),

  createExternalTransfer: (data) =>
    callTool('create_external_transfer', data),
};
