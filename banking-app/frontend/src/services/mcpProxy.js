import { getToken } from './api.js';

const VIRTUAL_SERVER_URL = import.meta.env.VITE_VIRTUAL_SERVER_URL
  || 'http://localhost:3003/api/proxy/da2223c8-2b2a-429c-9220-d9e75b36f330';

const MCP_SERVER_ID = import.meta.env.VITE_MCP_SERVER_ID
  || 'b49d5d6e-f465-4d3d-8963-c74dd1bb1101';

const WARDEN_API_KEY = import.meta.env.VITE_WARDEN_API_KEY || '';

// Warden interceptor for chat messages — uses the banking-chatbot virtual server
const WARDEN_BASE = import.meta.env.VITE_WARDEN_URL || 'http://localhost:3003';
const CHAT_VS_ID  = import.meta.env.VITE_WARDEN_CHAT_VS_ID || '35250de9-689d-4284-a197-0aca282c2c4d';

/**
 * Scan a chat message through Warden's interceptor pipeline.
 * Returns { action: 'allow'|'mask'|'block'|'warn', text, reason }.
 * Fails open (allow) if Warden is unreachable.
 */
export async function scanMessage(text, direction = 'inbound') {
  try {
    const res = await fetch(`${WARDEN_BASE}/api/interceptors/${CHAT_VS_ID}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, direction }),
    });
    if (!res.ok) return { action: 'allow', text };
    return res.json();
  } catch {
    // Warden unavailable — fail open so the chatbot still works
    return { action: 'allow', text };
  }
}

/**
 * Call a banking MCP tool through the virtual server proxy.
 * The user's Okta access token is forwarded — the virtual server
 * verifies it, evaluates Cedar policies, performs OBO exchange with
 * Okta, then forwards the call to the MCP server with the OBO token.
 *
 * @param {string} toolName  - MCP tool name (e.g. 'get_accounts')
 * @param {object} args      - Tool arguments
 * @returns {*}              - Parsed tool result (JSON parsed from MCP content)
 */
export async function callTool(toolName, args = {}) {
  const token = await getToken();

  const response = await fetch(VIRTUAL_SERVER_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(WARDEN_API_KEY ? { 'X-API-Key': WARDEN_API_KEY } : {}),
    },
    body: JSON.stringify({
      mcp_server_id: MCP_SERVER_ID,
      tool_name: toolName,
      arguments: args,
    }),
  });

  const data = await response.json();

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
