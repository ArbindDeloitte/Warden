// Server-side relay to the Warden gateway. The browser authenticates with its Okta token only; this
// module adds the Warden credentials so none of them ship in the frontend bundle.
//
// Identities: there are exactly two Warden agents, and each path acts as its own agent
//   - MCP tool calls  -> the banking agent   (WARDEN_AGENT_TOKEN)
//   - A2A messages    -> the A2A agent       (WARDEN_A2A_AGENT_TOKEN)
// An agent's own token is its identity, so it is the one secret kept on the server (in .env.local).
// It also authenticates that agent to the Warden Credential Vault, where the shared Warden API key is
// stored and read at runtime under a vault policy for that agent. Warden policies, allowlists and
// scoring stay keyed to the same two agents as before.

import { randomUUID } from 'crypto';
import { createVaultClient } from './wardenVault.js';

export class GatewayConfigError extends Error {
  constructor(message) { super(message); this.name = 'GatewayConfigError'; }
}
export class WardenUpstreamError extends Error {
  constructor(message) { super(message); this.name = 'WardenUpstreamError'; }
}

export function loadWardenConfig(env = process.env) {
  return {
    baseUrl: (env.WARDEN_URL || 'http://localhost:3003').replace(/\/$/, ''),
    // MCP tool calls (banking agent)
    vsId: env.WARDEN_VIRTUAL_SERVER_ID || '',
    mcpServerId: env.WARDEN_MCP_SERVER_ID || '',
    agentToken: env.WARDEN_AGENT_TOKEN || '',
    // A2A (Credit Card Agent, called as the A2A agent)
    a2aVsId: env.WARDEN_A2A_VS_ID || '',
    a2aTargetId: env.WARDEN_A2A_TARGET_ID || '',
    a2aAgentToken: env.WARDEN_A2A_AGENT_TOKEN || '',
    // Chat message scanning: the virtual server that hosts the shared chat-scan interceptors.
    chatVsId: env.WARDEN_CHAT_VS_ID || '',
    // Name of the Credential Vault secret holding the Warden API key. Leave empty when the
    // virtual server has no active API keys; the vault is then not contacted at all.
    apiKeySecret: env.WARDEN_API_KEY_SECRET || '',
  };
}

export function createWardenGateway({ config, fetchImpl = fetch, timeoutMs = 25000, vaultFactory = createVaultClient }) {
  const toolsConfigured = !!(config.vsId && config.mcpServerId && config.agentToken);
  const a2aConfigured = !!(config.a2aVsId && config.a2aTargetId && config.a2aAgentToken);
  const scanConfigured = !!(config.chatVsId && config.agentToken);

  // One vault client (and lease cache) per agent identity, so each agent only ever reads what its own
  // vault policy permits.
  const vaults = new Map();
  const vaultFor = (agentToken) => {
    if (!vaults.has(agentToken)) vaults.set(agentToken, vaultFactory({ baseUrl: config.baseUrl, agentToken, fetchImpl }));
    return vaults.get(agentToken);
  };

  async function credentials(agentToken) {
    const headers = { 'X-Agent-Token': agentToken };
    if (config.apiKeySecret) headers['X-API-Key'] = await vaultFor(agentToken).getSecret(config.apiKeySecret);
    return headers;
  }

  const post = (url, headers, payload) => request('POST', url, headers, payload);
  async function request(method, url, headers, payload) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    let res;
    try {
      res = await fetchImpl(url, {
        method,
        headers: { 'Content-Type': 'application/json', ...headers },
        ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
        redirect: 'error', // never forward credentials to a redirect target
        signal: ctl.signal,
      });
    } catch (e) {
      throw new WardenUpstreamError(`Could not reach the Warden gateway (${e.name === 'AbortError' ? 'timed out' : e.message})`);
    } finally {
      clearTimeout(timer);
    }
    let body;
    try { body = await res.json(); } catch { throw new WardenUpstreamError(`Warden returned a non-JSON response (HTTP ${res.status})`); }
    return { status: res.status, body };
  }

  return {
    describe: () => ({ toolsConfigured, a2aConfigured, scanConfigured }),

    /**
     * Scans one chat message through Warden's interceptors, as the banking agent ('mcp') or the A2A agent ('a2a').
     * Warden takes the agent's identity from its token, so findings and scores land on the right agent and the
     * browser cannot claim to be a different one. The browser no longer talks to Warden at all.
     */
    async scan({ idToken, text, direction, agent }) {
      if (!scanConfigured) throw new GatewayConfigError('Chat scanning is not configured on the server (set WARDEN_CHAT_VS_ID and WARDEN_AGENT_TOKEN)');
      const agentToken = agent === 'a2a' ? config.a2aAgentToken : config.agentToken;
      if (!agentToken) throw new GatewayConfigError('The Credit Card Agent is not configured on the server (set WARDEN_A2A_AGENT_TOKEN)');
      const headers = { ...(idToken ? { 'x-id-token': `Bearer ${idToken}` } : {}), ...(await credentials(agentToken)) };
      return post(`${config.baseUrl}/api/interceptors/${config.chatVsId}/scan`, headers, { text, direction });
    },

    /** Reads an approval ticket's status as the agent that made the call (Warden only shows a ticket to its own agent). */
    async approvalStatus({ ticketId, agent }) {
      const agentToken = agent === 'a2a' ? config.a2aAgentToken : config.agentToken;
      if (!agentToken) throw new GatewayConfigError(agent === 'a2a' ? 'The Credit Card Agent is not configured on the server (set WARDEN_A2A_AGENT_TOKEN)' : 'The banking agent is not configured on the server (set WARDEN_AGENT_TOKEN)');
      return request('GET', `${config.baseUrl}/api/approvals/${encodeURIComponent(ticketId)}/status`, await credentials(agentToken));
    },

    /** Relays one MCP tool call through the Warden proxy. Returns Warden's status and JSON body unchanged. */
    async callTool({ userToken, idToken, toolName, args }) {
      if (!toolsConfigured) {
        throw new GatewayConfigError('Warden tool calls are not configured on the server (set WARDEN_VIRTUAL_SERVER_ID, WARDEN_MCP_SERVER_ID and WARDEN_AGENT_TOKEN)');
      }
      const headers = {
        Authorization: `Bearer ${userToken}`,
        'x-user-token': `Bearer ${userToken}`,
        ...(idToken ? { 'x-id-token': `Bearer ${idToken}` } : {}),
        ...(await credentials(config.agentToken)),
      };
      return post(`${config.baseUrl}/api/proxy/${config.vsId}`, headers,
        { mcp_server_id: config.mcpServerId, tool_name: toolName, arguments: args });
    },

    /** Relays one A2A SendMessage to the Credit Card Agent through Warden. */
    async sendA2A({ userToken, question, skillId, contextId }) {
      if (!a2aConfigured) {
        throw new GatewayConfigError('The Credit Card Agent is not configured on the server (set WARDEN_A2A_VS_ID, WARDEN_A2A_TARGET_ID and WARDEN_A2A_AGENT_TOKEN)');
      }
      const params = {
        message: { messageId: randomUUID(), contextId: contextId || randomUUID(), role: 'ROLE_USER', parts: [{ text: question }] },
        ...(skillId ? { metadata: { skillId } } : {}),
      };
      const headers = {
        'A2A-Version': '1.0',
        'X-User-Token': `Bearer ${userToken}`,
        ...(await credentials(config.a2aAgentToken)),
      };
      return post(`${config.baseUrl}/a2a/${config.a2aVsId}/${config.a2aTargetId}`, headers,
        { jsonrpc: '2.0', id: randomUUID(), method: 'SendMessage', params });
    },
  };
}
