const axios = require('axios');
const crypto = require('crypto');

// Session cache: cacheKey → { sessionId, expiresAt }
// Key is `url` for static-auth calls (fetchMcpTools) or `url:tokenHash` for user sessions.
// This prevents one user's session from being reused for a different user.
const sessionCache = new Map();
const SESSION_TTL_MS = 10 * 60 * 1000; // 10 minutes

function sessionKey(url, oboToken) {
  if (!oboToken) return url;
  const hash = crypto.createHash('sha256').update(oboToken).digest('hex').slice(0, 16);
  return `${url}:${hash}`;
}

function getCachedSession(key) {
  const entry = sessionCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { sessionCache.delete(key); return null; }
  return entry.sessionId;
}

function setCachedSession(key, sessionId) {
  sessionCache.set(key, { sessionId, expiresAt: Date.now() + SESSION_TTL_MS });
}

function buildHeaders(auth_type, config) {
  const headers = {
    'Content-Type': 'application/json',
    // MCP Streamable HTTP transport requires both accept types
    'Accept': 'application/json, text/event-stream',
  };

  if (auth_type === 'bearer' && config.token) {
    headers['Authorization'] = `Bearer ${config.token}`;
  } else if (auth_type === 'apikey' && config.header && config.key) {
    headers[config.header] = config.key;
  } else if (auth_type === 'basic' && config.username && config.password) {
    const creds = Buffer.from(`${config.username}:${config.password}`).toString('base64');
    headers['Authorization'] = `Basic ${creds}`;
  }

  return headers;
}

/**
 * Run the MCP initialization handshake:
 *   POST initialize → get mcp-session-id
 *   POST notifications/initialized
 *
 * Returns the session ID (or null if server doesn't use sessions).
 */
async function initializeMcpSession(url, headers, cacheKey) {
  const key = cacheKey || url;

  // Check cache first
  const cached = getCachedSession(key);
  if (cached) return cached;

  const initRes = await axios.post(
    url,
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: { roots: { listChanged: true } },
        clientInfo: { name: 'mcp-virtual-server', version: '1.0.0' },
      },
    },
    { headers, timeout: 8000 }
  );

  // Session ID comes back as a response header
  const sessionId = initRes.headers['mcp-session-id'] || null;
  const headersWithSession = { ...headers };
  if (sessionId) headersWithSession['mcp-session-id'] = sessionId;

  // Send initialized notification (no response expected — fire and forget)
  axios.post(
    url,
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { headers: headersWithSession, timeout: 5000 }
  ).catch(() => {});

  if (sessionId) setCachedSession(key, sessionId);
  return sessionId;
}

/**
 * Parse the response body — handles both plain JSON and SSE-wrapped JSON.
 * SSE format: lines starting with "data: <json>\n\n"
 */
function parseRpcResponse(data) {
  if (typeof data === 'object' && data !== null) return data;

  if (typeof data === 'string') {
    // SSE: extract the last data: line
    const lines = data.split('\n').filter(l => l.startsWith('data: '));
    for (const line of lines.reverse()) {
      try { return JSON.parse(line.slice(6)); } catch {}
    }
  }

  return null;
}

/**
 * Discover tools from an MCP server.
 * Performs the full initialize → initialized → tools/list flow.
 */
async function fetchMcpTools(mcpServer) {
  const { url, auth_type, auth_config } = mcpServer;
  const config = auth_config ? JSON.parse(auth_config) : {};
  const baseUrl = url.replace(/\/$/, '');

  const headers = buildHeaders(auth_type, config);

  // Initialize session (cached after first call)
  let sessionId;
  try {
    sessionId = await initializeMcpSession(baseUrl, headers);
  } catch (err) {
    throw new Error(`MCP initialize failed for ${baseUrl}: ${err.response?.data ? JSON.stringify(err.response.data) : err.message}`);
  }

  if (sessionId) headers['mcp-session-id'] = sessionId;

  // Request tools list
  try {
    const response = await axios.post(
      baseUrl,
      { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
      { headers, timeout: 15000 }
    );

    const parsed = parseRpcResponse(response.data);
    const tools = parsed?.result?.tools;

    if (Array.isArray(tools)) return tools;
    if (parsed?.error) throw new Error(`MCP error: ${JSON.stringify(parsed.error)}`);

    throw new Error(`Unexpected tools/list response: ${JSON.stringify(parsed)}`);
  } catch (err) {
    // Session may have expired — clear cache and propagate
    sessionCache.delete(baseUrl);
    throw err;
  }
}

/**
 * Forward a tool call to the MCP server using the OBO token.
 * Re-uses the cached session when available, re-initializes on failure.
 * On HTTP 400 (typically a stale session after MCP server restart), clears
 * the session cache and retries once with a fresh initialize.
 */
async function callMcpTool(mcpServer, toolName, toolArguments, oboToken, _isRetry = false) {
  const baseUrl = mcpServer.url.replace(/\/$/, '');
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json, text/event-stream',
    'Authorization': `Bearer ${oboToken}`,
  };

  // Key sessions per user (OBO token) so different users never share a session.
  // The banking MCP server binds a session to one user at initialize time.
  const key = sessionKey(baseUrl, oboToken);
  let sessionId = getCachedSession(key);

  if (!sessionId) {
    try {
      sessionId = await initializeMcpSession(baseUrl, headers, key);
    } catch (err) {
      const detail = err.response?.data ? ` (${JSON.stringify(err.response.data)})` : '';
      throw new Error(`MCP session init failed: ${err.message}${detail}`);
    }
  }

  if (sessionId) headers['mcp-session-id'] = sessionId;

  try {
    const response = await axios.post(
      baseUrl,
      {
        jsonrpc: '2.0',
        id: Date.now(),
        method: 'tools/call',
        params: { name: toolName, arguments: toolArguments || {} },
      },
      { headers, timeout: 30000 }
    );

    const parsed = parseRpcResponse(response.data);
    if (parsed?.error) throw new Error(`Tool call error: ${JSON.stringify(parsed.error)}`);
    return parsed;
  } catch (err) {
    // Clear stale session so the next call re-initializes
    sessionCache.delete(key);

    // HTTP 400 almost always means the MCP session was lost (e.g. server restarted).
    // Retry once with a fresh session before giving up.
    if (!_isRetry && err.response?.status === 400) {
      console.warn('[MCP] 400 on tools/call — session likely stale, retrying with fresh session');
      return callMcpTool(mcpServer, toolName, toolArguments, oboToken, true);
    }

    // Enrich the error message with the response body so callers can diagnose
    const detail = err.response?.data ? ` — ${JSON.stringify(err.response.data)}` : '';
    const enriched = new Error(`${err.message}${detail}`);
    enriched.response = err.response;
    throw enriched;
  }
}

module.exports = { fetchMcpTools, callMcpTool };
