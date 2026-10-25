import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { randomUUID } from 'crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

import { initDatabase, getDb, getOrCreateUser } from './db.js';
import { seedDatabase } from './seed.js';
import accountsRouter from './routes/accounts.js';
import paymentsRouter from './routes/payments.js';
import standingOrdersRouter from './routes/standing-orders.js';
import transfersRouter from './routes/transfers.js';
import adminRouter from './routes/admin.js';
import { createMcpServer } from './mcp/server.js';

const app = express();
const PORT = process.env.PORT || 3001;

// ─── CORS ─────────────────────────────────────────────────────────────────────
const allowedOrigins = [
  process.env.FRONTEND_URL || 'http://localhost:5173',
  'http://localhost:3000',
  'http://localhost:5174',
];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. curl, Postman) and allowed origins
      if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'mcp-session-id'],
  })
);

// ─── Body Parsing ─────────────────────────────────────────────────────────────
app.use(express.json());

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── REST Routes ──────────────────────────────────────────────────────────────
app.use('/api/accounts', accountsRouter);
app.use('/api/admin', adminRouter);
app.use('/api/transactions', (req, res) => {
  // Convenience redirect – transactions are always scoped to an account
  res.status(400).json({
    success: false,
    error: 'Use /api/accounts/:id/transactions to query transactions',
  });
});
app.use('/api/payments', paymentsRouter);
app.use('/api/standing-orders', standingOrdersRouter);
app.use('/api/transfers', transfersRouter);

// ─── MCP (Model Context Protocol) ─────────────────────────────────────────────
// Security is handled by PointGuard (OBO token exchange + policy enforcement).
// We decode the JWT payload forwarded by PointGuard to extract user identity,
// but do NOT cryptographically verify it — PointGuard is the trust boundary.

function decodeMcpToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  try {
    const payload = authHeader.split(' ')[1].split('.')[1];
    const padded = payload.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((payload.length + 3) % 4);
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf-8'));
  } catch {
    return null;
  }
}

// Session store: sessionId -> { transport }  (auto-expires after 30 min)
const mcpSessions = new Map();

function patchAcceptHeader(req) {
  // MCP SDK requires Accept to include text/event-stream; gateways like
  // PointGuard may only send application/json — patch it transparently.
  const accept = req.headers['accept'] || '';
  if (!accept.includes('text/event-stream')) {
    req.headers['accept'] = accept
      ? `${accept}, text/event-stream`
      : 'application/json, text/event-stream';
  }
}

// POST /mcp  — handles MCP JSON-RPC messages
app.post('/mcp', async (req, res) => {
  patchAcceptHeader(req);

  try {
    // Decode user identity from PointGuard-forwarded token (no verification)
    const claims = decodeMcpToken(req);
    const sub   = claims?.sub   || 'pointguard-system';
    const email = claims?.email || null;
    const name  = claims?.name  || null;
    const db   = getDb();
    const user = getOrCreateUser(db, sub, email, name);

    // Reuse an existing session if the client sends mcp-session-id
    const sessionId = req.headers['mcp-session-id'];
    if (sessionId && mcpSessions.has(sessionId)) {
      const { transport } = mcpSessions.get(sessionId);
      await transport.handleRequest(req, res, req.body);
      return;
    }

    // New session: create a fresh MCP server + transport
    const mcpServer = createMcpServer(user.id, db);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (newId) => {
        mcpSessions.set(newId, { transport });
        // Auto-clean after 30 minutes of inactivity
        setTimeout(() => mcpSessions.delete(newId), 30 * 60 * 1000);
      },
      enableJsonResponse: true,
    });

    await mcpServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error('MCP POST error:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Internal server error', message: err.message });
    }
  }
});

// GET /mcp  — SSE stream (not used with enableJsonResponse, kept for spec compliance)
app.get('/mcp', async (req, res) => {
  patchAcceptHeader(req);
  const sessionId = req.headers['mcp-session-id'];
  if (sessionId && mcpSessions.has(sessionId)) {
    const { transport } = mcpSessions.get(sessionId);
    await transport.handleRequest(req, res);
    return;
  }
  res.status(404).json({ error: 'Session not found' });
});

// DELETE /mcp  — session teardown
app.delete('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'];
  if (sessionId && mcpSessions.has(sessionId)) {
    const { transport } = mcpSessions.get(sessionId);
    await transport.close();
    mcpSessions.delete(sessionId);
  }
  res.status(200).json({ ok: true });
});

// ─── Dev Tools (no auth required — local dev only) ───────────────────────────

// GET /api/dev/config: returns OBO-related env var values so the DevTools page
// can pre-fill the OBO Verifier form.  Secret is included because this endpoint
// is intentionally local-only (never exposed in production).
app.get('/api/dev/config', (_req, res) => {
  res.json({
    serverBTokenUrl: process.env.OBO_SERVER_B_TOKEN_URL || '',
    gwClientId:      process.env.OBO_GW_CLIENT_ID      || '',
    gwClientSecret:  process.env.OBO_GW_CLIENT_SECRET  || '',
    expectedAud:     process.env.OBO_EXPECTED_AUD      || 'api://banking-mcp',
    scopes:          process.env.OBO_SCOPES            || 'accounts:read accounts:balance:read accounts:transactions:read payments:read',
  });
});

// POST /api/dev/obo-verify: proxies an OBO token exchange to Okta so the
// browser-based DevTools page can call it without CORS issues.
app.post('/api/dev/obo-verify', async (req, res) => {
  try {
    const {
      userToken,
      serverBTokenUrl,
      gwClientId,
      gwClientSecret,
      expectedAud = 'api://banking-mcp',
      scopes = 'accounts:read accounts:balance:read accounts:transactions:read payments:read',
    } = req.body;

    if (!userToken || !serverBTokenUrl || !gwClientId || !gwClientSecret) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: userToken, serverBTokenUrl, gwClientId, gwClientSecret',
      });
    }

    const basicHeader = 'Basic ' + Buffer.from(`${gwClientId}:${gwClientSecret}`).toString('base64');

    const params = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      subject_token: userToken,
      audience: expectedAud,
      scope: scopes,
    });

    const response = await fetch(serverBTokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: basicHeader,
      },
      body: params.toString(),
    });

    const responseText = await response.text();
    let responseJson = null;
    try { responseJson = JSON.parse(responseText); } catch { /* not JSON */ }

    if (!response.ok) {
      const errCode = responseJson?.error || responseJson?.errorCode || 'unknown_error';
      const errDesc = responseJson?.error_description || responseJson?.errorSummary || responseText;
      return res.status(response.status).json({
        success: false,
        httpStatus: response.status,
        error: errCode,
        errorDescription: errDesc,
        raw: responseJson,
      });
    }

    const accessToken = responseJson?.access_token || '';
    let claims = null;
    if (accessToken) {
      try {
        const parts = accessToken.split('.');
        if (parts.length >= 2) {
          const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
          const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
          claims = JSON.parse(Buffer.from(padded, 'base64').toString('utf-8'));
        }
      } catch { /* non-JWT response */ }
    }

    return res.json({ success: true, httpStatus: response.status, token: responseJson, claims });
  } catch (err) {
    console.error('POST /api/dev/obo-verify error:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ─── 404 Catch-all ────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, error: 'Endpoint not found' });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ─── Startup ──────────────────────────────────────────────────────────────────
async function main() {
  try {
    initDatabase();
    const db = getDb();
    seedDatabase(db);

    app.listen(PORT, () => {
      console.log(`Banking backend running on http://localhost:${PORT}`);
      console.log(`  REST API: http://localhost:${PORT}/api`);
      console.log(`  MCP endpoint: http://localhost:${PORT}/mcp`);
      console.log(`  Health: http://localhost:${PORT}/api/health`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

main();
