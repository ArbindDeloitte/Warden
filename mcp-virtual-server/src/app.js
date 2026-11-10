require('dotenv').config();
require('express-async-errors');

const express = require('express');
const cors = require('cors');
const path = require('path');

const mcpRegistry = require('./routes/mcpRegistry');
const virtualServers = require('./routes/virtualServers');
const tokenPolicies = require('./routes/tokenPolicies');
const proxy = require('./routes/proxy');
const audit = require('./routes/audit');
const interceptors = require('./routes/interceptors');
const apiKeys = require('./routes/apiKeys');
const approvalsRouter = require('./routes/approvals');
const { processExpiredTickets } = require('./routes/approvals');
const agentsRouter = require('./routes/agents');
const scoringRouter = require('./routes/scoring');
const idpConfigs = require('./routes/idpConfigs');
const wardenFunctions = require('./routes/wardenFunctions');
const agentGroups = require('./routes/agentGroups');
const a2aAgents = require('./routes/a2aAgents');
const a2aPolicies = require('./routes/a2aPolicies');
const a2a = require('./routes/a2a');
const vaultRoutes = require('./routes/vault');
const adminAuth = require('./middleware/adminAuth');
const { createRateLimiter } = require('./middleware/rateLimit');

const app = express();
const PORT = process.env.PORT || 3003;
// Loopback by default: only processes on this machine (the banking backend, your browser) can reach Warden.
// Set WARDEN_HOST=0.0.0.0 to listen on every interface (then put it behind a firewall and set WARDEN_ADMIN_TOKEN).
const HOST = process.env.WARDEN_HOST || '127.0.0.1';

app.use(cors());
app.use(express.json({ limit: '10mb' }));
// Serve static assets with caching, but never cache index.html so UI changes take effect immediately
app.use(express.static(path.join(__dirname, '../public'), { etag: false }));
app.use((req, res, next) => {
  if (req.path === '/' || req.path.endsWith('.html')) {
    res.setHeader('Cache-Control', 'no-store');
  }
  next();
});

// ── Security ────────────────────────────────────────────────────────────────────────────────────
// Admin sign-in (open mode when WARDEN_ADMIN_TOKEN is unset), then the gate over the rest of /api. The data-plane
// routes the gate lets through authenticate themselves (see middleware/adminAuth.js).
const limitProxy = createRateLimiter({ scope: 'proxy' });
const limitA2a = createRateLimiter({ scope: 'a2a', jsonRpc: true });
const limitMisc = createRateLimiter({ scope: 'agent-api' });
const loginLimit = createRateLimiter({ scope: 'login' });
app.use('/api/auth/login', loginLimit);
app.use('/api/auth', adminAuth.routes);
app.use('/api', adminAuth.gate);
app.use('/api/proxy', limitProxy);
app.use('/a2a', (req, res, next) => (req.method === 'POST' ? limitA2a(req, res, next) : next()));
app.use(['/api/vault/checkout', '/api/vault/sign'], limitMisc);
app.use(/^\/api\/interceptors\/[^/]+\/scan$/, limitMisc);

// API routes
app.use('/api/mcp', mcpRegistry);
app.use('/api/virtual-servers', virtualServers);
app.use('/api/token-policies', tokenPolicies);
app.use('/api/proxy', proxy);
app.use('/api/audit', audit);
app.use('/api/interceptors', interceptors);
app.use('/api/keys', apiKeys);
app.use('/api/approvals', approvalsRouter);
app.use('/api/agents', agentsRouter);
app.use('/api/scoring', scoringRouter);
app.use('/api/virtual-servers/:id/idp-configs', idpConfigs);
app.use('/api/warden-functions', wardenFunctions);
app.use('/api/agent-groups', agentGroups);
app.use('/api/a2a-agents', a2aAgents);
app.use('/api/a2a-policies', a2aPolicies);
app.use('/api/vault', vaultRoutes);

// A2A gateway + discovery (must precede the SPA fallback)
app.use('/a2a', a2a);
app.use('/.well-known', a2a.wellKnown);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// JSON 404 for unmatched API routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: `No API route: ${req.method} ${req.originalUrl}` });
});

// SPA fallback — serve index.html for all non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[Error]', err.message);
  const body = { error: err.message || 'Internal server error' };
  if (err.detail) body.detail = err.detail;
  res.status(err.status || 500).json(body);
});

// Background job: expire pending approval tickets every 30 seconds
setInterval(processExpiredTickets, 30 * 1000);

const server = app.listen(PORT, HOST, () => {
  console.log(`\n✅ MCP Virtual Server running on http://localhost:${PORT}`);
  const notice = adminAuth.startupNotice();
  console.log(`   Listening on ${HOST}${HOST === '127.0.0.1' ? ' (this machine only)' : ''}`);
  console[notice.level === 'warn' ? 'warn' : 'log'](`   ${notice.level === 'warn' ? '⚠️  ' : '🔒 '}${notice.text}`);
  console.log(`   UI:    http://localhost:${PORT}`);
  console.log(`   Proxy: POST http://localhost:${PORT}/api/proxy/:virtualServerId\n`);

  // Initialize interceptor scanners after the server is accepting requests.
  // EmbeddingScanner loads the ONNX model (~2–3 s); until ready it degrades gracefully.
  const registry = require('./interceptors/ScannerRegistry');
  registry.initAll()
    .then(() => console.log('[Interceptors] All scanners ready'))
    .catch(err => console.warn('[Interceptors] Scanner init error (degraded):', err.message));
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n❌ Port ${PORT} is already in use. Set a different port with PORT=XXXX npm start\n`);
  } else {
    console.error('Server error:', err.message);
  }
  process.exit(1);
});

module.exports = app;
