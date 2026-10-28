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

const app = express();
const PORT = process.env.PORT || 3003;

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

// API routes
app.use('/api/mcp', mcpRegistry);
app.use('/api/virtual-servers', virtualServers);
app.use('/api/token-policies', tokenPolicies);
app.use('/api/proxy', proxy);
app.use('/api/audit', audit);
app.use('/api/interceptors', interceptors);
app.use('/api/keys', apiKeys);
app.use('/api/approvals', approvalsRouter);

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

const server = app.listen(PORT, () => {
  console.log(`\n✅ MCP Virtual Server running on http://localhost:${PORT}`);
  console.log(`   UI:    http://localhost:${PORT}`);
  console.log(`   Proxy: POST http://localhost:${PORT}/api/proxy/:virtualServerId\n`);

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
