const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { extractTokenClaims } = require('../services/oboService');

const clientCache = new Map();

function getJwksClient(jwksUri) {
  if (!clientCache.has(jwksUri)) {
    clientCache.set(jwksUri, jwksClient({
      jwksUri,
      cache: true,
      cacheMaxEntries: 10,
      cacheMaxAge: 600000, // 10 minutes
      rateLimit: true,
      timeout: 5000, // 5s — prevents hanging if Okta JWKS endpoint is slow
    }));
  }
  return clientCache.get(jwksUri);
}

/**
 * Verify the incoming Bearer token against the virtual server's JWKS endpoint.
 * Attaches parsed claims to req.tokenClaims and raw token to req.accessToken.
 *
 * If jwks_uri is not configured, falls back to unverified claim extraction
 * (useful for dev/testing — log a warning). With no JWKS and no token,
 * still proceeds in dev mode with empty claims.
 *
 * IMPORTANT: always calls next() (with or without an error) so that callers
 * that wrap this in a Promise do not hang indefinitely.
 */
async function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;

  const virtualServer = req.virtualServer;
  const jwksUri = virtualServer?.jwks_uri
    || (virtualServer?.okta_issuer
      ? `${virtualServer.okta_issuer.replace(/\/$/, '')}/v1/keys`
      : null)
    || process.env.JWKS_URI;

  // Dev mode: no JWKS URI → skip verification, proceed with whatever claims are in the token
  if (!jwksUri) {
    console.warn('[Auth] No JWKS URI configured — using unverified token claims (dev only)');
    req.accessToken = token;
    req.tokenClaims = token ? extractTokenClaims(token) : {};
    req.tokenVerified = false;
    return next();
  }

  // JWKS verification mode: a token is required
  if (!token) {
    const err = new Error('Missing Bearer token');
    err.status = 401;
    return next(err);
  }

  req.accessToken = token;

  try {
    const client = getJwksClient(jwksUri);

    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(token, (header, callback) => {
        client.getSigningKey(header.kid, (err, key) => {
          if (err) return callback(err);
          callback(null, key.getPublicKey());
        });
      }, { algorithms: ['RS256'] }, (err, decoded) => {
        if (err) reject(err);
        else resolve(decoded);
      });
    });

    const scopes = decoded.scp
      ? (Array.isArray(decoded.scp) ? decoded.scp : decoded.scp.split(' '))
      : decoded.scope
        ? decoded.scope.split(' ')
        : [];

    const groups = decoded.groups || decoded['cognito:groups'] || [];

    req.tokenClaims = {
      sub: decoded.sub,
      jti: decoded.jti,
      scopes,
      groups: Array.isArray(groups) ? groups : [],
      exp: decoded.exp,
    };
    req.tokenVerified = true;
    next();
  } catch (err) {
    const authErr = new Error('Invalid or expired token');
    authErr.status = 401;
    authErr.detail = err.message;
    return next(authErr);
  }
}

module.exports = { verifyToken };
