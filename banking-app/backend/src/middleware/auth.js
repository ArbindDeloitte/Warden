import OktaJwtVerifier from '@okta/jwt-verifier';
import dotenv from 'dotenv';

dotenv.config();

const oktaJwtVerifier = new OktaJwtVerifier({
  issuer: process.env.OKTA_ISSUER || 'https://demo-arbind-lochan-mishra.okta.com/oauth2/default',
});

const AUDIENCE = process.env.OKTA_AUDIENCE || 'api://banking';

export async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Missing or invalid Authorization header. Expected: Bearer <token>',
      });
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'No token provided',
      });
    }

    const jwt = await oktaJwtVerifier.verifyAccessToken(token, AUDIENCE);
    const claims = jwt.claims;

    req.user = {
      sub: claims.sub,
      email: claims.email || null,
      name: claims.name || null,
      groups: claims.groups || [],
      scp: Array.isArray(claims.scp) ? claims.scp : (claims.scp ? [claims.scp] : []),
    };

    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired token',
      details: err.message,
    });
  }
}

export function requireScope(scope) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Not authenticated',
      });
    }

    const scopes = req.user.scp || [];

    if (!scopes.includes(scope)) {
      return res.status(403).json({
        success: false,
        error: `Insufficient permissions. Required scope: ${scope}`,
      });
    }

    next();
  };
}

export function requireGroup(group) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Not authenticated' });
    }

    const groups = req.user.groups || [];

    if (!groups.includes(group)) {
      return res.status(403).json({
        success: false,
        error: `Access denied. Required group: ${group}`,
      });
    }

    next();
  };
}
