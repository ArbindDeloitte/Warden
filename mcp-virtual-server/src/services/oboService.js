const axios = require('axios');
const jwt = require('jsonwebtoken');
const { getOboToken, setOboToken } = require('./tokenCache');

/**
 * Exchange a user's access token for an OBO (On-Behalf-Of) token using Okta's
 * token exchange grant (RFC 8693).
 *
 * Returns the cached OBO token if still fresh, otherwise performs the exchange.
 */
async function exchangeForOboToken(userAccessToken, virtualServer) {
  // Check cache first
  const cached = await getOboToken(userAccessToken);
  if (cached) return { token: cached, fromCache: true };

  const { okta_issuer, okta_client_id, okta_client_secret, okta_audience } = virtualServer;

  if (!okta_issuer || !okta_client_id || !okta_client_secret) {
    throw new Error('Virtual server missing Okta OBO configuration (issuer, client_id, client_secret)');
  }

  const tokenEndpoint = `${okta_issuer.replace(/\/$/, '')}/v1/token`;

  // Derive the scope list from the user's own token (pass through what they already have,
  // excluding OIDC scopes that Auth Server B likely doesn't expose).
  const userClaims = extractTokenClaims(userAccessToken);
  const oidcScopes = new Set(['openid', 'profile', 'email', 'offline_access']);
  const bankingScopes = (userClaims.scopes || []).filter(s => !oidcScopes.has(s));

  const params = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: userAccessToken,
    subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    // audience tells Auth Server B which resource this token is for (NOT a scope value)
    ...(okta_audience ? { audience: okta_audience } : {}),
    // scope must be actual scope names, not the audience URL
    ...(bankingScopes.length > 0 ? { scope: bankingScopes.join(' ') } : {}),
  });

  const credentials = Buffer.from(`${okta_client_id}:${okta_client_secret}`).toString('base64');

  try {
    const response = await axios.post(tokenEndpoint, params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${credentials}`,
      },
      timeout: 10000,
    });

    const { access_token, expires_in } = response.data;
    if (!access_token) throw new Error('OBO exchange returned no access_token');

    // Cache the OBO token
    await setOboToken(userAccessToken, access_token, expires_in || 3600);

    return { token: access_token, fromCache: false };
  } catch (err) {
    const detail = err.response?.data
      ? JSON.stringify(err.response.data)
      : err.message;
    throw new Error(`OBO exchange failed: ${detail}`);
  }
}

/**
 * Parse JWT claims without verification (verification happens upstream).
 * Returns { sub, jti, scopes, groups, exp }.
 */
function extractTokenClaims(accessToken) {
  try {
    const decoded = jwt.decode(accessToken);
    if (!decoded) return {};

    const scopes = decoded.scp
      ? (Array.isArray(decoded.scp) ? decoded.scp : decoded.scp.split(' '))
      : decoded.scope
        ? decoded.scope.split(' ')
        : [];

    const groups = decoded.groups || decoded['cognito:groups'] || [];

    return {
      sub: decoded.sub,
      jti: decoded.jti,
      scopes,
      groups: Array.isArray(groups) ? groups : [],
      exp: decoded.exp,
    };
  } catch {
    return {};
  }
}

module.exports = { exchangeForOboToken, extractTokenClaims };
