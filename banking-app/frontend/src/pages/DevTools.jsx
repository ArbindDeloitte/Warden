import React, { useState, useRef } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001/api';

// ─── JWT helpers ──────────────────────────────────────────────────────────────
function decodeJwtPayload(token) {
  try {
    const parts = token.trim().split('.');
    if (parts.length < 2) return null;
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

function formatTs(epoch) {
  if (!epoch) return '—';
  return new Date(epoch * 1000).toLocaleString();
}

function tokenExpiryInfo(claims) {
  if (!claims?.exp) return null;
  const now = Math.floor(Date.now() / 1000);
  const diff = claims.exp - now;
  if (diff <= 0) return { expired: true, label: `Expired ${Math.abs(Math.round(diff / 60))} min ago` };
  return { expired: false, label: `Valid — expires in ${Math.round(diff / 60)} min` };
}

// ─── ClaimsTable ─────────────────────────────────────────────────────────────
function ClaimsTable({ claims }) {
  if (!claims) return null;
  return (
    <div className="table-wrapper" style={{ marginTop: '12px' }}>
      <table className="table">
        <thead>
          <tr><th>Claim</th><th>Value</th></tr>
        </thead>
        <tbody>
          {Object.entries(claims).map(([k, v]) => {
            const isTs = (k === 'exp' || k === 'iat' || k === 'auth_time') && typeof v === 'number';
            const display = Array.isArray(v) ? v.join(', ') : isTs ? `${v}  (${formatTs(v)})` : String(v);
            return (
              <tr key={k}>
                <td><code>{k}</code></td>
                <td style={{ wordBreak: 'break-all' }}>{display}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ─── CopyButton ──────────────────────────────────────────────────────────────
function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      const el = document.createElement('textarea');
      el.value = text;
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button className="btn btn-outline btn-sm" onClick={copy} style={{ minWidth: '80px' }}>
      {copied ? '✓ Copied' : label}
    </button>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAB 1 — Token Inspector
// ═══════════════════════════════════════════════════════════════════════════════
function TokenInspector() {
  const [raw, setRaw] = useState('');
  const [accessToken, setAccessToken] = useState('');
  const [idToken, setIdToken] = useState('');
  const [parseError, setParseError] = useState('');
  const [activeToken, setActiveToken] = useState('access');

  function parse() {
    setParseError('');
    setAccessToken('');
    setIdToken('');
    const text = raw.trim();
    if (!text) { setParseError('Paste something first.'); return; }

    // If it looks like a JWT already (three dot-separated base64url segments)
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(text)) {
      setAccessToken(text);
      return;
    }

    // Try JSON
    try {
      const obj = JSON.parse(text);
      const at = obj.access_token
        || obj.accessToken
        || obj.tokenType?.accessToken
        || obj?.accessToken?.accessToken
        || (obj?.accessToken && typeof obj.accessToken === 'object' ? obj.accessToken.value : null);
      const it = obj.id_token
        || obj.idToken
        || obj?.idToken?.idToken
        || (obj?.idToken && typeof obj.idToken === 'object' ? obj.idToken.idToken : null);
      if (!at && !it) { setParseError('JSON found but no access_token or id_token field detected.'); return; }
      if (at) setAccessToken(at);
      if (it) setIdToken(it);
      setActiveToken(at ? 'access' : 'id');
    } catch {
      setParseError('Could not parse as JSON or JWT. Make sure you paste the full Okta token storage JSON.');
    }
  }

  const shown = activeToken === 'access' ? accessToken : idToken;
  const claims = shown ? decodeJwtPayload(shown) : null;
  const expiry = tokenExpiryInfo(claims);

  return (
    <div>
      <p className="page-subtitle" style={{ marginBottom: '16px' }}>
        Paste the full Okta token JSON (from Session Storage → okta-token-storage) or paste a bare JWT directly.
      </p>

      <div className="form-card">
        <div className="form-group">
          <label className="form-label">Paste token JSON or JWT</label>
          <textarea
            className="form-input"
            rows={6}
            placeholder={'{\n  "accessToken": { "accessToken": "eyJ..." },\n  "idToken": { "idToken": "eyJ..." }\n}'}
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            style={{ fontFamily: 'monospace', fontSize: '12px', resize: 'vertical' }}
          />
        </div>
        <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
          <button className="btn btn-primary" onClick={parse}>Inspect</button>
          <button className="btn btn-outline" onClick={() => { setRaw(''); setAccessToken(''); setIdToken(''); setParseError(''); }}>Clear</button>
        </div>
        {parseError && (
          <div className="alert alert-error" style={{ marginTop: '12px' }}>⚠️ {parseError}</div>
        )}
      </div>

      {(accessToken || idToken) && (
        <div className="section" style={{ marginTop: '24px' }}>
          {/* Token picker */}
          {accessToken && idToken && (
            <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
              <button
                className={`btn ${activeToken === 'access' ? 'btn-primary' : 'btn-outline'}`}
                onClick={() => setActiveToken('access')}
              >
                Access Token
              </button>
              <button
                className={`btn ${activeToken === 'id' ? 'btn-primary' : 'btn-outline'}`}
                onClick={() => setActiveToken('id')}
              >
                ID Token
              </button>
            </div>
          )}
          {!idToken && accessToken && (
            <h3 className="section-title">Access Token</h3>
          )}
          {!accessToken && idToken && (
            <h3 className="section-title">ID Token</h3>
          )}

          {/* Expiry pill */}
          {expiry && (
            <div style={{ marginBottom: '12px' }}>
              <span className={`badge ${expiry.expired ? 'badge-rejected' : 'badge-approved'}`} style={{ fontSize: '13px', padding: '4px 10px' }}>
                {expiry.label}
              </span>
            </div>
          )}

          {/* Raw token + copy */}
          <div className="detail-card" style={{ padding: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <span className="balance-label">Raw token</span>
              <CopyButton text={shown} label="Copy token" />
            </div>
            <div style={{
              fontFamily: 'monospace', fontSize: '11px', wordBreak: 'break-all',
              maxHeight: '80px', overflow: 'auto', color: 'var(--text-secondary, #666)'
            }}>
              {shown}
            </div>
          </div>

          {/* Decoded claims */}
          {claims ? (
            <>
              <h3 className="section-title" style={{ marginTop: '20px' }}>Decoded Claims</h3>
              <ClaimsTable claims={claims} />
            </>
          ) : (
            <div className="alert alert-error" style={{ marginTop: '12px' }}>Could not decode JWT payload.</div>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAB 2 — OBO Verifier
// ═══════════════════════════════════════════════════════════════════════════════

function Check({ pass, label, detail }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', marginBottom: '6px' }}>
      <span style={{ fontSize: '16px', lineHeight: '1.4', flexShrink: 0 }}>{pass ? '✅' : '❌'}</span>
      <div>
        <span style={{ fontWeight: '600' }}>{label}</span>
        {detail && <span style={{ marginLeft: '8px', color: 'var(--text-secondary, #666)', fontSize: '13px' }}>{detail}</span>}
      </div>
    </div>
  );
}

function diagnosisFor(error) {
  switch (error) {
    case 'invalid_client':
      return 'GW_CLIENT_ID or GW_CLIENT_SECRET is wrong, or the app is not assigned to Auth Server B.';
    case 'unauthorized_client':
      return 'Token Exchange grant is not enabled on the PointGuardAI Gateway app. Enable it under General Settings → Advanced.';
    case 'invalid_token':
    case 'invalid_grant':
      return 'The User Token is expired or invalid. Get a fresh one from the banking frontend.';
    case 'access_denied':
      return 'No matching access policy rule on Auth Server B for this app/scopes.';
    case 'invalid_request':
      return 'Malformed request — check the Auth Server B token URL.';
    default:
      return null;
  }
}

// Small pill shown next to a label when a field was loaded from .env
function EnvBadge({ dirty }) {
  return (
    <span style={{
      marginLeft: '8px', fontSize: '10px', fontWeight: '600', letterSpacing: '0.04em',
      padding: '1px 6px', borderRadius: '4px',
      background: dirty ? 'rgba(245,158,11,0.15)' : 'rgba(16,185,129,0.12)',
      color: dirty ? '#b45309' : '#047857',
      border: `1px solid ${dirty ? 'rgba(245,158,11,0.35)' : 'rgba(16,185,129,0.3)'}`,
    }}>
      {dirty ? 'edited' : 'from .env'}
    </span>
  );
}

function OboVerifier() {
  const [userToken, setUserToken] = useState('');
  const [serverB, setServerB] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [audience, setAudience] = useState('api://banking-mcp');
  const [scopes, setScopes] = useState('accounts:read accounts:balance:read accounts:transactions:read payments:read');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [showSecret, setShowSecret] = useState(false);

  // Track which fields were loaded from env and whether user has changed them
  const [envValues, setEnvValues] = useState(null); // null = not loaded yet

  // Fetch env config from backend on mount
  React.useEffect(() => {
    fetch(`${API_BASE}/dev/config`)
      .then((r) => r.json())
      .then((cfg) => {
        setEnvValues(cfg);
        if (cfg.serverBTokenUrl) setServerB(cfg.serverBTokenUrl);
        if (cfg.gwClientId)      setClientId(cfg.gwClientId);
        if (cfg.gwClientSecret)  setClientSecret(cfg.gwClientSecret);
        if (cfg.expectedAud)     setAudience(cfg.expectedAud);
        if (cfg.scopes)          setScopes(cfg.scopes);
      })
      .catch(() => { /* backend not running — user fills manually */ });
  }, []);

  function resetToEnv() {
    if (!envValues) return;
    if (envValues.serverBTokenUrl) setServerB(envValues.serverBTokenUrl);
    if (envValues.gwClientId)      setClientId(envValues.gwClientId);
    if (envValues.gwClientSecret)  setClientSecret(envValues.gwClientSecret);
    if (envValues.expectedAud)     setAudience(envValues.expectedAud);
    if (envValues.scopes)          setScopes(envValues.scopes);
  }

  // Whether a field differs from the loaded env value
  const isDirty = (field, val) => envValues?.[field] && val !== envValues[field];
  const hasEnv = (field) => !!envValues?.[field];

  // Pre-decode user token for expiry check
  const userClaims = userToken.trim() ? decodeJwtPayload(userToken.trim()) : null;
  const userExpiry = tokenExpiryInfo(userClaims);

  async function runVerify(e) {
    e.preventDefault();
    setResult(null);
    setLoading(true);
    try {
      const resp = await fetch(`${API_BASE}/dev/obo-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userToken: userToken.trim(),
          serverBTokenUrl: serverB.trim(),
          gwClientId: clientId.trim(),
          gwClientSecret: clientSecret.trim(),
          expectedAud: audience.trim(),
          scopes: scopes.trim(),
        }),
      });
      const data = await resp.json();
      setResult(data);
    } catch (err) {
      setResult({ success: false, error: 'network_error', errorDescription: err.message });
    } finally {
      setLoading(false);
    }
  }

  const oboToken = result?.token?.access_token || '';
  const oboClaims = result?.claims || null;
  const expectedIssBase = serverB.trim().replace(/\/v1\/token$/, '');

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
        <p className="page-subtitle" style={{ margin: 0 }}>
          Paste a live Auth Server A access token to verify the full OBO exchange against Auth Server B.
        </p>
        {envValues && (
          <button className="btn btn-outline btn-sm" onClick={resetToEnv} style={{ marginLeft: '16px', flexShrink: 0 }}>
            ↺ Reset to .env
          </button>
        )}
      </div>

      {envValues && (envValues.gwClientId || envValues.serverBTokenUrl) && (
        <div className="alert" style={{
          marginBottom: '16px', padding: '10px 14px',
          background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.25)',
          borderRadius: '8px', color: 'inherit', fontSize: '13px',
        }}>
          ✅ Gateway credentials pre-filled from <code>backend/.env</code>.
          Fields marked <strong style={{ color: '#047857' }}>from .env</strong> were loaded automatically — edit any field to override.
        </div>
      )}

      <div className="form-card">
        <form onSubmit={runVerify}>
          {/* User Token */}
          <div className="form-group">
            <label className="form-label">
              User Token (Auth Server A access token) *
              {userClaims && userExpiry && (
                <span className={`badge ${userExpiry.expired ? 'badge-rejected' : 'badge-approved'}`} style={{ marginLeft: '10px', fontSize: '11px' }}>
                  {userExpiry.label}
                </span>
              )}
            </label>
            <textarea
              className="form-input"
              rows={4}
              placeholder="eyJraWQiOiJ..."
              value={userToken}
              onChange={(e) => setUserToken(e.target.value)}
              style={{ fontFamily: 'monospace', fontSize: '12px', resize: 'vertical' }}
              required
            />
            {userClaims?.sub && (
              <div style={{ fontSize: '12px', color: 'var(--text-secondary, #666)', marginTop: '4px' }}>
                sub: {userClaims.sub} · iss: {userClaims.iss}
              </div>
            )}
          </div>

          {/* Auth Server B URL */}
          <div className="form-group" style={{ marginTop: '16px' }}>
            <label className="form-label">
              Auth Server B Token URL *
              {hasEnv('serverBTokenUrl') && <EnvBadge dirty={isDirty('serverBTokenUrl', serverB)} />}
            </label>
            <input
              type="url"
              className="form-input"
              value={serverB}
              onChange={(e) => setServerB(e.target.value)}
              placeholder="https://your-okta-domain.okta.com/oauth2/ausXXX/v1/token"
              required
            />
          </div>

          {/* Client credentials */}
          <div className="form-row" style={{ marginTop: '16px' }}>
            <div className="form-group">
              <label className="form-label">
                Gateway Client ID *
                {hasEnv('gwClientId') && <EnvBadge dirty={isDirty('gwClientId', clientId)} />}
              </label>
              <input
                type="text"
                className="form-input"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                placeholder="0oaXXXXXXXXXXXXXXXXX"
                required
                style={{ fontFamily: 'monospace' }}
              />
            </div>
            <div className="form-group">
              <label className="form-label">
                Gateway Client Secret *
                {hasEnv('gwClientSecret') && <EnvBadge dirty={isDirty('gwClientSecret', clientSecret)} />}
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showSecret ? 'text' : 'password'}
                  className="form-input"
                  value={clientSecret}
                  onChange={(e) => setClientSecret(e.target.value)}
                  placeholder="Client secret"
                  required
                  style={{ fontFamily: 'monospace', paddingRight: '80px' }}
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  style={{
                    position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px',
                    color: 'var(--text-secondary, #666)',
                  }}
                >
                  {showSecret ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>
          </div>

          {/* Audience + Scopes */}
          <div className="form-row" style={{ marginTop: '16px' }}>
            <div className="form-group">
              <label className="form-label">
                Expected Audience
                {hasEnv('expectedAud') && <EnvBadge dirty={isDirty('expectedAud', audience)} />}
              </label>
              <input
                type="text"
                className="form-input"
                value={audience}
                onChange={(e) => setAudience(e.target.value)}
                style={{ fontFamily: 'monospace' }}
              />
            </div>
            <div className="form-group">
              <label className="form-label">
                Scopes
                {hasEnv('scopes') && <EnvBadge dirty={isDirty('scopes', scopes)} />}
              </label>
              <input
                type="text"
                className="form-input"
                value={scopes}
                onChange={(e) => setScopes(e.target.value)}
                style={{ fontFamily: 'monospace' }}
              />
            </div>
          </div>

          <div style={{ marginTop: '20px', display: 'flex', gap: '8px' }}>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Running exchange…' : 'Run OBO Exchange'}
            </button>
            <button type="button" className="btn btn-outline" onClick={() => setResult(null)} disabled={loading}>
              Clear results
            </button>
          </div>
        </form>
      </div>

      {/* Results */}
      {result && (
        <div className="section" style={{ marginTop: '28px' }}>
          <h3 className="section-title">
            {result.success ? '✅ Exchange Succeeded' : '❌ Exchange Failed'}
            <span style={{ marginLeft: '12px', fontSize: '13px', fontWeight: '400', color: 'var(--text-secondary, #666)' }}>
              HTTP {result.httpStatus}
            </span>
          </h3>

          {/* Error block */}
          {!result.success && (
            <div className="alert alert-error" style={{ marginBottom: '16px' }}>
              <div><strong>{result.error}</strong></div>
              {result.errorDescription && <div style={{ marginTop: '4px' }}>{result.errorDescription}</div>}
              {diagnosisFor(result.error) && (
                <div style={{ marginTop: '8px', padding: '8px', background: 'rgba(255,255,255,0.15)', borderRadius: '6px' }}>
                  💡 <strong>Diagnosis:</strong> {diagnosisFor(result.error)}
                </div>
              )}
            </div>
          )}

          {/* Checks */}
          {result.success && oboClaims && (
            <div className="detail-card" style={{ marginBottom: '20px' }}>
              <h4 style={{ marginBottom: '12px', fontWeight: '600' }}>Verification Checks</h4>
              <Check
                pass={oboClaims.iss === expectedIssBase}
                label="Issuer (iss)"
                detail={oboClaims.iss}
              />
              <Check
                pass={oboClaims.aud === audience}
                label="Audience (aud)"
                detail={oboClaims.aud}
              />
              <Check
                pass={!!oboClaims.sub && oboClaims.sub !== clientId}
                label="User identity preserved (sub)"
                detail={oboClaims.sub === clientId
                  ? `⚠ sub = gateway client ID — user identity was lost`
                  : oboClaims.sub}
              />
              <Check
                pass={oboClaims.cid === clientId}
                label="Gateway app (cid)"
                detail={oboClaims.cid}
              />
              <Check
                pass={result.token?.issued_token_type === 'urn:ietf:params:oauth:token-type:access_token'}
                label="issued_token_type"
                detail={result.token?.issued_token_type}
              />
            </div>
          )}

          {/* Raw OBO token + copy */}
          {oboToken && (
            <div className="detail-card" style={{ marginBottom: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span className="balance-label">OBO Access Token</span>
                <CopyButton text={oboToken} label="Copy token" />
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: '11px', wordBreak: 'break-all', maxHeight: '80px', overflow: 'auto', color: 'var(--text-secondary, #666)' }}>
                {oboToken}
              </div>
              {result.token?.expires_in && (
                <div style={{ marginTop: '8px', fontSize: '13px', color: 'var(--text-secondary, #666)' }}>
                  Expires in: {result.token.expires_in}s · Scope: {result.token.scope}
                </div>
              )}
            </div>
          )}

          {/* Decoded OBO claims */}
          {result.success && oboClaims && (
            <>
              <h4 style={{ fontWeight: '600', marginBottom: '8px' }}>Decoded OBO Token Claims</h4>
              <ClaimsTable claims={oboClaims} />
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main DevTools page
// ═══════════════════════════════════════════════════════════════════════════════
const TABS = [
  { id: 'inspector', label: '🔍 Token Inspector' },
  { id: 'obo',       label: '🔄 OBO Verifier' },
];

export default function DevTools() {
  const [tab, setTab] = useState('inspector');

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Developer Tools</h1>
        <p className="page-subtitle">OAuth token inspection and OBO exchange verification</p>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: '0', borderBottom: '2px solid var(--border-color, #e5e7eb)', marginBottom: '24px' }}>
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              padding: '10px 20px',
              background: 'none',
              border: 'none',
              borderBottom: tab === t.id ? '2px solid var(--primary, #1a2744)' : '2px solid transparent',
              marginBottom: '-2px',
              fontWeight: tab === t.id ? '600' : '400',
              color: tab === t.id ? 'var(--primary, #1a2744)' : 'var(--text-secondary, #666)',
              cursor: 'pointer',
              fontSize: '14px',
              whiteSpace: 'nowrap',
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'inspector' && <TokenInspector />}
      {tab === 'obo'       && <OboVerifier />}
    </div>
  );
}
