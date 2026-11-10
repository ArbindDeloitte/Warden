'use strict';

// A2A versions Warden can gateway. Each registered agent speaks exactly one of them.
const SUPPORTED_VERSIONS = ['1.0', '0.3'];
const A2A_VERSION = '1.0'; // the default / latest

async function fetchCard(url, timeoutMs = 8000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { headers: { Accept: 'application/json' }, signal: ctl.signal });
    if (!r.ok) throw new Error(`Card fetch returned HTTP ${r.status}`);
    return await r.json();
  } catch (e) {
    throw new Error(e.name === 'AbortError' ? 'Card fetch timed out' : `Card fetch failed: ${e.message}`);
  } finally {
    clearTimeout(t);
  }
}

/**
 * Which A2A version an Agent Card is written for, or null if it is neither.
 *   1.0: `supportedInterfaces` array.
 *   0.3: a top-level `url` with `protocolVersion` 0.3.x (a card that has a `url` but no
 *        `protocolVersion` is treated as 0.3, since older sloppy 0.3 cards omit it).
 * Pre-0.3 cards (0.2.x and earlier use different method names) are not supported.
 */
function detectVersion(card) {
  if (!card || typeof card !== 'object') return null;
  if (Array.isArray(card.supportedInterfaces)) return '1.0';
  if (card.url || card.protocolVersion) {
    if (card.protocolVersion === undefined || /^0\.3(\.|$)/.test(String(card.protocolVersion))) return '0.3';
  }
  return null;
}

/**
 * Validates an Agent Card and extracts what Warden needs.
 * `requested` is 'auto' (use what the card says), '1.0' or '0.3'. An explicit choice must agree with the card.
 */
function parseCard(card, requested = 'auto') {
  if (!card || typeof card !== 'object') throw new Error('Agent Card must be a JSON object');
  if (requested !== 'auto' && !SUPPORTED_VERSIONS.includes(requested)) {
    throw new Error(`protocol_version must be "auto", ${SUPPORTED_VERSIONS.map(v => `"${v}"`).join(' or ')}`);
  }
  const detected = detectVersion(card);
  const version = requested === 'auto' ? detected : requested;
  if (!version) {
    throw new Error('Unrecognised Agent Card: expected A2A 1.0 (a "supportedInterfaces" list) or A2A 0.3 (a "url" with protocolVersion 0.3.x). Earlier versions are not supported.');
  }
  if (detected && detected !== version) {
    throw new Error(`This Agent Card is written for A2A ${detected}, but A2A ${version} was selected. Choose A2A ${detected} or Auto-detect.`);
  }
  if (!card.name) throw new Error('Agent Card is missing "name"');
  const skills = Array.isArray(card.skills) ? card.skills : [];

  let endpoint;
  if (version === '1.0') {
    const ifaces = Array.isArray(card.supportedInterfaces) ? card.supportedInterfaces : [];
    const rpc = ifaces.find(i => String(i.protocolBinding || '').toUpperCase() === 'JSONRPC' && i.url);
    if (!rpc) throw new Error('Agent Card has no JSONRPC entry in supportedInterfaces');
    endpoint = rpc.url;
  } else {
    // 0.3: `url` is the preferred transport's endpoint; other transports are listed in additionalInterfaces.
    const preferred = String(card.preferredTransport || 'JSONRPC').toUpperCase();
    endpoint = preferred === 'JSONRPC' ? card.url : null;
    if (!endpoint) {
      const alt = (Array.isArray(card.additionalInterfaces) ? card.additionalInterfaces : [])
        .find(i => String(i.transport || '').toUpperCase() === 'JSONRPC' && i.url);
      endpoint = alt?.url;
    }
    if (!endpoint) throw new Error('Agent Card has no JSON-RPC interface (preferredTransport / additionalInterfaces). Warden gateways the JSON-RPC transport only.');
  }
  return {
    version,
    name: String(card.name),
    description: String(card.description || ''),
    endpoint_url: endpoint,
    skills: skills.map(s => ({ id: s.id, name: s.name, description: s.description })),
  };
}

function publicBase(req) {
  if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/$/, '');
  return `${req.protocol}://${req.get('host')}`;
}

// The card Warden serves: same identity/skills, but the only interface is Warden itself, in the SAME
// protocol version as the registered agent. Original signatures/security declarations are dropped because
// the card is modified.
function buildGatewayCard(row, vsId, base) {
  const orig = JSON.parse(row.card_json);
  const card = { ...orig };
  delete card.signatures;
  delete card.securitySchemes;
  const url = `${base}/a2a/${vsId}/${row.id}`;

  if (row.protocol_version === '0.3') {
    delete card.security;
    delete card.additionalInterfaces;
    card.protocolVersion = orig.protocolVersion || '0.3.0';
    card.url = url;
    card.preferredTransport = 'JSONRPC';
    card.supportsAuthenticatedExtendedCard = false;
    if (card.capabilities) {
      const { extensions, ...caps } = card.capabilities;
      card.capabilities = { ...caps, pushNotifications: false };
    }
    return card;
  }

  delete card.securityRequirements;
  card.supportedInterfaces = [{ url, protocolBinding: 'JSONRPC', protocolVersion: A2A_VERSION }];
  // Advertise only what the gateway can actually serve: it does not implement push notifications or
  // GetExtendedAgentCard, and it does not forward A2A-Extensions, so a target's claims for those
  // would make clients attempt calls that fail.
  if (card.capabilities) {
    const { extensions, ...caps } = card.capabilities;
    card.capabilities = { ...caps, pushNotifications: false, extendedAgentCard: false };
  }
  return card;
}

module.exports = { SUPPORTED_VERSIONS, A2A_VERSION, fetchCard, detectVersion, parseCard, publicBase, buildGatewayCard };
