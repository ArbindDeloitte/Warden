'use strict';

const A2A_VERSION = '1.0';

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

// Validates an A2A 1.0 Agent Card and extracts what Warden needs.
function parseCard(card) {
  if (!card || typeof card !== 'object') throw new Error('Agent Card must be a JSON object');
  if (!card.supportedInterfaces && card.url) {
    throw new Error('This looks like a pre-1.0 (0.3) Agent Card. Only A2A 1.0 cards (supportedInterfaces) are supported.');
  }
  if (!card.name) throw new Error('Agent Card is missing "name"');
  const ifaces = Array.isArray(card.supportedInterfaces) ? card.supportedInterfaces : [];
  const rpc = ifaces.find(i => String(i.protocolBinding || '').toUpperCase() === 'JSONRPC' && i.url);
  if (!rpc) throw new Error('Agent Card has no JSONRPC entry in supportedInterfaces');
  const skills = Array.isArray(card.skills) ? card.skills : [];
  return {
    name: String(card.name),
    description: String(card.description || ''),
    endpoint_url: rpc.url,
    skills: skills.map(s => ({ id: s.id, name: s.name, description: s.description })),
  };
}

function publicBase(req) {
  if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/$/, '');
  return `${req.protocol}://${req.get('host')}`;
}

// The card Warden serves: same identity/skills, but the only interface is Warden itself.
// Original signatures/security declarations are dropped because the card is modified.
function buildGatewayCard(row, vsId, base) {
  const orig = JSON.parse(row.card_json);
  const card = { ...orig };
  delete card.signatures;
  delete card.securitySchemes;
  delete card.securityRequirements;
  card.supportedInterfaces = [{
    url: `${base}/a2a/${vsId}/${row.id}`,
    protocolBinding: 'JSONRPC',
    protocolVersion: A2A_VERSION,
  }];
  // Advertise only what the gateway can actually serve: it does not implement push notifications or
  // GetExtendedAgentCard, and it does not forward A2A-Extensions, so a target's claims for those
  // would make clients attempt calls that fail.
  if (card.capabilities) {
    const { extensions, ...caps } = card.capabilities;
    card.capabilities = { ...caps, pushNotifications: false, extendedAgentCard: false };
  }
  return card;
}

module.exports = { A2A_VERSION, fetchCard, parseCard, publicBase, buildGatewayCard };
