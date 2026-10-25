#!/usr/bin/env bash
# verify-obo.sh — Manually verify the OBO token exchange between Auth Server A and Auth Server B.
#
# Usage:
#   ./scripts/verify-obo.sh
#
# The script reads from scripts/.env (copy scripts/.env.example and fill it in).
# Every value can also be set as a shell environment variable before running.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

# ── Load .env if present ──────────────────────────────────────────────────────
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a
fi

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

pass() { echo -e "  ${GREEN}✔${RESET}  $1"; }
fail() { echo -e "  ${RED}✗${RESET}  $1"; FAILURES=$((FAILURES+1)); }
info() { echo -e "  ${CYAN}→${RESET}  $1"; }

# ── Require values ────────────────────────────────────────────────────────────
require_var() {
  local name=$1 val=${!1:-}
  if [[ -z "$val" ]]; then
    echo -e "${RED}ERROR:${RESET} \$$name is not set. Set it in scripts/.env or export it before running."
    exit 1
  fi
}

require_var SERVER_B_TOKEN_URL   # e.g. https://demo-arbind-lochan-mishra.okta.com/oauth2/{serverB-id}/v1/token
require_var GW_CLIENT_ID         # PointGuardAI Gateway app client ID
require_var GW_CLIENT_SECRET     # PointGuardAI Gateway app client secret
require_var USER_TOKEN           # An Auth Server A access token (from frontend login or DevTools)

EXPECTED_AUD="${EXPECTED_AUD:-api://banking-mcp}"
SCOPES="${SCOPES:-accounts:read accounts:balance:read accounts:transactions:read payments:read}"

FAILURES=0

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  SecureBank — OBO Exchange Verification${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
echo ""
info "Auth Server B token URL: $SERVER_B_TOKEN_URL"
info "Scopes requested: $SCOPES"
echo ""

# ── Perform the OBO exchange ──────────────────────────────────────────────────
echo -e "${BOLD}Step 1: Sending OBO token exchange request…${RESET}"

HTTP_RESPONSE=$(curl -s -w "\n__HTTP_STATUS__%{http_code}" -X POST "$SERVER_B_TOKEN_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "subject_token=$USER_TOKEN" \
  --data-urlencode "client_id=$GW_CLIENT_ID" \
  --data-urlencode "client_secret=$GW_CLIENT_SECRET" \
  --data-urlencode "audience=$EXPECTED_AUD" \
  --data-urlencode "scope=$SCOPES")

HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed '$d')
HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tail -n1 | grep -o '[0-9]*$')

if [[ "$HTTP_STATUS" != "200" ]]; then
  echo ""
  echo -e "${RED}ERROR: HTTP $HTTP_STATUS${RESET}"
  echo "$HTTP_BODY" | python3 -m json.tool 2>/dev/null || echo "$HTTP_BODY"
  echo ""
  echo -e "${YELLOW}Common causes:${RESET}"
  echo "  • unauthorized_client  → NHI subscription not active, or Token Exchange grant not enabled on the app"
  echo "  • invalid_token        → USER_TOKEN is expired or from the wrong issuer (must be Auth Server A)"
  echo "  • access_denied        → No access policy on Server B for the PointGuardAI Gateway app"
  exit 1
fi

echo ""
pass "HTTP 200 — exchange succeeded"
echo ""

# ── Extract the access token ──────────────────────────────────────────────────
OBO_TOKEN=$(echo "$HTTP_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || true)

if [[ -z "$OBO_TOKEN" ]]; then
  echo -e "${RED}ERROR: Could not parse access_token from response.${RESET}"
  echo "$HTTP_BODY"
  exit 1
fi

ISSUED_TYPE=$(echo "$HTTP_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('issued_token_type',''))" 2>/dev/null || true)
EXPIRES_IN=$(echo "$HTTP_BODY"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('expires_in',''))" 2>/dev/null || true)
SCOPE_OUT=$(echo "$HTTP_BODY"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('scope',''))" 2>/dev/null || true)

# ── Decode the JWT payload (no signature verification — that is Okta's job) ──
PAYLOAD_B64=$(echo "$OBO_TOKEN" | cut -d'.' -f2)
# Base64url → base64 padding
PADDED=$(echo "$PAYLOAD_B64" | tr '_-' '/+' | awk '{l=length($0)%4; if(l==2) print $0"=="; else if(l==3) print $0"="; else print $0}')
CLAIMS=$(echo "$PADDED" | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "{}")

get_claim() {
  echo "$CLAIMS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1','<missing>'))" 2>/dev/null || echo "<error>"
}

ISS=$(get_claim iss)
AUD=$(get_claim aud)
SUB=$(get_claim sub)
CID=$(get_claim cid)
SCP=$(get_claim scp)

# ── Verify claims ─────────────────────────────────────────────────────────────
echo -e "${BOLD}Step 2: Verifying JWT claims…${RESET}"
echo ""

# iss — must come from Auth Server B (not A)
SERVER_B_HOST=$(echo "$SERVER_B_TOKEN_URL" | sed 's|/v1/token||')
if [[ "$ISS" == "$SERVER_B_HOST" ]]; then
  pass "iss = $ISS"
else
  fail "iss mismatch — got '$ISS', expected issuer matching '$SERVER_B_HOST'"
fi

# aud — must be the MCP audience
if [[ "$AUD" == "$EXPECTED_AUD" ]]; then
  pass "aud = $AUD"
else
  fail "aud mismatch — got '$AUD', expected '$EXPECTED_AUD'"
fi

# sub — must be a user ID (not the gateway client ID)
if [[ "$SUB" == "$GW_CLIENT_ID" ]]; then
  fail "sub = $SUB  ← this is the GATEWAY client ID, not a user. Trust or policy is misconfigured."
elif [[ -n "$SUB" && "$SUB" != "<missing>" ]]; then
  pass "sub = $SUB  (user identity preserved)"
else
  fail "sub is missing"
fi

# cid — should be the gateway client ID
if [[ "$CID" == "$GW_CLIENT_ID" ]]; then
  pass "cid = $CID  (gateway app)"
else
  info "cid = $CID  (expected $GW_CLIENT_ID)"
fi

# issued_token_type
if [[ "$ISSUED_TYPE" == "urn:ietf:params:oauth:token-type:access_token" ]]; then
  pass "issued_token_type = access_token"
else
  info "issued_token_type = $ISSUED_TYPE"
fi

echo ""
echo -e "${BOLD}Step 3: Token details${RESET}"
echo ""
info "expires_in : ${EXPIRES_IN}s"
info "scope      : $SCOPE_OUT"
echo ""
echo -e "${BOLD}Full decoded payload:${RESET}"
echo "$CLAIMS"
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
if [[ $FAILURES -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}  ALL CHECKS PASSED — OBO exchange is working correctly.${RESET}"
else
  echo -e "${RED}${BOLD}  $FAILURES CHECK(S) FAILED — review the output above.${RESET}"
fi
echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
echo ""

exit $FAILURES
