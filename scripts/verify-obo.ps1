# verify-obo.ps1 - Manually verify the OBO token exchange between Auth Server A and Auth Server B.
#
# Usage (from the project root):
#   .\scripts\verify-obo.ps1
#
# The script reads from scripts\.env (copy scripts\.env.example and fill it in).
# Every value can also be set as a PowerShell environment variable before running:
#   $env:USER_TOKEN = "eyJ..."
#   .\scripts\verify-obo.ps1

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile   = Join-Path $ScriptDir '.env'

# Load .env if present
if (Test-Path $EnvFile) {
  Get-Content $EnvFile | ForEach-Object {
    if ($_ -match '^\s*([^#=\s][^=]*?)\s*=\s*(.*?)\s*$') {
      $name  = $Matches[1]
      $value = $Matches[2] -replace '^["'']|["'']$'
      # Always override: .env file wins over any inherited machine/user env vars.
      [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
  }
}

# Helper to require env vars
function Require-EnvVar([string]$Name) {
  $val = [System.Environment]::GetEnvironmentVariable($Name)
  if (-not $val) {
    $hint = '$env:' + $Name + " = 'value'"
    Write-Host "ERROR: $Name is not set. Add it to scripts\.env or run: $hint" -ForegroundColor Red
    exit 1
  }
  return $val
}

$SERVER_B_TOKEN_URL = Require-EnvVar 'SERVER_B_TOKEN_URL'
$GW_CLIENT_ID       = Require-EnvVar 'GW_CLIENT_ID'
$GW_CLIENT_SECRET   = Require-EnvVar 'GW_CLIENT_SECRET'
$USER_TOKEN         = Require-EnvVar 'USER_TOKEN'
$EXPECTED_AUD       = if ($env:EXPECTED_AUD) { $env:EXPECTED_AUD } else { 'api://banking-mcp' }
$SCOPES             = if ($env:SCOPES)       { $env:SCOPES }       else { 'accounts:read accounts:balance:read accounts:transactions:read payments:read' }

$failures = 0

function Write-Pass([string]$msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Write-Fail([string]$msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red;  $script:failures++ }
function Write-Info([string]$msg) { Write-Host "  [INFO] $msg" -ForegroundColor Cyan }
function Write-Warn([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }

# Decode a JWT payload without verifying the signature
function Decode-JwtPayload([string]$token) {
  $parts = $token -split '\.'
  if ($parts.Count -lt 2) { return $null }
  $b64 = $parts[1] -replace '-','+' -replace '_','/'
  switch ($b64.Length % 4) {
    2 { $b64 += '==' }
    3 { $b64 += '=' }
  }
  try {
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64)) | ConvertFrom-Json
  } catch { return $null }
}

Write-Host ""
Write-Host "===========================================================" -ForegroundColor White
Write-Host "  SecureBank -- OBO Exchange Verification" -ForegroundColor White
Write-Host "===========================================================" -ForegroundColor White
Write-Host ""
Write-Info "Auth Server B token URL : $SERVER_B_TOKEN_URL"
Write-Info "Expected audience       : $EXPECTED_AUD"
Write-Info "Scopes requested        : $SCOPES"
Write-Host ""

# Pre-flight: check USER_TOKEN expiry
Write-Host "Pre-flight: Checking USER_TOKEN..." -ForegroundColor White
$userClaims = Decode-JwtPayload $USER_TOKEN
if ($userClaims) {
  $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $exp      = [long]$userClaims.exp
  $diff     = $exp - $nowEpoch
  $iss      = $userClaims.iss
  $sub      = $userClaims.sub
  $aud      = $userClaims.aud

  Write-Info "sub : $sub"
  Write-Info "iss : $iss"
  Write-Info "aud : $aud"

  if ($diff -le 0) {
    Write-Warn "USER_TOKEN EXPIRED $([Math]::Abs([int]($diff/60))) min ago."
    Write-Warn "Get a fresh token: log into the banking frontend, copy the access_token"
    Write-Warn "from browser DevTools > Application > Session Storage > okta-token-storage"
    Write-Warn "then update USER_TOKEN in scripts\.env and re-run."
    Write-Host ""
    exit 1
  } elseif ($diff -lt 300) {
    Write-Warn "USER_TOKEN expires in $([int]($diff/60)) min -- continue but get a fresh one soon."
  } else {
    Write-Pass "USER_TOKEN valid for $([int]($diff/60)) more minutes"
  }
} else {
  Write-Warn "Could not decode USER_TOKEN -- proceeding anyway."
}
Write-Host ""

# Build POST body
# Credentials go in Authorization: Basic header (required by Okta Token Exchange).
# Putting client_id/client_secret in the body causes invalid_client for this grant type.
function UrlEncode([string]$s) { [System.Uri]::EscapeDataString($s) }

$credBytes   = [System.Text.Encoding]::UTF8.GetBytes("${GW_CLIENT_ID}:${GW_CLIENT_SECRET}")
$basicHeader = 'Basic ' + [System.Convert]::ToBase64String($credBytes)

# Credential diagnostics -- shows the values actually being sent
Write-Host "Credential check:" -ForegroundColor White
$idPreview = if ($GW_CLIENT_ID.Length -gt 8) { $GW_CLIENT_ID.Substring(0,8) + '...' + $GW_CLIENT_ID.Substring($GW_CLIENT_ID.Length-4) } else { $GW_CLIENT_ID }
Write-Info "GW_CLIENT_ID     : $idPreview  (length $($GW_CLIENT_ID.Length))"
Write-Info "GW_CLIENT_SECRET : *** (length $($GW_CLIENT_SECRET.Length) chars)"
if ($GW_CLIENT_ID.Length -ne 20) {
  Write-Warn "GW_CLIENT_ID is $($GW_CLIENT_ID.Length) chars; Okta API Services client IDs are normally 20 chars (e.g. 0oaXXXXXXXXXXXXXXXX)."
}
if ($GW_CLIENT_SECRET.Length -lt 20) {
  Write-Warn "GW_CLIENT_SECRET looks short ($($GW_CLIENT_SECRET.Length) chars) -- check for truncation in scripts\.env."
}

# Credential pre-flight: try client_credentials against Server B to test credentials alone.
# A valid response OR an access_denied / unauthorized_client means credentials are correct.
# An invalid_client means the client ID / secret is genuinely wrong.
Write-Host ""
Write-Host "Credential pre-flight: testing client ID/secret with client_credentials grant..." -ForegroundColor White
$ccBody  = "grant_type=client_credentials"
$ccBody += "&scope=$(UrlEncode $SCOPES)"
try {
  $ccWr = Invoke-WebRequest `
    -Method Post `
    -Uri $SERVER_B_TOKEN_URL `
    -ContentType 'application/x-www-form-urlencoded' `
    -Headers @{ Authorization = $basicHeader } `
    -Body $ccBody `
    -UseBasicParsing
  Write-Pass "client_credentials succeeded (HTTP $($ccWr.StatusCode)) -- credentials are valid."
} catch {
  $ccCode = $_.Exception.Response.StatusCode.value__
  try {
    $ccStream = $_.Exception.Response.GetResponseStream()
    $ccReader = [System.IO.StreamReader]::new($ccStream)
    $ccRaw = $ccReader.ReadToEnd(); $ccReader.Dispose()
    $ccErr = $ccRaw | ConvertFrom-Json
    $ccCode2 = if ($ccErr.error) { $ccErr.error } else { $ccErr.errorCode }
    if ($ccCode2 -eq 'invalid_client') {
      Write-Fail "client_credentials also returns invalid_client (HTTP $ccCode)."
      Write-Warn "  -> The GW_CLIENT_ID or GW_CLIENT_SECRET in scripts\.env does NOT match Okta."
      Write-Warn "  -> In Okta: Applications > PointGuardAI Gateway > copy Client ID exactly."
      Write-Warn "  -> Click 'Edit' in Client Credentials > generate a NEW client secret > paste it."
      Write-Warn "  -> Make sure scripts\.env has no leading/trailing spaces around the values."
      Write-Host ""
      Write-Host "  Current GW_CLIENT_ID in use: $GW_CLIENT_ID" -ForegroundColor Yellow
      Write-Host "  To generate a raw Basic header for curl, run:" -ForegroundColor Yellow
      $b64check = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("${GW_CLIENT_ID}:YOUR_SECRET"))
      Write-Host "    curl -s -X POST '$SERVER_B_TOKEN_URL' -H 'Authorization: Basic $b64check' -d 'grant_type=client_credentials'" -ForegroundColor DarkYellow
      exit 1
    } else {
      Write-Pass "client_credentials returned $ccCode2 (HTTP $ccCode) -- credentials are accepted by Okta (no matching policy is expected)."
    }
  } catch {
    Write-Info "client_credentials pre-flight inconclusive (HTTP $ccCode)."
  }
}
Write-Host ""

$body  = "grant_type=$(UrlEncode 'urn:ietf:params:oauth:grant-type:token-exchange')"
$body += "&subject_token_type=$(UrlEncode 'urn:ietf:params:oauth:token-type:access_token')"
$body += "&requested_token_type=$(UrlEncode 'urn:ietf:params:oauth:token-type:access_token')"
$body += "&subject_token=$(UrlEncode $USER_TOKEN)"
$body += "&audience=$(UrlEncode $EXPECTED_AUD)"
$body += "&scope=$(UrlEncode $SCOPES)"

# Send the request -- use Invoke-WebRequest so we always get the raw body
Write-Host "Step 1: Sending OBO token exchange request..." -ForegroundColor White
Write-Host ""

$rawBody  = $null
$httpCode = 0

try {
  $wr = Invoke-WebRequest `
    -Method Post `
    -Uri $SERVER_B_TOKEN_URL `
    -ContentType 'application/x-www-form-urlencoded' `
    -Headers @{ Authorization = $basicHeader } `
    -Body $body `
    -UseBasicParsing
  $httpCode = $wr.StatusCode
  $rawBody  = $wr.Content
} catch {
  $httpCode = $_.Exception.Response.StatusCode.value__
  # Read raw bytes from the error stream
  try {
    $stream = $_.Exception.Response.GetResponseStream()
    $reader = [System.IO.StreamReader]::new($stream)
    $rawBody = $reader.ReadToEnd()
    $reader.Dispose()
  } catch {
    $rawBody = "(could not read response body: $($_.Exception.Message))"
  }
}

if ($httpCode -ne 200) {
  Write-Host "ERROR: HTTP $httpCode" -ForegroundColor Red
  Write-Host ""
  Write-Host "Raw Okta response body:" -ForegroundColor Yellow
  Write-Host $rawBody -ForegroundColor Yellow
  Write-Host ""

  # Try to parse -- handles both OAuth standard AND Okta's own error format
  try {
    $errObj = $rawBody | ConvertFrom-Json

    # Okta uses errorCode/errorSummary; OAuth uses error/error_description
    $errCode = if ($errObj.error)     { $errObj.error }        else { $errObj.errorCode }
    $errDesc = if ($errObj.error_description) { $errObj.error_description } else { $errObj.errorSummary }

    if ($errCode) {
      Write-Host "  error   : $errCode" -ForegroundColor Red
      Write-Host "  message : $errDesc" -ForegroundColor Red
      Write-Host ""

      switch ($errCode) {
        'invalid_client' {
          Write-Host "  DIAGNOSIS: GW_CLIENT_ID or GW_CLIENT_SECRET is wrong." -ForegroundColor Yellow
          Write-Host "    -> Open Okta > Applications > PointGuardAI Gateway" -ForegroundColor Yellow
          Write-Host "    -> Copy the Client ID exactly and paste into scripts\.env as GW_CLIENT_ID" -ForegroundColor Yellow
          Write-Host "    -> Reveal the client secret and paste as GW_CLIENT_SECRET" -ForegroundColor Yellow
        }
        'unauthorized_client' {
          Write-Host "  DIAGNOSIS: Token Exchange grant not enabled on the app, or NHI subscription inactive." -ForegroundColor Yellow
          Write-Host "    -> Okta > Applications > PointGuardAI Gateway > General Settings > Advanced > tick Token Exchange" -ForegroundColor Yellow
        }
        'invalid_token' {
          Write-Host "  DIAGNOSIS: USER_TOKEN is invalid or expired. Get a fresh one from the frontend." -ForegroundColor Yellow
        }
        'access_denied' {
          Write-Host "  DIAGNOSIS: No matching access policy rule on Server B for this app/scopes." -ForegroundColor Yellow
        }
        'invalid_request' {
          Write-Host "  DIAGNOSIS: Malformed request -- check SERVER_B_TOKEN_URL points to Auth Server B." -ForegroundColor Yellow
        }
        'invalid_grant' {
          Write-Host "  DIAGNOSIS: Subject token rejected. Common causes:" -ForegroundColor Yellow
          Write-Host "    1. Token expired (check Pre-flight above)" -ForegroundColor Yellow
          Write-Host "    2. Server B Trusted Servers does not include Server A" -ForegroundColor Yellow
          Write-Host "       -> Okta > Security > API > SecureBank-MCPExchange > Trusted Servers > Add Server A" -ForegroundColor Yellow
        }
      }
    }
  } catch {}

  Write-Host ""
  Write-Host "General checklist:" -ForegroundColor White
  Write-Host "  1. USER_TOKEN is a FRESH Auth Server A token (not expired)"
  Write-Host "  2. SERVER_B_TOKEN_URL is Auth Server B's /v1/token endpoint (not Server A)"
  Write-Host "  3. GW_CLIENT_ID / GW_CLIENT_SECRET are from the PointGuardAI Gateway API Services app"
  Write-Host "  4. Server B has Server A in its Trusted Servers list (Okta > Security > API > Server B > Trusted Servers)"
  Write-Host "  5. Token Exchange grant is enabled on the PointGuardAI Gateway app (General Settings > Advanced)"
  Write-Host "  6. Access policy on Server B is assigned to the PointGuardAI Gateway app"
  exit 1
}

Write-Pass "HTTP 200 -- exchange succeeded"
Write-Host ""

# Decode the OBO token
$response = $rawBody | ConvertFrom-Json
$jwtParts = $response.access_token -split '\.'
if ($jwtParts.Count -lt 2) {
  Write-Host "ERROR: Response token does not look like a JWT." -ForegroundColor Red
  exit 1
}

$claims = Decode-JwtPayload $response.access_token

# Verify claims
Write-Host "Step 2: Verifying JWT claims..." -ForegroundColor White
Write-Host ""

$serverBBase = $SERVER_B_TOKEN_URL -replace '/v1/token$'

if ($claims.iss -eq $serverBBase) {
  Write-Pass "iss = $($claims.iss)"
} else {
  Write-Fail "iss mismatch -- got '$($claims.iss)', expected '$serverBBase'"
}

if ($claims.aud -eq $EXPECTED_AUD) {
  Write-Pass "aud = $($claims.aud)"
} else {
  Write-Fail "aud mismatch -- got '$($claims.aud)', expected '$EXPECTED_AUD'"
}

if ($claims.sub -eq $GW_CLIENT_ID) {
  Write-Fail "sub = $($claims.sub)  <- this is the GATEWAY client ID, not a user. Trust or policy is misconfigured."
} elseif ($claims.sub) {
  Write-Pass "sub = $($claims.sub)  (user identity preserved)"
} else {
  Write-Fail "sub is missing from the token"
}

if ($claims.cid -eq $GW_CLIENT_ID) {
  Write-Pass "cid = $($claims.cid)  (gateway app)"
} else {
  Write-Info "cid = $($claims.cid)  (expected $GW_CLIENT_ID)"
}

$issuedType = $response.issued_token_type
if ($issuedType -eq 'urn:ietf:params:oauth:token-type:access_token') {
  Write-Pass "issued_token_type = access_token"
} else {
  Write-Info "issued_token_type = $issuedType"
}

# Token details
Write-Host ""
Write-Host "Step 3: Token details" -ForegroundColor White
Write-Host ""
Write-Info "expires_in : $($response.expires_in)s"
Write-Info "scope      : $($response.scope)"
Write-Host ""
Write-Host "Full decoded payload:" -ForegroundColor White
$claims | ConvertTo-Json -Depth 5
Write-Host ""

# Summary
Write-Host "===========================================================" -ForegroundColor White
if ($failures -eq 0) {
  Write-Host "  ALL CHECKS PASSED -- OBO exchange is working correctly." -ForegroundColor Green
} else {
  Write-Host "  $failures CHECK(S) FAILED -- review the output above." -ForegroundColor Red
}
Write-Host "===========================================================" -ForegroundColor White
Write-Host ""

exit $failures
