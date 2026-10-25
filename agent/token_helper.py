"""
Okta PKCE token helper.

Opens the user's browser for Okta login, catches the callback on localhost,
exchanges the code for tokens, and returns the access token.
"""
import base64
import hashlib
import http.server
import os
import secrets
import threading
import urllib.parse
import webbrowser
import requests


def _generate_pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def get_access_token_via_pkce(
    issuer: str, client_id: str, scopes: list[str], port: int = 8765
) -> str:
    """
    Opens browser for Okta login, returns the access token.

    Args:
        issuer: Okta authorization server base URL (e.g. https://domain/oauth2/default)
        client_id: OIDC app client ID from Okta
        scopes: List of custom scopes to request (openid/profile/email are added automatically)
        port: Local port to listen on for the redirect callback

    Returns:
        The access token string
    """
    redirect_uri = f"http://localhost:{port}/callback"
    verifier, challenge = _generate_pkce()
    state = secrets.token_urlsafe(16)

    scope_str = " ".join(["openid", "profile", "email"] + scopes)

    auth_url = (
        f"{issuer}/v1/authorize"
        f"?client_id={client_id}"
        f"&response_type=code"
        f"&scope={urllib.parse.quote(scope_str)}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        f"&state={state}"
        f"&code_challenge={challenge}"
        f"&code_challenge_method=S256"
    )

    code_holder = [None]
    error_holder = [None]
    done = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if "code" in params:
                code_holder[0] = params["code"][0]
            elif "error" in params:
                error_holder[0] = params.get("error_description", ["Unknown error"])[0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h2>Authentication complete. You can close this tab.</h2></body></html>"
            )
            done.set()

        def log_message(self, *args):
            pass  # suppress server logs

    server = http.server.HTTPServer(("localhost", port), CallbackHandler)
    thread = threading.Thread(target=server.handle_request)
    thread.start()

    print(f"\nOpening browser for Okta login...")
    webbrowser.open(auth_url)

    done.wait(timeout=120)
    server.server_close()

    if error_holder[0]:
        raise RuntimeError(f"Okta login failed: {error_holder[0]}")
    if not code_holder[0]:
        raise RuntimeError("No authorization code received (timeout)")

    # Exchange code for tokens
    token_resp = requests.post(
        f"{issuer}/v1/token",
        data={
            "grant_type": "authorization_code",
            "code": code_holder[0],
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": verifier,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    token_resp.raise_for_status()
    tokens = token_resp.json()

    if "access_token" not in tokens:
        raise RuntimeError(f"No access token in response: {tokens}")

    return tokens["access_token"]
