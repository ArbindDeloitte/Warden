"""
Client for the Warden Credential Vault, so an agent never needs credentials in code or .env.

The agent holds exactly one secret -- its Warden agent token. Everything else is requested at
runtime and only if a Warden vault policy permits this agent (or one of its groups):

  get()   runtime checkout; returns the value and caches it only until its lease expires
  sign()  Warden signs a JWT (e.g. an OAuth client assertion) with a stored private key; the key
          never leaves the vault
  (brokered mode needs no client code at all: put "vault://secret-name" as a whole string in tool
   arguments and Warden injects the value server-side, so the agent never sees it)

Secret values are kept in memory only, are never logged, and are hidden from repr().
"""
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

import requests

_EXPIRY_SKEW_SECONDS = 5  # drop a cached value slightly before its lease actually ends


class VaultError(Exception):
    """Raised for denial, auth failure, or any gateway error. Never contains a secret value."""

    def __init__(self, message: str, http_status: Optional[int] = None, code: Optional[str] = None):
        super().__init__(message)
        self.http_status = http_status
        self.code = code


class Secret:
    """A checked-out secret. str()/repr() deliberately never show the value."""

    def __init__(self, data: dict):
        self.name: str = data["secret"]
        self.type: str = data.get("type", "generic")
        self.metadata: dict = data.get("metadata") or {}
        self.version: int = data.get("version", 1)
        self.lease_id: str = data["lease_id"]
        self.expires_at: str = data["expires_at"]
        self._value: str = data["value"]
        self._expires_epoch = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00")).timestamp()
        # Stop serving from cache a little early, but never more than 20% of the lease, so short leases stay cacheable.
        self._skew = min(_EXPIRY_SKEW_SECONDS, 0.2 * float(data.get("ttl_seconds") or 0))

    @property
    def value(self) -> str:
        return self._value

    def is_fresh(self) -> bool:
        return time.time() < self._expires_epoch - self._skew

    def __repr__(self) -> str:
        return f"Secret(name={self.name!r}, type={self.type!r}, version={self.version}, expires_at={self.expires_at!r}, value=<hidden>)"

    __str__ = __repr__


class VaultClient:
    def __init__(self, warden_url: str, agent_token: str, vs_id: Optional[str] = None, api_key: Optional[str] = None,
                 timeout: float = 10.0):
        self.base = f"{warden_url.rstrip('/')}/api/vault"
        self.vs_id = vs_id  # scopes requests to a virtual server (VS-scoped policies only match when it is named)
        self.timeout = timeout
        self._headers = {"Content-Type": "application/json", "X-Agent-Token": agent_token}
        if api_key:
            self._headers["X-API-Key"] = api_key
        self._cache: dict[str, Secret] = {}
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"VaultClient(base={self.base!r}, vs_id={self.vs_id!r})"

    def _post(self, path: str, body: dict) -> dict:
        if self.vs_id:
            body = {**body, "virtual_server_id": self.vs_id}
        try:
            r = requests.post(f"{self.base}/{path}", json=body, headers=self._headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise VaultError(f"Could not reach the Warden vault: {exc}")
        if r.status_code >= 400:
            try:
                err = r.json()
            except ValueError:
                err = {}
            raise VaultError(err.get("error") or f"Vault request failed (HTTP {r.status_code})", r.status_code, err.get("code"))
        return r.json()

    def get(self, name: str, ttl_seconds: Optional[int] = None, refresh: bool = False) -> Secret:
        """Check out a secret. Served from memory until its lease expires; pass refresh=True to force a new checkout."""
        with self._lock:
            cached = self._cache.get(name)
            if cached and cached.is_fresh() and not refresh:
                return cached
        body: dict[str, Any] = {"secret": name}
        if ttl_seconds:
            body["ttl_seconds"] = int(ttl_seconds)
        secret = Secret(self._post("checkout", body))
        with self._lock:
            self._cache[name] = secret
        return secret

    def sign(self, name: str, claims: Optional[dict] = None, algorithm: str = "RS256",
             expires_in: Optional[int] = None) -> str:
        """Have Warden sign a JWT with the stored private key `name`. Returns only the JWT."""
        body: dict[str, Any] = {"secret": name, "claims": claims or {}, "algorithm": algorithm}
        if expires_in:
            body["expires_in"] = int(expires_in)
        return self._post("sign", body)["token"]

    def is_valid(self, secret: Secret) -> bool:
        """Ask Warden whether a lease is still good (not revoked, expired, or superseded by a rotation)."""
        try:
            r = requests.get(f"{self.base}/validate/{secret.lease_id}", headers=self._headers, timeout=self.timeout)
            return r.status_code == 200 and bool(r.json().get("valid"))
        except (requests.RequestException, ValueError):
            return False

    def invalidate(self, name: Optional[str] = None) -> None:
        """Forget cached values (one secret, or all). Call after an upstream 401/403 to force a fresh checkout."""
        with self._lock:
            if name is None:
                self._cache.clear()
            else:
                self._cache.pop(name, None)


def client_from_env() -> VaultClient:
    """Builds a client from WARDEN_URL (default http://localhost:3003), WARDEN_AGENT_TOKEN, and optionally
    PG_VIRTUAL_SERVER_ID / WARDEN_API_KEY."""
    import os
    from dotenv import load_dotenv

    load_dotenv()
    token = os.getenv("WARDEN_AGENT_TOKEN")
    if not token:
        raise VaultError("WARDEN_AGENT_TOKEN is not set (the agent token issued in Warden > Agents)")
    return VaultClient(
        os.getenv("WARDEN_URL", "http://localhost:3003"),
        token,
        vs_id=os.getenv("PG_VIRTUAL_SERVER_ID") or None,
        api_key=os.getenv("WARDEN_API_KEY") or None,
    )
