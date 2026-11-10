"""
Smoke-test the Warden Credential Vault from the agent side.

  python test_vault.py <secret-name>              # runtime checkout (value is NOT printed)
  python test_vault.py <secret-name> --sign       # sign a JWT with a stored private key

Needs WARDEN_AGENT_TOKEN (and optionally WARDEN_URL, PG_VIRTUAL_SERVER_ID) in .env. The agent must be
permitted by a vault policy in Warden > Vault > Policies, otherwise this is denied by design.
"""
import sys

from vault_client import VaultError, client_from_env


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    name = sys.argv[1]
    try:
        vault = client_from_env()
        if "--sign" in sys.argv:
            token = vault.sign(name, claims={})
            print(f"signed JWT ({len(token)} chars): {token[:24]}...")
        else:
            secret = vault.get(name)
            print(secret)
            print(f"value: <{len(secret.value)} characters, hidden>")
            print(f"lease valid: {vault.is_valid(secret)}")
        return 0
    except VaultError as exc:
        print(f"DENIED/ERROR: {exc} (HTTP {exc.http_status})")
        return 1


if __name__ == "__main__":
    sys.exit(main())
