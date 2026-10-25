"""Quick test: verify Anthropic/Bedrock connectivity using BEDROCK_API_KEY."""
import os, sys
from dotenv import load_dotenv
load_dotenv()

import anthropic

# Prefer the new BEDROCK_API_KEY over the old ANTHROPIC_API_KEY
api_key  = os.environ.get("BEDROCK_API_KEY", "").strip() or os.environ.get("ANTHROPIC_API_KEY", "").strip()
base_url = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
model    = os.environ.get("AGENT_MODEL_ID", "us.anthropic.claude-3-5-sonnet-20241022-v2:0").strip()

key_status = ("SET - " + str(len(api_key)) + " chars") if api_key else "MISSING"
print(f"API key  : [{key_status}]")
print(f"Base URL : {base_url or '[default anthropic.com]'}")
print(f"Model    : {model}")
print("\nSending test message...")

kwargs = {"api_key": api_key}
if base_url:
    kwargs["base_url"] = base_url

client = anthropic.Anthropic(**kwargs)

try:
    resp = client.messages.create(
        model=model,
        max_tokens=64,
        messages=[{"role": "user", "content": "Say hello in one sentence."}],
    )
    text = resp.content[0].text if resp.content else "(empty)"
    print(f"\n  SUCCESS: {text!r}")
    print(f"  stop_reason={resp.stop_reason}  usage={resp.usage}")
except anthropic.APIStatusError as e:
    print(f"\n  FAIL {e.status_code}: {e.message}")
    sys.exit(1)
except Exception as e:
    print(f"\n  ERROR: {e}")
    sys.exit(1)
