"""Probe the PointGuard gateway to find the correct API path."""
import re, requests, sys

BASE = "https://deloitte-184504.eval1.appsoc.com"
VS_ID = "be2dd9a745b44318bc4c1eb3760f0060"
TOKEN = sys.argv[1] if len(sys.argv) > 1 else ""

hdrs = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"}

# Fetch SPA HTML, look for API base URL hints
r = requests.get(BASE + "/", headers=hdrs, timeout=10)
html = r.text[:8000]
for pat in [r"apiUrl['\"]?\s*[:=]\s*['\"`]([^'\"`]+)", r"baseUrl['\"]?\s*[:=]\s*['\"`]([^'\"`]+)", r"(https?://[^'\"`\s]*api[^'\"`\s]*)"]:
    matches = re.findall(pat, html)
    if matches:
        print(f"Found in HTML ({pat[:25]}...): {matches[:3]}")

# Find JS bundle filenames
js_refs = re.findall(r'src="([^"]+\.js)"', html)
print(f"\nJS bundles: {js_refs[:5]}")

# Try the first JS bundle for API URL hints
if js_refs:
    url = js_refs[0] if js_refs[0].startswith("http") else BASE + "/" + js_refs[0].lstrip("/")
    try:
        rj = requests.get(url, timeout=10)
        jstxt = rj.text
        for pat in [r"apiUrl['\"]?\s*[:=]\s*['\"`]([^'\"`]{10,80})", r"/api/v\d[^'\"`\s]{0,60}"]:
            m = re.findall(pat, jstxt)
            if m:
                print(f"In JS ({pat[:25]}...): {m[:3]}")
    except Exception as e:
        print(f"JS fetch error: {e}")

# Try likely paths
print("\n--- Path probe ---")
ph = {**hdrs, "Content-Type": "application/json"}
body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
for path in [
    f"/api/servers/{VS_ID}/mcp",
    f"/api/v1/servers/{VS_ID}/mcp",
    f"/api/v2/servers/{VS_ID}/mcp",
    f"/mcp/{VS_ID}",
    f"/gateway/{VS_ID}/mcp",
    f"/v1/mcp/servers/{VS_ID}",
]:
    rp = requests.post(BASE + path, headers=ph, json=body, timeout=8)
    print(f"POST {path} -> {rp.status_code}  {rp.text[:80]}")
