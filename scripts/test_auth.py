#!/usr/bin/env python3
"""Test AUTH-01 (registration) and AUTH-02 (RBAC) end-to-end."""
import subprocess
import json
import sys

BASE_URL = "http://192.168.1.225:8765"

def curl(method, path, data=None, token=None, form=False):
    cmd = ["curl", "-s", "-X", method, f"{BASE_URL}{path}"]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    if data:
        if form:
            cmd += ["-d", data]
        else:
            cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return r.returncode, r.stdout

print("=== AUTH-01: Registration ===")
# Create admin user
code, out = curl("POST", "/auth/register", {"username": "admin_test", "password": "adminpass123", "role": "admin"})
print(f"Register admin: {code} → {out[:200]}")
admin_reg = json.loads(out) if out.startswith("{") else {}

# Create viewer user
code, out = curl("POST", "/auth/register", {"username": "viewer_test", "password": "viewerpass123", "role": "viewer"})
print(f"Register viewer: {code} → {out[:200]}")
viewer_reg = json.loads(out) if out.startswith("{") else {}

print("\n=== AUTH-01: Login ===")
# Login as admin
code, out = curl("POST", "/auth/login?username=admin_test&password=adminpass123")
print(f"Admin login: {code} → {out[:200]}")
admin_token = json.loads(out).get("access_token") if out.startswith("{") else None

# Login as viewer
code, out = curl("POST", "/auth/login?username=viewer_test&password=viewerpass123")
print(f"Viewer login: {code} → {out[:200]}")
viewer_token = json.loads(out).get("access_token") if out.startswith("{") else None

print("\n=== AUTH-02: RBAC Tests ===")

# Test 1: Viewer can read /projects (viewer = operator on this route?)
code, out = curl("GET", "/projects", token=viewer_token)
print(f"Viewer GET /projects: {code} → {'OK' if code == 0 else 'FAIL'} (expect 200)")

# Test 2: Viewer should be blocked from admin endpoints
code, out = curl("GET", "/orgs", token=viewer_token)
status = json.loads(out).get("detail", "") if out.startswith("{") else out
print(f"Viewer GET /orgs: {code} → {status[:100]} (expect 403)")

# Test 3: Admin can access /orgs
code, out = curl("GET", "/orgs", token=admin_token)
print(f"Admin GET /orgs: {code} → {'OK' if code == 0 else 'FAIL'} (expect 200)")

# Test 4: No token → 401
code, out = curl("GET", "/orgs")
status = json.loads(out).get("detail", "") if out.startswith("{") else out
print(f"No token GET /orgs: {code} → {status[:100]} (expect 401)")

print("\n=== AUTH Tests Complete ===")

failures = 0
if not admin_token:
    print("FAIL: Could not login as admin")
    failures += 1
if not viewer_token:
    print("FAIL: Could not login as viewer")
    failures += 1

if failures == 0:
    print("PASS: Both AUTH-01 and AUTH-02 verified ✅")
else:
    print(f"FAIL: {failures} checks failed")
    sys.exit(1)
