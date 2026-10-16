"""HTTP smoke test for the built Sentinel Server API. Uses a temporary database and loopback only."""
import datetime
import json
import os
import pathlib
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

root = pathlib.Path(__file__).resolve().parents[2]
configuration = os.environ.get("Configuration", "Release")
application = root / "server" / "src" / "Sentinel.Server.Api" / "bin" / configuration / "net10.0" / "Sentinel.Server.Api.dll"
if not application.is_file():
    raise SystemExit(f"Build the server first: {application}")
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
address = f"http://127.0.0.1:{port}"
admin_key = secrets.token_urlsafe(32)
data_directory = pathlib.Path(tempfile.mkdtemp(prefix="sentinel-server-api-test-"))
environment = os.environ.copy()
environment.update({"ASPNETCORE_URLS": address, "Sentinel__DataDirectory": str(data_directory), "Sentinel__AdminApiKey": admin_key})
process = subprocess.Popen(["dotnet", str(application)], cwd=root, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def request(path, method="GET", body=None, token=None, expected=200):
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    encoded = json.dumps(body).encode() if body is not None else None
    http_request = urllib.request.Request(address + path, data=encoded, headers=headers, method=method)
    try:
        with urllib.request.urlopen(http_request, timeout=3) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    assert status == expected, f"{method} {path}: expected {expected}, received {status}"
    return json.loads(raw) if raw else None


try:
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("Server process exited before becoming ready")
        try:
            request("/readyz")
            break
        except (OSError, TimeoutError):
            time.sleep(0.1)
    else:
        raise TimeoutError("Server did not become ready")

    assert request("/healthz")["status"] == "healthy"
    request("/api/v1/admin/devices", expected=401)
    expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).isoformat()
    invitation = request("/api/v1/admin/invitations", "POST", {
        "group": "Testowe", "expiresAt": expiry, "maximumRegistrations": 1,
    }, admin_key, 201)
    device = request("/api/v1/agents/enroll", "POST", {
        "invitationCode": invitation["registrationCode"], "deviceName": "TEST-01", "clientVersion": "0.2.0",
    }, expected=201)
    assert request("/api/v1/agents/me", token=device["deviceToken"])["id"] == device["deviceId"]
    request("/api/v1/agents/heartbeat", "POST", {"lastError": "sync_failed"}, device["deviceToken"], 204)
    inventory = request("/api/v1/admin/devices", token=admin_key)
    assert len(inventory) == 1 and inventory[0]["isOnline"] and inventory[0]["group"] == "Testowe"
    request("/api/v1/admin/devices/" + device["deviceId"], "DELETE", token=admin_key, expected=204)
    request("/api/v1/agents/me", token=device["deviceToken"], expected=401)
    print("PASS: health, admin authorization, invitation, enrollment, device auth, heartbeat and revocation")
finally:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    import shutil
    shutil.rmtree(data_directory, ignore_errors=True)
