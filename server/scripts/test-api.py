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
import xml.etree.ElementTree as ET

root = pathlib.Path(__file__).resolve().parents[2]
product_version = ET.parse(root / "eng" / "ProductVersion.props").findtext("./PropertyGroup/VersionPrefix")
configuration = os.environ.get("Configuration", "Release")
application = root / "server" / "src" / "Sentinel.Server.Api" / "bin" / configuration / "net10.0" / "Sentinel.Server.Api.dll"
if not application.is_file():
    raise SystemExit(f"Build the server first: {application}")
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
address = f"http://127.0.0.1:{port}"
admin_password = "Initial-api-admin-password-42!"
data_directory = pathlib.Path(tempfile.mkdtemp(prefix="sentinel-server-api-test-"))
environment = os.environ.copy()
environment.update({"ASPNETCORE_URLS": address, "Sentinel__DataDirectory": str(data_directory),
                    "Sentinel__BootstrapAdminUsername": "it-admin", "Sentinel__BootstrapAdminPassword": admin_password})
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


def request_raw(path, data, token=None, file_name=None, expected=200):
    headers = {"Content-Type": "application/octet-stream"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if file_name:
        headers["X-Sentinel-Filename"] = file_name
    http_request = urllib.request.Request(address + path, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(http_request, timeout=10) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    assert status == expected, f"POST {path}: expected {expected}, received {status}"
    return json.loads(raw) if raw else None


try:
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("Server process exited before becoming ready")
        try:
            readiness = request("/readyz")
            assert readiness.get("productVersion") == product_version, readiness
            break
        except (OSError, TimeoutError):
            time.sleep(0.1)
    else:
        raise TimeoutError("Server did not become ready")

    assert request("/healthz")["status"] == "healthy"
    with urllib.request.urlopen(address + "/", timeout=3) as response:
        page = response.read().decode("utf-8")
        assert response.status == 200 and "Bezpieczeństwo cyfrowe." in page and "Kontakt i zgłoszenia" in page
        assert response.headers.get("Content-Security-Policy", "").find("script-src 'self'") >= 0
        assert response.headers.get("X-Frame-Options") == "DENY"
    for asset, expected_marker in (("/site.css", ".feature-grid"), ("/site.js", "aria-expanded")):
        with urllib.request.urlopen(address + asset, timeout=3) as response:
            assert response.status == 200 and expected_marker.encode() in response.read()
    with urllib.request.urlopen(address + "/admin/", timeout=3) as response:
        page = response.read().decode("utf-8")
        assert response.status == 200 and "Panel administracyjny" in page
        assert response.headers.get("Content-Security-Policy", "").find("script-src 'self'") >= 0
        assert response.headers.get("X-Frame-Options") == "DENY"
    for asset, expected_marker in (("app.css", "--orange"), ("app.js", "sectionTitles")):
        with urllib.request.urlopen(address + "/admin/" + asset, timeout=3) as response:
            assert response.status == 200 and expected_marker.encode() in response.read()
    request("/api/v1/admin/devices", expected=401)
    request("/api/v1/admin/auth/login", "POST", {"username": "it-admin", "password": "incorrect-password"}, expected=401)
    system_session = request("/api/v1/admin/auth/login", "POST", {"username": "it-admin", "password": admin_password})["accessToken"]
    request("/api/v1/admin/devices", token=system_session)
    ai_config = request("/api/v1/admin/ai/configuration", token=system_session)
    assert not ai_config["enabled"] and ai_config["execution"] == "loopback_only"
    request("/api/v1/admin/ai/configuration", "PUT", {
        "endpoint": "https://remote-model.invalid", "model": "synthetic", "enabled": False,
        "timeoutSeconds": 30, "expectedVersion": ai_config["version"],
    }, system_session, 400)
    request("/api/v1/admin/ai/configuration", "PUT", {
        "endpoint": "http://127.0.0.1:1", "model": "", "enabled": False,
        "timeoutSeconds": 3, "expectedVersion": ai_config["version"],
    }, system_session, 200)
    request("/api/v1/admin/ai/models", token=system_session, expected=503)
    request("/api/v1/admin/ai/configuration", "PUT", {
        "endpoint": "http://127.0.0.1:1", "model": "", "enabled": False,
        "timeoutSeconds": 3, "expectedVersion": ai_config["version"],
    }, system_session, 409)
    request("/api/v1/admin/users", "POST", {
        "username": "operator", "password": "Operator-api-password-42!", "role": "Operator",
    }, system_session, 201)
    operator_session = request("/api/v1/admin/auth/login", "POST", {
        "username": "operator", "password": "Operator-api-password-42!",
    })["accessToken"]
    request("/api/v1/admin/audit", token=operator_session, expected=403)
    request("/api/v1/admin/devices", token=operator_session)
    group = request("/api/v1/admin/groups", "POST", {"name": "Testowe"}, system_session, 201)
    request("/api/v1/admin/groups", "POST", {"name": "testowe"}, system_session, 409)
    request("/api/v1/admin/invitations", "POST", {
        "group": "Brak", "expiresAt": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).isoformat(),
        "maximumRegistrations": 1,
    }, system_session, 400)
    request("/api/v1/admin/policies/global", "PUT", {
        "policy": {"analysisIntervalSeconds": 45}, "expectedVersion": 0,
    }, system_session, 204)
    request("/api/v1/admin/policies/global", "PUT", {
        "policy": {"analysisIntervalSeconds": 60}, "expectedVersion": 0,
    }, system_session, 409)
    request(f"/api/v1/admin/groups/{group['id']}/policy", "PUT", {
        "policy": {"detailLevel": 3}, "expectedVersion": 0,
    }, system_session, 204)
    request(f"/api/v1/admin/groups/{group['id']}/policy", "PUT", {
        "policy": {"analysisMode": "server"}, "expectedVersion": 1,
    }, system_session, 403)
    request("/api/v1/admin/users", "POST", {
        "username": "security", "password": "Security-api-password-42!", "role": "SecurityAdministrator",
    }, system_session, 201)
    security_session = request("/api/v1/admin/auth/login", "POST", {
        "username": "security", "password": "Security-api-password-42!",
    })["accessToken"]
    request_raw("/api/v1/admin/knowledge/documents", b"Syntetyczna procedura: weryfikuj przelew niezaleznym kanalem.", operator_session, "policy.txt", 403)
    document = request_raw("/api/v1/admin/knowledge/documents", b"Syntetyczna procedura: weryfikuj przelew niezaleznym kanalem.", security_session, "policy.txt", 201)
    assert document["chunkCount"] >= 1
    docs = request("/api/v1/admin/knowledge/documents", token=system_session)
    assert len(docs) == 1 and docs[0]["id"] == document["id"]
    hits = request("/api/v1/admin/knowledge/search?query=weryfikuj%20przelew", token=operator_session)
    assert hits and hits[0]["documentId"] == document["id"]
    request_raw("/api/v1/admin/knowledge/documents", b"synthetic", security_session, "../../bad.txt", 400)
    request(f"/api/v1/admin/groups/{group['id']}/policy", "PUT", {
        "policy": {"analysisMode": "server", "detailLevel": 3}, "expectedVersion": 1, "confirmedSensitiveChange": True,
    }, security_session, 403)
    request(f"/api/v1/admin/groups/{group['id']}/policy", "PUT", {
        "policy": {"analysisMode": "server"}, "expectedVersion": 1,
    }, system_session, 403)
    request(f"/api/v1/admin/groups/{group['id']}/policy", "PUT", {
        "policy": {"analysisMode": "server", "detailLevel": 3}, "expectedVersion": 1, "confirmedSensitiveChange": True,
    }, system_session, 204)
    expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).isoformat()
    invitation = request("/api/v1/admin/invitations", "POST", {
        "group": "Testowe", "expiresAt": expiry, "maximumRegistrations": 1,
        "requiresApproval": True,
    }, system_session, 201)
    request("/api/v1/admin/invitations", "POST", {
        "group": "Testowe", "expiresAt": expiry, "maximumRegistrations": 1,
    }, operator_session, 403)
    device = request("/api/v1/agents/enroll", "POST", {
        "invitationCode": invitation["registrationCode"], "deviceName": "TEST-01", "clientVersion": product_version,
    }, expected=201)
    assert request("/api/v1/admin/devices", token=system_session)[0]["approved"] is False
    request("/api/v1/agents/me", token=device["deviceToken"], expected=401)
    request(f"/api/v1/admin/devices/{device['deviceId']}/approval", "PUT", {"approved": True}, operator_session, 403)
    request(f"/api/v1/admin/devices/{device['deviceId']}/approval", "PUT", {"approved": True}, system_session, 204)
    assert request("/api/v1/agents/me", token=device["deviceToken"])["id"] == device["deviceId"]
    rotated_device_token = "rotated-api-device-token-12345678901234567890"
    request("/api/v1/agents/credentials/rotate", "POST", {"newDeviceToken": rotated_device_token}, device["deviceToken"], 204)
    assert request("/api/v1/agents/me", token=device["deviceToken"])["id"] == device["deviceId"]
    assert request("/api/v1/agents/me", token=rotated_device_token)["id"] == device["deviceId"]
    request("/api/v1/agents/me", token=device["deviceToken"], expected=401)
    device["deviceToken"] = rotated_device_token
    agent_configuration = request("/api/v1/agents/configuration", token=device["deviceToken"])
    assert agent_configuration["effective"]["analysisMode"] == "server"
    request("/api/v1/agents/configuration", token="invalid-configuration-agent-token-123456789", expected=401)
    request("/api/v1/agents/heartbeat", "POST", {"lastError": "sync_failed"}, device["deviceToken"], 204)
    inventory = request("/api/v1/admin/devices", token=system_session)
    assert len(inventory) == 1 and inventory[0]["isOnline"] and inventory[0]["group"] == "Testowe"
    effective = request(f"/api/v1/admin/devices/{device['deviceId']}/policy", token=system_session)
    assert effective["effective"]["analysisIntervalSeconds"] == 45
    assert effective["effective"]["detailLevel"] == 3
    assert effective["sources"]["analysisIntervalSeconds"] == "global"
    assert effective["sources"]["detailLevel"] == "group"
    assert effective["effective"]["analysisMode"] == "server"
    request("/api/v1/agents/analyze", "POST", {
        "application": "Synthetic", "text": "Pilnie: blokada konta. Zaloguj się.",
        "contextSharingConfirmed": True,
    }, device["deviceToken"], 403)
    request(f"/api/v1/admin/devices/{device['deviceId']}/policy", "PUT", {
        "policy": {"includeContext": True, "aiProvider": "ollama"}, "expectedVersion": 0, "confirmedSensitiveChange": True,
    }, system_session, 204)
    remote_analysis = request("/api/v1/agents/analyze", "POST", {
        "application": "Synthetic", "text": "Pilnie: blokada konta. Zaloguj się.",
        "targetUrl": "https://example.test/login",
        "contextSharingConfirmed": True,
    }, device["deviceToken"])
    assert remote_analysis["modelEnabled"] is False and remote_analysis["contextPersisted"] is False
    request("/api/v1/agents/analyze", "POST", {
        "application": "Synthetic", "text": "Pilnie: blokada konta.",
        "contextSharingConfirmed": False,
    }, device["deviceToken"], 400)
    url_only_analysis = request("/api/v1/agents/analyze", "POST", {
        "application": "Synthetic", "text": "", "targetUrl": "https://example.test/login",
        "contextSharingConfirmed": True,
    }, device["deviceToken"])
    assert url_only_analysis["contextPersisted"] is False
    request(f"/api/v1/admin/devices/{device['deviceId']}/group", "PUT", {"groupId": group["id"]}, system_session, 204)
    request(f"/api/v1/admin/devices/{device['deviceId']}/group", "PUT", {"groupId": "missing"}, system_session, 404)
    request(f"/api/v1/admin/devices/{device['deviceId']}/policy", "PUT", {
        "policy": {"riskThreshold": 4}, "expectedVersion": 1,
    }, system_session, 204)
    device_policy = request(f"/api/v1/admin/devices/{device['deviceId']}/policy", token=system_session)
    assert device_policy["effective"]["riskThreshold"] == 4
    assert device_policy["sources"]["riskThreshold"] == "device"
    event = {
        "eventId": "7bc2141e-cb9d-4d10-b9e0-47e4d2ce4100",
        "occurredAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "category": "url", "riskLevel": 3, "ruleCode": "url.suspicious_domain",
        "source": "manual-analysis", "ruleVersion": "2026.10.1", "schemaVersion": 1,
    }
    assert request("/api/v1/agents/events", "POST", {"events": [event]}, device["deviceToken"]) == {"accepted": 1, "duplicates": 0}
    assert request("/api/v1/agents/events", "POST", {"events": [event]}, device["deviceToken"]) == {"accepted": 0, "duplicates": 1}
    request("/api/v1/agents/events", "POST", {"events": [event]}, "invalid-event-agent-token-123456789012345", 401)
    events = request("/api/v1/admin/events", token=system_session)
    assert len(events) == 1 and events[0]["deviceId"] == device["deviceId"]
    assert events[0]["source"] == "manual-analysis" and events[0]["ruleVersion"] == "2026.10.1" and events[0]["schemaVersion"] == 1
    request(f"/api/v1/admin/events/{device['deviceId']}/{event['eventId']}/status", "PUT",
            {"status": "false_positive"}, security_session, 204)
    assert request("/api/v1/admin/events", token=system_session)[0]["status"] == "false_positive"
    request("/api/v1/admin/devices/" + device["deviceId"], "DELETE", token=system_session, expected=204)
    request("/api/v1/agents/me", token=device["deviceToken"], expected=401)
    request("/api/v1/admin/auth/password", "PUT", {
        "currentPassword": admin_password, "newPassword": "Rotated-api-admin-password-42!",
    }, system_session, 204)
    request("/api/v1/admin/devices", token=system_session, expected=401)
    rotated_session = request("/api/v1/admin/auth/login", "POST", {
        "username": "it-admin", "password": "Rotated-api-admin-password-42!",
    })["accessToken"]
    request(f"/api/v1/admin/knowledge/documents/{document['id']}", "DELETE", token=security_session, expected=204)
    assert request("/api/v1/admin/knowledge/documents", token=rotated_session) == []
    audit = request("/api/v1/admin/audit", token=rotated_session)
    assert any(entry["action"] == "device.revoked" for entry in audit)
    assert any(entry["action"] == "event.status_changed" for entry in audit)
    assert any(entry["action"] == "admin.password_changed" for entry in audit)
    assert any(entry["action"] == "knowledge.document_imported" for entry in audit)
    assert any(entry["action"] == "knowledge.document_deleted" for entry in audit)
    print("PASS: health, admin bootstrap/login, RBAC, policies, AI configuration/test and consent-gated analysis, knowledge import/search/delete, invitations, enrollment, heartbeat, audit and revocation")
finally:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    import shutil
    shutil.rmtree(data_directory, ignore_errors=True)
