#!/usr/bin/env python3
"""Validate the packaged Chromium extension's identity and narrow permissions."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
extension = root / "browser-extension"
manifest = json.loads((extension / "manifest.json").read_text(encoding="utf-8"))
app_version = ET.parse(root / "eng/ProductVersion.props").findtext("./PropertyGroup/VersionPrefix")
if manifest.get("version") != app_version:
    raise SystemExit("Browser extension version must match the shipped application version")
if manifest.get("manifest_version") != 3:
    raise SystemExit("Browser extension must use Manifest V3")
permissions = set(manifest.get("permissions", []))
if permissions != {"webNavigation", "tabs", "nativeMessaging"}:
    raise SystemExit(f"Unexpected browser permissions: {sorted(permissions)}")
key = base64.b64decode(manifest["key"], validate=True)
extension_id = "".join(chr(97 + (nibble >> 4)) + chr(97 + (nibble & 15))
                       for nibble in hashlib.sha256(key).digest()[:16])
host_source = (root / "src/Sentinel.UrlHost/NativeHostRegistration.cs").read_text(encoding="utf-8")
if f'ExtensionId = "{extension_id}"' not in host_source:
    raise SystemExit("Extension key and native host allowed origin do not match")
for required in ("background.js", "popup.html", "popup.js", "warning.html", "warning.js", "style.css"):
    if not (extension / required).is_file():
        raise SystemExit(f"Missing extension file: {required}")
background = (extension / "background.js").read_text(encoding="utf-8")
if "webNavigation.onBeforeNavigate" not in background or "connectNative(HOST)" not in background:
    raise SystemExit("Extension is missing navigation or Native Messaging integration")
if shutil.which("node"):
    for path in sorted(extension.glob("*.js")):
        subprocess.run(["node", "--check", str(path)], check=True)
else:
    print("SKIP: Node.js is unavailable; extension JavaScript syntax was not checked")
print(f"PASS: Chromium MV3 extension, least-privilege permissions and Native Messaging identity {extension_id}")
