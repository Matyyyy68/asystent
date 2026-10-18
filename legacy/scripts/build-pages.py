#!/usr/bin/env python3
"""Prepare the public site and current Windows installer for GitHub Pages."""

from __future__ import annotations

import re
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE_SOURCE = ROOT / "server/src/Sentinel.Server.Api/wwwroot"
VERSION_FILE = ROOT / "eng/ProductVersion.props"
REPOSITORY = "https://github.com/Matyyyy68/asystent"


def main() -> int:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "_site"
    if output.exists():
        shutil.rmtree(output)
    shutil.copytree(SITE_SOURCE, output, ignore=shutil.ignore_patterns("admin"))

    props = ET.parse(VERSION_FILE).getroot()
    version = props.findtext(".//VersionPrefix")
    if not version or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit("Could not read a valid product version from eng/ProductVersion.props")

    installer_name = f"SentinelAI-{version}-win-x64-Setup.exe"
    installer_source = ROOT / "artifacts/installer" / installer_name
    checksum_source = ROOT / "artifacts/installer" / f"{installer_name}.sha256"
    if not installer_source.is_file() or not checksum_source.is_file():
        raise SystemExit(f"Installer or SHA-256 file is missing for version {version}")

    download_dir = output / "downloads"
    download_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(installer_source, download_dir / installer_name)
    shutil.copy2(checksum_source, download_dir / f"{installer_name}.sha256")

    base = "/asystent"
    index_path = output / "index.html"
    html = index_path.read_text(encoding="utf-8")
    for asset in ("favicon.svg", "site.css", "site.js"):
        html = html.replace(f'="/{asset}"', f'="{base}/{asset}"')
    html = html.replace('href="/admin/"', f'href="{REPOSITORY}/tree/main/server"')
    html = html.replace(
        f'<span id="release-version">aktualne</span>',
        f'<span id="release-version">{version}</span>',
    )
    html = html.replace(
        'href="https://github.com/Matyyyy68/asystent/releases"',
        f'href="{base}/downloads/{installer_name}"',
        1,
    )
    html = html.replace(
        'href="https://github.com/Matyyyy68/asystent/releases"',
        f'href="{base}/downloads/{installer_name}.sha256"',
        1,
    )
    index_path.write_text(html, encoding="utf-8")
    print(f"Prepared {output} with Sentinel AI {version} installer")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
