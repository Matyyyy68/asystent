#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
export DOTNET_CLI_HOME=/workspace/tools/dotnet-home
export NUGET_PACKAGES=/workspace/tools/nuget
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false
export PATH="/workspace/tools/dotnet:$PATH"
export NSISDIR=/workspace/tools/installer/root/usr/share/nsis

version="$(python3 -c 'import xml.etree.ElementTree as ET; print(ET.parse("eng/ProductVersion.props").findtext("./PropertyGroup/VersionPrefix"))')"
staging="$(mktemp -d /tmp/sentinel-server-installer.XXXXXX)"
trap 'rm -rf "$staging"' EXIT
payload="$staging/SentinelServer"
output="$root/server/artifacts"
mkdir -p "$payload" "$output"
rm -f "$output/SentinelServer-$version-win-x64.zip" "$output/SentinelServer-$version-win-x64.zip.sha256" \
  "$output/SentinelServer-$version-win-x64-Setup.exe" "$output/SentinelServer-$version-win-x64-Setup.exe.sha256"
dotnet publish server/src/Sentinel.Server.Api/Sentinel.Server.Api.csproj -c Release -r win-x64 --self-contained true \
  -p:RestoreLockedMode=true -p:VersionPrefix="$version" -o "$payload"
cp server/scripts/install-windows-service.ps1 server/scripts/remove-windows-service.ps1 server/scripts/expand-package.ps1 "$payload/"
cp server/README.md "$payload/README.md"
cp docs/SERVER-BACKUP-RESTORE.md "$payload/BACKUP-RESTORE.md"
(cd "$payload" && zip -qr "$output/SentinelServer-$version-win-x64.zip" .)
sha256sum "$output/SentinelServer-$version-win-x64.zip" > "$output/SentinelServer-$version-win-x64.zip.sha256"
"/workspace/tools/installer/root/usr/bin/makensis" \
  -DAPP_VERSION="$version" \
  -DSERVER_PACKAGE="$output/SentinelServer-$version-win-x64.zip" \
  -DOUTPUT_EXE="$output/SentinelServer-$version-win-x64-Setup.exe" \
  -DSERVER_SCRIPT_DIR="$root/server/scripts" \
  server/installer/SentinelServer.nsi
"/workspace/tools/installer/root/usr/lib/7zip/7z" t "$output/SentinelServer-$version-win-x64-Setup.exe" >/dev/null
"/workspace/tools/installer/root/usr/lib/7zip/7z" t "$output/SentinelServer-$version-win-x64.zip" >/dev/null
sha256sum "$output/SentinelServer-$version-win-x64-Setup.exe" > "$output/SentinelServer-$version-win-x64-Setup.exe.sha256"
printf 'Server installer: %s\n' "$output/SentinelServer-$version-win-x64-Setup.exe"
cat "$output/SentinelServer-$version-win-x64-Setup.exe.sha256"
