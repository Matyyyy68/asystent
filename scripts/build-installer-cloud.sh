#!/usr/bin/env bash
set -euo pipefail
cd /workspace/asystent
export DOTNET_CLI_HOME=/workspace/tools/dotnet-home
export NUGET_PACKAGES=/workspace/tools/nuget
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false
export NSISDIR=/workspace/tools/installer/root/usr/share/nsis
bash scripts/setup-installer-tools.sh
python scripts/package-installer.py --dotnet /workspace/tools/dotnet/dotnet --makensis /workspace/tools/installer/root/usr/bin/makensis
version="$(python3 -c 'import xml.etree.ElementTree as ET; print(ET.parse("eng/ProductVersion.props").findtext("./PropertyGroup/VersionPrefix"))')"
python scripts/verify-installer.py "artifacts/installer/SentinelAI-${version}-win-x64-Setup.exe" --seven-zip /workspace/tools/installer/root/usr/lib/7zip/7z
