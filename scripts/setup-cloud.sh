#!/usr/bin/env bash
set -euo pipefail
export DOTNET_CLI_HOME=/workspace/tools/dotnet-home
export NUGET_PACKAGES=/workspace/tools/nuget
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false
export PATH="/workspace/tools/dotnet:$PATH"
if [[ ! -x /workspace/tools/dotnet/dotnet ]]; then
    archive=$(mktemp /tmp/sentinel-sdk.XXXXXX.tar.gz)
    trap 'rm -f "$archive"' EXIT
    curl --fail --show-error --silent --location https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.402/dotnet-sdk-10.0.402-linux-x64.tar.gz -o "$archive"
    printf '%s  %s\n' '1904a98dda2db34ba78ba3c4fb1b224455329af91c341d83547843c1839e112b04ae699ee92fa2449a8f62249196a938723078c0c60b9f65c88539d5687729c2' "$archive" | sha512sum --check -
    mkdir -p /workspace/tools/dotnet
    tar -xzf "$archive" -C /workspace/tools/dotnet
fi
cd /workspace/asystent
dotnet restore Sentinel.sln --locked-mode --disable-parallel -m:1 -nr:false
dotnet build Sentinel.sln -c Release --no-restore --disable-build-servers -m:1 -nr:false
dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release --no-build --no-restore --disable-build-servers -m:1 -nr:false
dotnet restore server/Sentinel.Server.sln --locked-mode --disable-parallel -m:1 -nr:false
dotnet build server/Sentinel.Server.sln -c Release --no-restore --disable-build-servers -m:1 -nr:false
dotnet test server/Sentinel.Server.sln -c Release --no-build --no-restore --disable-build-servers -m:1 -nr:false
python3 server/scripts/test-api.py
