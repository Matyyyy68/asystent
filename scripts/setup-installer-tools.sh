#!/usr/bin/env bash
set -euo pipefail
# Debian 13 x64 cloud host. Packages are checked against signed Debian indexes.
tool_root=/workspace/tools/installer
mkdir -p "$tool_root/apt/lists/partial" "$tool_root/apt/cache/archives/partial" "$tool_root/apt/unused.d" "$tool_root/apt/preferences.d" "$tool_root/compiler-packages"
if [[ ! -x "$tool_root/root/usr/bin/makensis" || ! -x "$tool_root/root/usr/lib/7zip/7z" ]]; then
    cat > "$tool_root/apt/apt.conf" <<CONF
Dir::Etc "$tool_root/apt";
Dir::Etc::main "unused.conf";
Dir::Etc::parts "unused.d";
Dir::Etc::sourcelist "sources.list";
Dir::Etc::sourceparts "sources.list.d";
Dir::State::lists "$tool_root/apt/lists";
Dir::Cache "$tool_root/apt/cache";
Dir::Log "$tool_root/apt/log";
APT::Sandbox::User "$(id -un)";
Acquire::Languages "none";
CONF
    cat > "$tool_root/apt/sources.list" <<'SOURCES'
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian trixie main
SOURCES
    export APT_CONFIG="$tool_root/apt/apt.conf"
    apt-get update
    cd "$tool_root/compiler-packages"
    apt-get download nsis=3.11-1 nsis-common=3.11-1 7zip
    for package in ./*.deb; do dpkg-deb -x "$package" "$tool_root/root"; done
fi
export NSISDIR="$tool_root/root/usr/share/nsis"
"$tool_root/root/usr/bin/makensis" -VERSION
