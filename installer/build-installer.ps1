$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$version = ([xml](Get-Content (Join-Path $repo 'eng/ProductVersion.props'))).Project.PropertyGroup.VersionPrefix
$out = Join-Path $repo 'artifacts/desktop'
$unpacked = Join-Path $out 'win-unpacked'
$payload = Join-Path $out "Sentinel.AI.Payload.$version.zip"
New-Item -ItemType Directory -Force $out | Out-Null
Push-Location (Join-Path $repo 'desktop')
try {
  npm.cmd run build
  if ($LASTEXITCODE) { throw 'Budowa aplikacji nie powiodła się.' }
  npx.cmd electron-builder --win dir
  if ($LASTEXITCODE) { throw 'Budowa plików aplikacji nie powiodła się.' }
} finally { Pop-Location }
if (Test-Path $payload) { Remove-Item $payload -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($unpacked, $payload, [System.IO.Compression.CompressionLevel]::Optimal, $false)
$hash = (Get-FileHash $payload -Algorithm SHA256).Hash
dotnet publish (Join-Path $PSScriptRoot 'Sentinel.Setup/Sentinel.Setup.csproj') -c Release -r win-x64 --self-contained true -p:PayloadZip="$payload" -p:PayloadSha256="$hash" -o $out
if ($LASTEXITCODE) { throw 'Budowa własnego instalatora nie powiodła się.' }
$installer = Join-Path $out 'Sentinel.AI.Setup.exe'
$namedInstaller = Join-Path $out "Sentinel.AI.Setup.$version.exe"
Move-Item -Force $installer $namedInstaller
$finalHash = (Get-FileHash $namedInstaller -Algorithm SHA256).Hash
Set-Content -NoNewline -Encoding ascii "$namedInstaller.sha256" "$finalHash  Sentinel.AI.Setup.$version.exe`n"
Write-Host "Instalator: $namedInstaller"
Write-Host "SHA-256: $finalHash"
