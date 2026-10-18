param([switch]$Installer)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo
try {
  dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release
  if ($LASTEXITCODE) { throw 'Testy nie przeszły' }
  foreach ($project in @('Sentinel.Engine','Sentinel.UrlHost')) {
    dotnet publish "src/$project/$project.csproj" -c Release -r win-x64 --self-contained true -o artifacts/engine
    if ($LASTEXITCODE) { throw "Build $project nie powiódł się" }
  }
  node scripts/test-engine.cjs
  if ($LASTEXITCODE) { throw 'Test IPC nie przeszedł' }
  Push-Location desktop
  try {
    npm.cmd ci
    if ($LASTEXITCODE) { throw 'npm ci nie powiodło się' }
    node node_modules/electron/install.js
    if ($LASTEXITCODE) { throw 'Pobranie środowiska Electron nie powiodło się' }
    npm.cmd run build
    if ($LASTEXITCODE) { throw 'Build UI nie powiódł się' }
    if ($Installer) { npm.cmd run package; if ($LASTEXITCODE) { throw 'Build instalatora nie powiódł się' } }
  } finally { Pop-Location }
} finally { Pop-Location }
