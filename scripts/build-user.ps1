param([switch]$Installer)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Push-Location $repo
try {
  node scripts/check-product.cjs
  if ($LASTEXITCODE) { throw 'Product consistency check failed' }
  dotnet build src/Sentinel.Engine/Sentinel.Engine.csproj -c Debug
  if ($LASTEXITCODE) { throw 'Debug Engine build failed' }
  dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release
  if ($LASTEXITCODE) { throw 'Tests failed' }
  pwsh -NoProfile -File scripts/test-evaluate-phiusiil-split.ps1
  if ($LASTEXITCODE) { throw 'Domain-disjoint detection evaluation test failed' }
  pwsh -NoProfile -File scripts/test-evaluate-phishvn.ps1
  if ($LASTEXITCODE) { throw 'PhishVN temporal test evaluation guard failed' }
  pwsh -NoProfile -File scripts/test-evaluate-phishvn-brand-tokens.ps1
  if ($LASTEXITCODE) { throw 'PhishVN train/validation brand-token diagnostic guard failed' }
  pwsh -NoProfile -File scripts/test-implementation-plans.ps1
  if ($LASTEXITCODE) { throw 'Implementation plan structure check failed' }
  foreach ($project in @('Sentinel.Engine','Sentinel.UrlHost')) {
    dotnet publish "src/$project/$project.csproj" -c Release -r win-x64 --self-contained true -o artifacts/engine
    if ($LASTEXITCODE) { throw "Build $project failed" }
  }
  node scripts/test-engine.cjs --dns-live
  if ($LASTEXITCODE) { throw 'IPC test failed' }
  Push-Location desktop
  try {
    npm.cmd ci
    if ($LASTEXITCODE) { throw 'npm ci failed' }
    node node_modules/electron/install.js
    if ($LASTEXITCODE) { throw 'Electron runtime download failed' }
    npm.cmd test
    if ($LASTEXITCODE) { throw 'Desktop tests failed' }
    npm.cmd run build
    if ($LASTEXITCODE) { throw 'Build UI failed' }
    if ($Installer) { npm.cmd run package; if ($LASTEXITCODE) { throw 'Installer build failed' } }
  } finally { Pop-Location }
} finally { Pop-Location }
