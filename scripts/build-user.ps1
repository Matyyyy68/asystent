param([switch]$Installer, [switch]$Offline, [switch]$AllowDownloads)
$ErrorActionPreference = 'Stop'
if ($Offline -and $AllowDownloads) { throw 'Choose either -Offline or -AllowDownloads, not both.' }
if (-not $Offline -and -not $AllowDownloads) {
  throw 'Builds do not download dependencies by default. Use -Offline for local dependencies or pass -AllowDownloads to permit NuGet/npm and Electron runtime downloads.'
}
$repo = Split-Path $PSScriptRoot -Parent
$dotnetRestoreArgs = @()
if ($Offline) {
  $dotnetRestoreArgs = @('--no-restore')
  Write-Host 'Offline mode: NuGet restore, npm install, Electron runtime install, and live DNS checks are disabled.'
}
Push-Location $repo
try {
  if ($Offline) {
    $requiredProjectAssets = @(
      'src/Sentinel.Engine/obj/project.assets.json',
      'src/Sentinel.UrlHost/obj/project.assets.json',
      'tests/Sentinel.Tests/obj/project.assets.json',
      'tests/Sentinel.NativeMessagingEngineHost/obj/project.assets.json'
    )
    if ($Installer) { $requiredProjectAssets += 'installer/Sentinel.Setup/obj/project.assets.json' }
    foreach ($assetPath in $requiredProjectAssets) {
      if (!(Test-Path -LiteralPath (Join-Path $repo $assetPath) -PathType Leaf)) {
        throw "Offline build requires existing NuGet restore metadata: $assetPath; no restore was attempted."
      }
    }
    $requiredLocalDependencies = @(
      'node_modules/.bin/tsc.cmd',
      'node_modules/.bin/vite.cmd',
      'node_modules/electron/dist/electron.exe'
    )
    if ($Installer) { $requiredLocalDependencies += 'node_modules/.bin/electron-builder.cmd' }
    foreach ($dependencyPath in $requiredLocalDependencies) {
      if (!(Test-Path -LiteralPath (Join-Path $repo "desktop/$dependencyPath") -PathType Leaf)) {
        throw "Offline build requires an existing local dependency: desktop/$dependencyPath"
      }
    }
    # electron-builder 26.15.3 edits Windows resources through its bundled
    # `resedit` dependency. `rcedit-x64.exe` is not used for the `dir` target.
    Push-Location (Join-Path $repo 'desktop')
    try {
      $npmTreeOutput = & npm.cmd ls --all --json 2>&1
      $npmTreeExitCode = $LASTEXITCODE
    } finally { Pop-Location }
    if ($npmTreeExitCode) {
      Write-Host 'Offline npm dependency validation details:'
      try {
        $npmTreeText = $npmTreeOutput -join [Environment]::NewLine
        $jsonStart = $npmTreeText.IndexOf('{')
        $jsonEnd = $npmTreeText.LastIndexOf('}')
        if ($jsonStart -lt 0 -or $jsonEnd -le $jsonStart) { throw 'npm did not return a JSON report.' }
        $npmTreeReport = $npmTreeText.Substring($jsonStart, $jsonEnd - $jsonStart + 1) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        if ($npmTreeReport.error.summary) { Write-Host " - $($npmTreeReport.error.summary)" }
        else { foreach ($problem in $npmTreeReport.problems) { Write-Host " - $problem" } }
      } catch {
        $npmTreeOutput | Select-Object -Last 5 | ForEach-Object { Write-Host $_ }
      }
      throw 'Offline npm dependency tree is incomplete or inconsistent; no install was attempted.'
    }
  }
  node scripts/check-product.cjs
  if ($LASTEXITCODE) { throw 'Product consistency check failed' }
  dotnet build src/Sentinel.Engine/Sentinel.Engine.csproj -c Debug @dotnetRestoreArgs
  if ($LASTEXITCODE) { throw 'Debug Engine build failed' }
  dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release @dotnetRestoreArgs
  if ($LASTEXITCODE) { throw 'Tests failed' }
  dotnet build tests/Sentinel.NativeMessagingEngineHost/Sentinel.NativeMessagingEngineHost.csproj -c Release @dotnetRestoreArgs
  if ($LASTEXITCODE) { throw 'Native Messaging browser E2E host build failed' }
  pwsh -NoProfile -File scripts/test-evaluate-phiusiil-split.ps1
  if ($LASTEXITCODE) { throw 'Domain-disjoint detection evaluation test failed' }
  pwsh -NoProfile -File scripts/test-evaluate-phishvn.ps1
  if ($LASTEXITCODE) { throw 'PhishVN temporal test evaluation guard failed' }
  pwsh -NoProfile -File scripts/test-evaluate-phishvn-brand-tokens.ps1
  if ($LASTEXITCODE) { throw 'PhishVN train/validation brand-token diagnostic guard failed' }
  pwsh -NoProfile -File scripts/test-evaluate-phishvn-feature-candidates.ps1
  if ($LASTEXITCODE) { throw 'PhishVN URL feature candidate diagnostic guard failed' }
  pwsh -NoProfile -File scripts/test-evaluate-phishvn-brand-candidates.ps1
  if ($LASTEXITCODE) { throw 'PhishVN brand candidate diagnostic guard failed' }
  pwsh -NoProfile -File scripts/test-evaluate-phishvn-cert-feed.ps1
  if ($LASTEXITCODE) { throw 'PhishVN CERT feed evaluation guard failed' }
  pwsh -NoProfile -File scripts/test-research-network-opt-in.ps1
  if ($LASTEXITCODE) { throw 'Research network opt-in guard failed' }
  pwsh -NoProfile -File scripts/test-evaluate-url-phish-feature-candidates.ps1
  if ($LASTEXITCODE) { throw 'URL-Phish feature candidate diagnostic guard failed' }
  pwsh -NoProfile -File scripts/test-evaluate-url-label-csv.ps1
  if ($LASTEXITCODE) { throw 'External URL/label evaluator test failed' }
  pwsh -NoProfile -File scripts/test-implementation-plans.ps1
  if ($LASTEXITCODE) { throw 'Implementation plan structure check failed' }
  pwsh -NoProfile -File scripts/test-implementation-gap-analysis.ps1
  if ($LASTEXITCODE) { throw 'Implementation gap analysis matrix check failed' }
  pwsh -NoProfile -File scripts/test-implementation-gap-analysis-validator.ps1
  if ($LASTEXITCODE) { throw 'Implementation gap analysis validator tests failed' }
  node --test scripts/test-audit-npm-license-lock.mjs
  if ($LASTEXITCODE) { throw 'Installed npm license metadata audit tests failed' }
  node --test scripts/research/phreshphish/network-opt-in.test.mjs
  if ($LASTEXITCODE) { throw 'Research extractor network opt-in tests failed' }
  # Each publish writes to the shared engine output directory. Start from a clean
  # directory so files removed from a project cannot leak into a release payload.
  $engineOutput = Join-Path $repo 'artifacts/engine'
  if (Test-Path -LiteralPath $engineOutput) { Remove-Item -LiteralPath $engineOutput -Recurse -Force }
  foreach ($project in @('Sentinel.Engine','Sentinel.UrlHost')) {
    dotnet publish "src/$project/$project.csproj" -c Release -r win-x64 --self-contained true -o artifacts/engine @dotnetRestoreArgs
    if ($LASTEXITCODE) { throw "Build $project failed" }
  }
  if ($Offline) { node scripts/test-engine.cjs }
  else { node scripts/test-engine.cjs --dns-live }
  if ($LASTEXITCODE) { throw 'IPC test failed' }
  pwsh -NoProfile -File scripts/test-build-download-guard.ps1
  if ($LASTEXITCODE) { throw 'Build download opt-in guard tests failed' }
  Push-Location desktop
  try {
    if ($Offline) {
      Write-Host 'Offline local dependency checks passed.'
    } else {
      npm.cmd ci
      if ($LASTEXITCODE) { throw 'npm ci failed' }
      node node_modules/electron/install.js
      if ($LASTEXITCODE) { throw 'Electron runtime download failed' }
    }
    node --test ../scripts/test-audit-packaged-npm-licenses.mjs
    if ($LASTEXITCODE) { throw 'Packaged npm license audit tests failed' }
    npm.cmd test
    if ($LASTEXITCODE) { throw 'Desktop tests failed' }
    # Load vite.config.js directly; bundling the config with esbuild traverses parent directories
    # and fails under workspace-restricted sandboxes even though all project files are accessible.
    npm.cmd run build -- --configLoader runner
    if ($LASTEXITCODE) { throw 'Build UI failed' }
    if ($Installer) {
      if ($Offline) { pwsh -NoProfile -File ../installer/build-installer.ps1 -Offline }
      else { pwsh -NoProfile -File ../installer/build-installer.ps1 -AllowDownloads }
      if ($LASTEXITCODE) { throw 'Installer build failed' }
    }
  } finally { Pop-Location }
} finally { Pop-Location }
