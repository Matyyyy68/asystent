param([switch]$Offline, [switch]$AllowDownloads)
$ErrorActionPreference = 'Stop'
if ($Offline -and $AllowDownloads) { throw 'Choose either -Offline or -AllowDownloads, not both.' }
if (-not $Offline -and -not $AllowDownloads) {
  throw 'Installer packaging does not download tools by default. Use -Offline for locally available tools or pass -AllowDownloads to permit tool downloads.'
}
$dotnetRestoreArgs = @()
if ($Offline) { $dotnetRestoreArgs = @('--no-restore') }
$repo = Split-Path $PSScriptRoot -Parent
$electronDistribution = Join-Path $repo 'desktop/node_modules/electron/dist'
if (!(Test-Path -LiteralPath (Join-Path $electronDistribution 'electron.exe') -PathType Leaf)) {
  throw 'The local Electron runtime is missing. Install the locked desktop dependencies before packaging.'
}
# electron-builder 26.15.3 edits the Windows executable using its installed
# `resedit` dependency; the `dir` target does not need the optional rcedit toolset.
$version = ([xml](Get-Content (Join-Path $repo 'eng/ProductVersion.props'))).Project.PropertyGroup.VersionPrefix
$out = Join-Path $repo 'artifacts/desktop'
$unpacked = Join-Path $out 'win-unpacked'
$payload = Join-Path $out "Sentinel.AI.Payload.$version.zip"
foreach ($requiredAsset in @(
  'desktop/assets/sentinel.ico',
  'media/illustrations/installer/welcome.png',
  'media/illustrations/installer/prepare.png',
  'media/illustrations/installer/configure.png',
  'media/illustrations/installer/installing.png',
  'media/illustrations/installer/complete.png',
  'media/illustrations/installer/error.png',
  'media/illustrations/installer/system-check.png',
  'media/illustrations/installer/rollback-ready.png'
)) {
  if (!(Test-Path -LiteralPath (Join-Path $repo $requiredAsset) -PathType Leaf)) {
    throw "Wymagany zasób instalatora nie istnieje: $requiredAsset"
  }
}
# Remove previous outputs only after all source assets are present. A failed build
# must not leave an old installer that appears to be the result of this run.
if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }
function Get-Sha256Hex([string]$path) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $stream = [System.IO.File]::OpenRead($path)
  try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') }
  finally { $stream.Dispose(); $sha.Dispose() }
}
New-Item -ItemType Directory -Force $out | Out-Null
Push-Location (Join-Path $repo 'desktop')
try {
  # Use Vite's runner to load the config without esbuild traversing parent directories.
  npm.cmd run build -- --configLoader runner
  if ($LASTEXITCODE) { throw 'Application build failed.' }
  node.exe ../scripts/build-npm-third-party-notices.mjs
  if ($LASTEXITCODE) { throw 'Generating npm third-party notices failed.' }
  pwsh -NoProfile -File ../scripts/build-nuget-third-party-notices.ps1
  if ($LASTEXITCODE) { throw 'Generating NuGet and .NET third-party notices failed.' }
  foreach ($asset in @('welcome', 'prepare', 'configure', 'installing', 'complete', 'error', 'cancel', 'system-check', 'rollback-ready')) {
    if (!(Test-Path (Join-Path $repo "desktop/dist/media/illustrations/installer/$asset.png"))) {
      throw "Brak ilustracji instalatora w paczce aplikacji: $asset.png"
    }
  }
  $illustrationSource = Join-Path $repo 'media/illustrations'
  $illustrations = @(Get-ChildItem -LiteralPath $illustrationSource -Recurse -Filter *.png)
  if ($illustrations.Count -lt 103) { throw "Biblioteka ilustracji jest niekompletna: znaleziono $($illustrations.Count), oczekiwano co najmniej 103 plików." }
  foreach ($illustrationFile in $illustrations) {
    $relativeIllustration = [IO.Path]::GetRelativePath($illustrationSource, $illustrationFile.FullName)
    if (!(Test-Path -LiteralPath (Join-Path $repo "desktop/dist/media/illustrations/$relativeIllustration") -PathType Leaf)) {
      throw "Brak ilustracji w paczce aplikacji: $relativeIllustration"
    }
  }
  $electronBuilder = Join-Path $repo 'desktop/node_modules/.bin/electron-builder.cmd'
  if (!(Test-Path -LiteralPath $electronBuilder -PathType Leaf)) {
    throw 'Electron Builder is not installed locally; install the locked desktop dependencies before packaging.'
  }
  & $electronBuilder --win dir
  if ($LASTEXITCODE) { throw 'Electron packaging failed.' }
  $npmNotices = Join-Path $unpacked 'resources/ThirdPartyNotices/npm-runtime.txt'
  if (!(Test-Path $npmNotices)) { throw 'npm runtime license notices are missing from the packaged application.' }
  node.exe ../scripts/audit-packaged-npm-licenses.mjs (Join-Path $unpacked 'resources/app.asar') $npmNotices
  if ($LASTEXITCODE) { throw 'Packaged npm runtime modules do not match their bundled license notices.' }
  $nugetNotices = Join-Path $unpacked 'resources/engine/THIRD-PARTY-LICENSES/nuget-runtime.txt'
  $dotnetNotices = Join-Path $unpacked 'resources/engine/THIRD-PARTY-LICENSES/dotnet/ThirdPartyNotices.txt'
  if (!(Test-Path $nugetNotices) -or !(Select-String -Path $nugetNotices -Pattern 'Microsoft.Data.Sqlite 10.0.13' -Quiet) -or
      !(Select-String -Path $nugetNotices -Pattern 'SQLitePCLRaw.lib.e_sqlite3 2.1.13' -Quiet) -or
      !(Test-Path $dotnetNotices) -or !(Select-String -Path $dotnetNotices -Pattern 'License notice for Unicode data' -Quiet)) {
    throw '.NET runtime or NuGet license notices are missing from the packaged application.'
  }
  $pdfPigLicense = Join-Path $unpacked 'resources/engine/THIRD-PARTY-LICENSES/PdfPig-LICENSE.txt'
  if (!(Test-Path $pdfPigLicense) -or !(Select-String -Path $pdfPigLicense -Pattern 'Apache License' -Quiet)) {
    throw 'PdfPig license notice is missing from the packaged application.'
  }
} finally { Pop-Location }
if (Test-Path $payload) { Remove-Item $payload -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($unpacked, $payload, [System.IO.Compression.CompressionLevel]::Optimal, $false)
$hash = Get-Sha256Hex $payload
dotnet publish (Join-Path $PSScriptRoot 'Sentinel.Setup/Sentinel.Setup.csproj') -c Release -r win-x64 --self-contained true -p:PayloadZip="$payload" -p:PayloadSha256="$hash" -o $out @dotnetRestoreArgs
if ($LASTEXITCODE) { throw 'Installer publish failed.' }
$installer = Join-Path $out 'Sentinel.AI.Setup.exe'
$namedInstaller = Join-Path $out "Sentinel.AI.Setup.$version.exe"
Move-Item -Force $installer $namedInstaller
$finalHash = Get-Sha256Hex $namedInstaller
Set-Content -NoNewline -Encoding ascii "$namedInstaller.sha256" "$finalHash  Sentinel.AI.Setup.$version.exe`n"
Write-Host "Instalator: $namedInstaller"
Write-Host "SHA-256: $finalHash"
$selfTest = Start-Process -FilePath $namedInstaller -ArgumentList @('--self-test') -Wait -PassThru -WindowStyle Hidden
if ($selfTest.ExitCode -ne 0) { throw "Installer self-test failed with exit code $($selfTest.ExitCode)." }
Write-Host 'Autotest instalatora: PASS'
