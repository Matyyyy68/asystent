$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$version = ([xml](Get-Content (Join-Path $repo 'eng/ProductVersion.props'))).Project.PropertyGroup.VersionPrefix
$out = Join-Path $repo 'artifacts/desktop'
$unpacked = Join-Path $out 'win-unpacked'
$payload = Join-Path $out "Sentinel.AI.Payload.$version.zip"
function Get-Sha256Hex([string]$path) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $stream = [System.IO.File]::OpenRead($path)
  try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') }
  finally { $stream.Dispose(); $sha.Dispose() }
}
New-Item -ItemType Directory -Force $out | Out-Null
Push-Location (Join-Path $repo 'desktop')
try {
  npm.cmd run build
  if ($LASTEXITCODE) { throw 'Application build failed.' }
  node.exe ../scripts/build-npm-third-party-notices.mjs
  if ($LASTEXITCODE) { throw 'Generating npm third-party notices failed.' }
  pwsh -NoProfile -File ../scripts/build-nuget-third-party-notices.ps1
  if ($LASTEXITCODE) { throw 'Generating NuGet and .NET third-party notices failed.' }
  foreach ($asset in @('welcome', 'prepare', 'configure', 'installing', 'complete', 'error', 'cancel')) {
    if (!(Test-Path (Join-Path $repo "desktop/dist/media/illustrations/installer/$asset.png"))) {
      throw "Brak ilustracji instalatora w paczce aplikacji: $asset.png"
    }
  }
  npx.cmd electron-builder --win dir
  if ($LASTEXITCODE) { throw 'Electron packaging failed.' }
  $npmNotices = Join-Path $unpacked 'resources/ThirdPartyNotices/npm-runtime.txt'
  if (!(Test-Path $npmNotices) -or !(Select-String -Path $npmNotices -Pattern 'lucide-react@' -Quiet) -or
      !(Select-String -Path $npmNotices -Pattern 'react-dom@' -Quiet) -or
      !(Select-String -Path $npmNotices -Pattern 'ISC License' -Quiet) -or
      !(Select-String -Path $npmNotices -Pattern 'MIT License' -Quiet)) {
    throw 'npm runtime license notices are missing from the packaged application.'
  }
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
dotnet publish (Join-Path $PSScriptRoot 'Sentinel.Setup/Sentinel.Setup.csproj') -c Release -r win-x64 --self-contained true -p:PayloadZip="$payload" -p:PayloadSha256="$hash" -o $out
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
