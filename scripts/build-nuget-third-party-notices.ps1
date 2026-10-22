param(
  [string]$EnginePublishPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'artifacts/engine')
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path $PSScriptRoot -Parent
$depsPath = Join-Path $EnginePublishPath 'Sentinel.Engine.deps.json'
if (!(Test-Path -LiteralPath $depsPath -PathType Leaf)) { throw "Engine dependency manifest is missing: $depsPath" }

$dotnetPath = (Get-Command dotnet.exe -ErrorAction Stop).Source
$dotnetRoot = Split-Path $dotnetPath -Parent
$dotnetNotices = Join-Path $dotnetRoot 'ThirdPartyNotices.txt'
if (!(Test-Path -LiteralPath $dotnetNotices -PathType Leaf)) { throw "Bundled .NET third-party notices are missing: $dotnetNotices" }

$deps = Get-Content -LiteralPath $depsPath -Raw | ConvertFrom-Json
$runtimeTarget = $deps.runtimeTarget.name
$target = $deps.targets.PSObject.Properties[$runtimeTarget].Value
if ($null -eq $target) { throw "Runtime target '$runtimeTarget' is missing from $depsPath" }

$nugetRoot = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path $env:USERPROFILE '.nuget/packages' }
$packages = @()
foreach ($property in $target.PSObject.Properties) {
  $parts = $property.Name -split '/', 2
  if ($parts.Count -ne 2 -or $parts[0] -like 'Sentinel.*' -or $parts[0] -like 'runtimepack.*') { continue }
  $packageId, $version = $parts
  $nuspecDirectory = Join-Path (Join-Path (Join-Path $nugetRoot $packageId.ToLowerInvariant()) $version) ''
  $nuspecFiles = @(Get-ChildItem -LiteralPath $nuspecDirectory -Filter '*.nuspec' -File -ErrorAction SilentlyContinue)
  if ($nuspecFiles.Count -ne 1) { throw "Expected one NuGet nuspec for $packageId@$version under $nuspecDirectory; found $($nuspecFiles.Count)." }

  [xml]$nuspec = Get-Content -LiteralPath $nuspecFiles[0].FullName -Raw
  $metadata = $nuspec.package.metadata
  $licenseNode = $metadata.license
  $licenseText = [string]$licenseNode.InnerText
  if ([string]::IsNullOrWhiteSpace($licenseText)) { throw "License declaration is missing from $packageId@$version nuspec." }
  $packages += [pscustomobject]@{
    Id = $packageId
    Version = $version
    License = $licenseText
    LicenseType = [string]$licenseNode.GetAttribute('type')
    LicenseUrl = [string]$metadata.licenseUrl
    Copyright = [string]$metadata.copyright
    Repository = [string]$metadata.repository.url
  }
}

if ($packages.Count -eq 0) { throw 'No runtime NuGet dependencies were found in the engine dependency manifest.' }
$packages = @($packages | Sort-Object Id, Version -Unique)
$licenseDirectory = Join-Path $EnginePublishPath 'THIRD-PARTY-LICENSES'
$dotnetDirectory = Join-Path $licenseDirectory 'dotnet'
New-Item -ItemType Directory -Path $dotnetDirectory -Force | Out-Null
Copy-Item -LiteralPath $dotnetNotices -Destination (Join-Path $dotnetDirectory 'ThirdPartyNotices.txt') -Force

$lines = @(
  'Runtime NuGet dependencies included in Sentinel.Engine.',
  'License declarations and copyright values are copied from each package nuspec.',
  'The bundled .NET runtime notice is in dotnet/ThirdPartyNotices.txt.',
  'For SPDX expression licenses, full license texts are available at the listed license URL.',
  ''
)
foreach ($package in $packages) {
  $lines += "[$($package.Id) $($package.Version)]"
  $lines += "License: $($package.LicenseType) $($package.License)"
  if ($package.Copyright) { $lines += "Copyright: $($package.Copyright)" }
  if ($package.LicenseUrl) { $lines += "License URL: $($package.LicenseUrl)" }
  if ($package.Repository) { $lines += "Repository: $($package.Repository)" }
  $lines += ''
}
$outputPath = Join-Path $licenseDirectory 'nuget-runtime.txt'
Set-Content -LiteralPath $outputPath -Value $lines -Encoding utf8
Write-Output "Generated runtime NuGet notices for $($packages.Count) packages and copied .NET third-party notices."
