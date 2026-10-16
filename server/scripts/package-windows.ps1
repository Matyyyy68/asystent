param([string]$OutputDirectory = "$(Split-Path -Parent $PSScriptRoot)\artifacts")
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$project = Join-Path $root 'server\src\Sentinel.Server.Api\Sentinel.Server.Api.csproj'
$props = [xml](Get-Content (Join-Path $root 'eng\ProductVersion.props'))
$version = $props.Project.PropertyGroup.VersionPrefix
$destination = [IO.Path]::GetFullPath($OutputDirectory)
$stage = Join-Path ([IO.Path]::GetTempPath()) ("sentinel-server-" + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    dotnet publish $project -c Release -r win-x64 --self-contained true -p:RestoreLockedMode=true -p:VersionPrefix=$version -o $stage
    if ($LASTEXITCODE -ne 0) { throw 'Publikowanie serwera nie powiodło się.' }
    Copy-Item (Join-Path $PSScriptRoot 'install-windows-service.ps1') $stage
    Copy-Item (Join-Path $PSScriptRoot 'remove-windows-service.ps1') $stage
    Copy-Item (Join-Path $PSScriptRoot 'expand-package.ps1') $stage
    Copy-Item (Join-Path $root 'docs\SERVER-BACKUP-RESTORE.md') (Join-Path $stage 'BACKUP-RESTORE.md')
    Copy-Item (Join-Path $root 'server\README.md') (Join-Path $stage 'README.md')
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    $archive = Join-Path $destination "SentinelServer-$version-win-x64.zip"
    if (Test-Path $archive) { throw "Pakiet już istnieje: $archive" }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
    Write-Host "Pakiet serwera: $archive"
}
finally { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
