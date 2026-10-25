param(
    [string]$InventoryPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'docs/dependency-license-inventory.csv')
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$lockFiles = @(
    (Join-Path $repoRoot 'desktop/package-lock.json'),
    (Join-Path $repoRoot 'website/package-lock.json')
)

foreach ($path in $lockFiles) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required npm lockfile is missing: $path"
    }
}
if (-not (Test-Path -LiteralPath $InventoryPath -PathType Leaf)) {
    throw "Existing inventory is required to preserve NuGet rows: $InventoryPath"
}

$existing = @(Import-Csv -LiteralPath $InventoryPath)
$requiredColumns = @('Ecosystem', 'Package', 'Version', 'LicenseDeclaration')
foreach ($column in $requiredColumns) {
    if ($existing.Count -gt 0 -and $existing[0].PSObject.Properties.Name -notcontains $column) {
        throw "Inventory is missing required column: $column"
    }
}
$nugetRows = @($existing | Where-Object Ecosystem -eq 'NuGet' | ForEach-Object {
    [pscustomobject]@{
        Ecosystem = 'NuGet'
        Package = $_.Package
        Version = $_.Version
        LicenseDeclaration = $_.LicenseDeclaration
        DevelopmentDependency = 'n/a'
        InLockfile = 'n/a'
        InstalledLocally = 'True'
    }
})

$npmByPackageVersion = @{}
$lockParserPath = Join-Path $PSScriptRoot 'audit-npm-license-lock.mjs'
foreach ($lockPath in $lockFiles) {
    $lockRoot = Split-Path $lockPath -Parent
    $lockLines = @(& node $lockParserPath $lockPath)
    if ($LASTEXITCODE -ne 0) { throw "Node could not parse npm lockfile: $lockPath" }
    foreach ($lockLine in $lockLines) {
        $entry = ConvertFrom-Json -InputObject $lockLine
        $packagePath = [string]$entry.PackagePath

        $name = $packagePath -replace '^.*node_modules/', ''
        $license = [string]$entry.LicenseDeclaration
        if ([string]::IsNullOrWhiteSpace($license)) {
            throw "No license declaration in lockfile for $name@$($entry.Version) ($lockPath)"
        }

        $key = "$name`n$($entry.Version)"
        $installedPath = Join-Path $lockRoot "$packagePath/package.json"
        $installed = Test-Path -LiteralPath $installedPath -PathType Leaf
        if ($npmByPackageVersion.ContainsKey($key)) {
            $row = $npmByPackageVersion[$key]
            if ($row.LicenseDeclaration -cne $license) {
                throw "Conflicting lockfile license declarations for $name@$($entry.Version): '$($row.LicenseDeclaration)' and '$license'"
            }
            if ($installed) {
                $row.InstalledLocally = 'True'
            }
            if ($entry.DevelopmentDependency -eq 'False') {
                $row.DevelopmentDependency = 'False'
            }
            continue
        }

        $npmByPackageVersion[$key] = [pscustomobject]@{
            Ecosystem = 'npm'
            Package = $name
            Version = [string]$entry.Version
            LicenseDeclaration = $license
            DevelopmentDependency = [string]$entry.DevelopmentDependency
            InLockfile = 'true'
            InstalledLocally = [string]$installed
        }
    }
}

$rows = @($nugetRows) + @($npmByPackageVersion.Values)
$rows = @($rows | Sort-Object Ecosystem, Package, Version)
$rows | Export-Csv -LiteralPath $InventoryPath -NoTypeInformation -Encoding utf8

$npmRows = @($rows | Where-Object Ecosystem -eq 'npm')
$missing = @($npmRows | Where-Object { [string]::IsNullOrWhiteSpace($_.LicenseDeclaration) })
if ($missing.Count -gt 0) {
    throw "Generated inventory contains $($missing.Count) npm entries without license declarations"
}

Write-Output "Wrote $($rows.Count) dependency records ($($nugetRows.Count) NuGet, $($npmRows.Count) npm; $(@($npmRows | Where-Object InstalledLocally -eq 'True').Count) npm manifests locally present and matched to lockfile version/license)."
