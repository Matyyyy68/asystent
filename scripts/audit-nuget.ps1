$ErrorActionPreference = 'Stop'

function Get-VulnerablePackages($Value) {
    if ($null -eq $Value) { return }

    if ($Value -is [System.Collections.IDictionary]) {
        $vulnerabilities = $Value['vulnerabilities']
        if ($null -ne $vulnerabilities -and @($vulnerabilities).Count -gt 0) {
            $Value
            return
        }
        foreach ($entry in $Value.Values) {
            Get-VulnerablePackages $entry
        }
        return
    }

    if ($Value -is [pscustomobject]) {
        $vulnerabilityProperty = $Value.PSObject.Properties['vulnerabilities']
        if ($null -ne $vulnerabilityProperty -and $null -ne $vulnerabilityProperty.Value -and @($vulnerabilityProperty.Value).Count -gt 0) {
            $Value
            return
        }
        foreach ($property in $Value.PSObject.Properties) {
            Get-VulnerablePackages $property.Value
        }
        return
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        foreach ($item in $Value) {
            Get-VulnerablePackages $item
        }
    }
}

function Get-AuditProblems($Value) {
    if ($null -eq $Value) { return }

    if ($Value -is [System.Collections.IDictionary]) {
        $level = $Value['level']
        $message = $Value['text']
        if ($null -ne $level -and $null -ne $message -and
            ($level -eq 'error' -or $message -match '(?i)vulnerabilit|audit source|audit data')) {
            $Value
            return
        }
        foreach ($entry in $Value.Values) {
            Get-AuditProblems $entry
        }
        return
    }

    if ($Value -is [pscustomobject]) {
        $level = $Value.PSObject.Properties['level']
        $message = $Value.PSObject.Properties['text']
        if ($null -ne $level -and $null -ne $message -and
            ($level.Value -eq 'error' -or $message.Value -match '(?i)vulnerabilit|audit source|audit data')) {
            $Value
            return
        }
        foreach ($property in $Value.PSObject.Properties) {
            Get-AuditProblems $property.Value
        }
        return
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        foreach ($item in $Value) {
            Get-AuditProblems $item
        }
    }
}

$solutions = @('Sentinel.sln', 'server/Sentinel.Server.sln')
foreach ($solution in $solutions) {
    Write-Host "Auditing transitive NuGet dependencies: $solution"
    $output = & dotnet package list --project $solution --vulnerable --include-transitive --format json --verbosity quiet 2>&1
    $exitCode = $LASTEXITCODE
    $jsonText = ($output | ForEach-Object { "$_" }) -join [Environment]::NewLine
    if ($exitCode -ne 0) {
        throw "NuGet vulnerability audit failed for '$solution' (exit $exitCode).`n$jsonText"
    }

    try {
        $report = $jsonText | ConvertFrom-Json -AsHashtable
    }
    catch {
        throw "NuGet vulnerability audit returned invalid JSON for '$solution'.`n$jsonText"
    }

    $auditProblems = @(Get-AuditProblems $report)
    if ($auditProblems.Count -gt 0) {
        $details = $auditProblems | ConvertTo-Json -Depth 8
        throw "NuGet vulnerability audit reported an incomplete or failed source for '$solution'.`n$details"
    }

    $findings = @(Get-VulnerablePackages $report)
    if ($findings.Count -gt 0) {
        $details = $findings | ConvertTo-Json -Depth 12
        throw "Known vulnerable NuGet dependencies were found in '$solution'.`n$details"
    }

    Write-Host "No known vulnerable NuGet dependencies found in $solution."
}
