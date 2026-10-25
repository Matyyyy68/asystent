$ErrorActionPreference = 'Stop'
$pwshPath = (Get-Command pwsh.exe -ErrorAction Stop).Source
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$cases = @(
    @{ Script = 'scripts/build-user.ps1'; Arguments = @(); Message = 'Builds do not download dependencies by default.' },
    @{ Script = 'scripts/build-user.ps1'; Arguments = @('-Offline', '-AllowDownloads'); Message = 'Choose either -Offline or -AllowDownloads, not both.' },
    @{ Script = 'installer/build-installer.ps1'; Arguments = @(); Message = 'Installer packaging does not download tools by default.' },
    @{ Script = 'installer/build-installer.ps1'; Arguments = @('-Offline', '-AllowDownloads'); Message = 'Choose either -Offline or -AllowDownloads, not both.' }
)

foreach ($case in $cases) {
    $scriptPath = Join-Path $repositoryRoot $case.Script
    $captureRoot = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-build-guard-' + [Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $captureRoot)
    $stdoutPath = Join-Path $captureRoot 'stdout.txt'
    $stderrPath = Join-Path $captureRoot 'stderr.txt'
    try {
        $childArguments = '-NoProfile -File "{0}" {1}' -f $scriptPath, ($case.Arguments -join ' ')
        $child = Start-Process -FilePath $pwshPath -ArgumentList $childArguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $text = @((Get-Content -LiteralPath $stdoutPath -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue)) -join [Environment]::NewLine
        if ($child.ExitCode -eq 0 -or $text -notlike "*$($case.Message)*") {
            throw "Download guard did not reject '$($case.Script)' with arguments '$($case.Arguments -join ' ')'."
        }
    } finally {
        Remove-Item -LiteralPath $captureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host 'PASS: build and installer scripts require explicit download opt-in and reject conflicting modes.'
