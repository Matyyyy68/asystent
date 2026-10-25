$ErrorActionPreference = 'Stop'
$researchRoot = Join-Path $PSScriptRoot 'research\phreshphish'
$evaluate = Join-Path $researchRoot 'evaluate.ps1'
$training = Join-Path $researchRoot 'train-and-evaluate.ps1'
$pythonExecutable = (Get-Command pwsh.exe -ErrorAction Stop).Source
$pwshPath = (Get-Command pwsh.exe -ErrorAction Stop).Source

$source = Get-Content -LiteralPath $evaluate -Raw
if ($source.IndexOf("if (-not `$AllowNetwork)", [StringComparison]::Ordinal) -lt 0 -or
    $source.IndexOf("if (-not `$AllowNetwork)", [StringComparison]::Ordinal) -gt $source.IndexOf('$temporaryDirectory', [StringComparison]::Ordinal)) {
    throw 'PhreshPhish evaluation must require opt-in before creating temporary files.'
}
$source = Get-Content -LiteralPath $training -Raw
if ($source.IndexOf("if (-not `$AllowNetwork)", [StringComparison]::Ordinal) -lt 0 -or
    $source.IndexOf("if (-not `$AllowNetwork)", [StringComparison]::Ordinal) -gt $source.IndexOf('$temporaryDirectory', [StringComparison]::Ordinal)) {
    throw 'PhreshPhish training must require opt-in before creating temporary files or installing packages.'
}

foreach ($script in @($evaluate, $training)) {
    $captureRoot = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-research-guard-' + [Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $captureRoot)
    $stdoutPath = Join-Path $captureRoot 'stdout.txt'
    $stderrPath = Join-Path $captureRoot 'stderr.txt'
    try {
        if ($script -eq $evaluate) {
            $childArguments = '-NoProfile -File "{0}"' -f $script
        } else {
            $childArguments = '-NoProfile -File "{0}" -PythonPath "{1}"' -f $script, $pythonExecutable
        }
        $child = Start-Process -FilePath $pwshPath -ArgumentList $childArguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $text = @((Get-Content -LiteralPath $stdoutPath -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue)) -join "`n"
        if ($child.ExitCode -eq 0 -or $text -notmatch 'Pass -AllowNetwork') {
            throw "$script did not refuse network access by default."
        }
    } finally {
        Remove-Item -LiteralPath $captureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Output 'PASS: research scripts require explicit network opt-in before temporary files or package installation.'
