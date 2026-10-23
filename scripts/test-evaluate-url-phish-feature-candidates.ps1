$ErrorActionPreference = 'Stop'
$fixtureDirectory = Join-Path $env:TEMP ('sentinel-url-phish-feature-scan-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $fixtureDirectory)
$fixture = Join-Path $fixtureDirectory 'Dataset.csv'
$wrongName = Join-Path $fixtureDirectory 'other.csv'
Set-Content -LiteralPath $fixture -Value @(
    'url,label',
    'https://abcdefghijklmnopqrstuvwxyz.com/,1',
    'https://qqqqqqqqqqqqqqqqqqqq.com/,0',
    'https://example.org/,0',
    'http://192.0.2.1/,0',
    'not-a-valid-url,0'
) -Encoding UTF8
Copy-Item -LiteralPath $fixture -Destination $wrongName

try {
    $evaluator = Join-Path $PSScriptRoot 'evaluate-url-phish-feature-candidates.ps1'
    $metrics = @(& $evaluator -CsvPath $fixture -DomainHoldoutPercent 30)
    $entropy = $metrics | Where-Object Feature -eq 'registered_label_entropy>=4.0'
    if ($entropy.Count -ne 2 -or ($entropy | Measure-Object -Property Rows -Sum).Sum -ne 5 -or
        ($entropy | Measure-Object -Property TP -Sum).Sum -ne 1 -or ($entropy | Measure-Object -Property FP -Sum).Sum -ne 0 -or
        ($entropy | Measure-Object -Property TN -Sum).Sum -ne 4 -or ($entropy | Measure-Object -Property FN -Sum).Sum -ne 0) {
        throw 'Entropy feature metrics do not match the synthetic fixture.'
    }
    $union = $metrics | Where-Object Feature -eq 'engine_or_entropy4'
    if (($union | Measure-Object -Property Rows -Sum).Sum -ne 5) { throw 'Combined detection omitted a fixture row.' }
    $metadata = Get-Item -LiteralPath $fixture
    if (($entropy | Where-Object { $_.DataSha256 -ne (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash -or $_.DataSizeBytes -ne $metadata.Length }).Count -ne 0) {
        throw 'Report does not identify the exact input bytes.'
    }
    $failedAsExpected = $false
    try { $null = @(& $evaluator -CsvPath $wrongName) } catch { $failedAsExpected = $true }
    if (-not $failedAsExpected) { throw 'Feature evaluator accepted a file with an unrecognized name.' }
    Write-Output 'PASS: URL-Phish candidate metrics, domain holdout, combined baseline, input hash, and filename guard'
}
finally { Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force -ErrorAction SilentlyContinue }
