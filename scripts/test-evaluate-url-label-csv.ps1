$ErrorActionPreference = 'Stop'
$fixtureDirectory = Join-Path $env:TEMP ('sentinel-url-label-evaluation-' + [Guid]::NewGuid().ToString('N'))
$fixture = Join-Path $fixtureDirectory 'fixture.csv'
$wrongSplit = Join-Path $fixtureDirectory 'wrong-split.csv'
$badLabel = Join-Path $fixtureDirectory 'bad-label.csv'
[void](New-Item -ItemType Directory -Path $fixtureDirectory)
$headers = 'url,label,split'
Set-Content -LiteralPath $fixture -Encoding UTF8 -Value @($headers,
    'https://example.com/,benign,test',
    'https://paypal.com@attacker.test/login,phish,test')
Set-Content -LiteralPath $wrongSplit -Encoding UTF8 -Value @($headers, 'https://example.com/,benign,train')
Set-Content -LiteralPath $badLabel -Encoding UTF8 -Value @($headers, 'https://example.com/,unknown,test')
try {
    $evaluator = Join-Path $PSScriptRoot 'evaluate-url-label-csv.ps1'
    $result = & $evaluator -CsvPath $fixture -DatasetName 'Synthetic URL fixture' -Split test
    if ($result.Rows -ne 2 -or $result.TP -ne 1 -or $result.FP -ne 0 -or $result.TN -ne 1 -or $result.FN -ne 0 -or $result.URLsOpened -ne 0) {
        throw 'Synthetic URL metrics or offline-only invariant failed.'
    }
    if ($result.DataSizeBytes -ne (Get-Item -LiteralPath $fixture).Length -or $result.DataSha256 -ne (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash) {
        throw 'Evaluation output does not identify exact input bytes.'
    }
    foreach ($path in @($wrongSplit, $badLabel)) {
        $rejected = $false
        try { $null = & $evaluator -CsvPath $path -DatasetName 'Synthetic URL fixture' -Split test } catch { $rejected = $true }
        if (-not $rejected) { throw 'Evaluator accepted a wrong split or unknown label.' }
    }
    Write-Output 'PASS: external URL/label CSV evaluation, split and label guards, byte checksum, and zero URL opens'
}
finally {
    Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
