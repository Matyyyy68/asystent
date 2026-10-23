$ErrorActionPreference = 'Stop'
$fixtureDirectory = Join-Path $env:TEMP ('sentinel-phishvn-brand-tokens-' + [Guid]::NewGuid().ToString('N'))
$trainFixture = Join-Path $fixtureDirectory 'url_train.csv'
$validationFixture = Join-Path $fixtureDirectory 'url_val.csv'
$wrongSplitFixture = Join-Path $fixtureDirectory 'wrong-split.csv'
[void](New-Item -ItemType Directory -Path $fixtureDirectory)
$header = 'domain,label,tier,split'
Set-Content -LiteralPath $trainFixture -Value (@($header) + @(
    'portal.vietcombank.login.test,phishing,gold,train',
    'portal.vietcombank.test,benign,gold,train',
    'acb.test,phishing,silver,train',
    'fakeacb.test,benign,gold,train',
    'campaign.test,phishing,gold,train',
    'momo.test,phishing,bronze,train'
)) -Encoding UTF8
Set-Content -LiteralPath $validationFixture -Value (@($header) + @(
    'campaign.test,phishing,gold,val',
    'www.bidv.test,benign,gold,val',
    'example.test,benign,gold,val'
)) -Encoding UTF8
Set-Content -LiteralPath $wrongSplitFixture -Value (@($header) + @('portal.vietcombank.test,phishing,gold,test')) -Encoding UTF8

try {
    $evaluator = Join-Path $PSScriptRoot 'evaluate-phishvn-brand-tokens.ps1'
    $results = @(& $evaluator -TrainCsvPath $trainFixture -ValidationCsvPath $validationFixture)
    if ($results.Count -ne 2) { throw 'Expected one result for train and one for validation.' }
    $train = $results | Where-Object Split -eq 'train'
    $validation = $results | Where-Object Split -eq 'val'
    if ($train.Rows -ne 5 -or $train.TP -ne 2 -or $train.FP -ne 1 -or $train.FN -ne 1 -or $train.TN -ne 1) {
        throw 'Default tier filtering or exact token-boundary matching failed on train fixture.'
    }
    if ($validation.Rows -ne 3 -or $validation.TP -ne 0 -or $validation.FP -ne 1 -or $validation.TN -ne 1 -or $validation.FN -ne 1) {
        throw 'Validation metrics or split-specific token matching failed.'
    }
    if ($train.DataSha256 -ne (Get-FileHash -LiteralPath $trainFixture -Algorithm SHA256).Hash -or $train.DataSizeBytes -ne (Get-Item -LiteralPath $trainFixture).Length) {
        throw 'Report does not identify the exact train fixture.'
    }
    $failedAsExpected = $false
    try { $null = @(& $evaluator -TrainCsvPath $wrongSplitFixture -ValidationCsvPath $validationFixture) } catch { $failedAsExpected = $true }
    if (-not $failedAsExpected) { throw 'Evaluator accepted rows outside the requested split.' }
    Write-Output 'PASS: fixed domain-token diagnostic, tier filtering, exact boundaries, split guard, and data checksums'
}
finally { Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force -ErrorAction SilentlyContinue }
