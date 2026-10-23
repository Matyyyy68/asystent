$ErrorActionPreference = 'Stop'
$fixtureDirectory = Join-Path $env:TEMP ('sentinel-phishvn-feature-scan-' + [Guid]::NewGuid().ToString('N'))
$trainFixture = Join-Path $fixtureDirectory 'url_train.csv'
$validationFixture = Join-Path $fixtureDirectory 'url_val.csv'
$testFixture = Join-Path $fixtureDirectory 'url_test.csv'
[void](New-Item -ItemType Directory -Path $fixtureDirectory)
$wrongSplitDirectory = Join-Path $fixtureDirectory 'wrong-split'
[void](New-Item -ItemType Directory -Path $wrongSplitDirectory)
$wrongSplitFixture = Join-Path $wrongSplitDirectory 'url_train.csv'
$header = 'id,url,label,tier,split'
Set-Content -LiteralPath $trainFixture -Value (@($header) + @(
    '1,login.123456.example.test/a,phishing,gold,train',
    '2,https://safe.example.test/,benign,gold,train',
    '3,https://aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test/,phishing,silver,train',
    '4,https://ordinary.example.test/,benign,silver,train',
    '5,777777.example.test/a,phishing,bronze,train',
    '6,https://abcdefghijklmnopqrstuvwxyz.com/,phishing,gold,train',
    '7,https://qqqqqqqqqqqqqqqqqq.example.com/,benign,gold,train'
)) -Encoding UTF8
Set-Content -LiteralPath $validationFixture -Value (@($header) + @(
    '6,verify.example.test/login,phishing,gold,val',
    '7,https://ordinary.example.test/,benign,gold,val'
)) -Encoding UTF8
Set-Content -LiteralPath $testFixture -Value (@($header) + @('8,123456.example.test/a,phishing,gold,test')) -Encoding UTF8
Set-Content -LiteralPath $wrongSplitFixture -Value (@($header) + @('9,123456.example.test/a,phishing,gold,val')) -Encoding UTF8

try {
    $evaluator = Join-Path $PSScriptRoot 'evaluate-phishvn-feature-candidates.ps1'
    $train = @(& $evaluator -CsvPath $trainFixture -Split train)
    $aggregate = $train | Where-Object ConfidenceTier -eq 'gold+silver aggregate'
    if ($aggregate.Count -ne 30 -or @($train | Where-Object ConfidenceTier -eq 'bronze').Count -ne 0) {
        throw 'Default tiers must include aggregate and separate gold/silver rows, and exclude bronze.'
    }
    $digitMetric = $aggregate | Where-Object Feature -eq 'digits>=4'
    if ($digitMetric.Rows -ne 6 -or $digitMetric.TP -ne 1 -or $digitMetric.FP -ne 0 -or $digitMetric.TN -ne 3 -or $digitMetric.FN -ne 2) {
        throw 'Digit candidate confusion matrix or tier filtering failed.'
    }
    $longLabelMetric = $aggregate | Where-Object Feature -eq 'long_label>=25'
    if ($longLabelMetric.TP -ne 2 -or $longLabelMetric.FP -ne 0 -or $longLabelMetric.TN -ne 3 -or $longLabelMetric.FN -ne 1) {
        throw 'Long-label candidate or scheme-stripped URL parsing failed.'
    }
    $hostTokenMetric = $aggregate | Where-Object Feature -eq 'auth_token_in_host'
    if ($hostTokenMetric.TP -ne 1 -or $hostTokenMetric.FP -ne 0 -or $hostTokenMetric.TN -ne 3 -or $hostTokenMetric.FN -ne 2) {
        throw 'Host-only authentication-token feature failed.'
    }
    $entropyMetric = $aggregate | Where-Object Feature -eq 'registered_label_entropy>=4.0'
    if ($entropyMetric.Rows -ne 6 -or $entropyMetric.TP -ne 1 -or $entropyMetric.FP -ne 0 -or $entropyMetric.TN -ne 3 -or $entropyMetric.FN -ne 2) {
        throw 'Registrable-label entropy candidate failed.'
    }
    $trainMetadata = Get-Item -LiteralPath $trainFixture
    if ($digitMetric.DataSizeBytes -ne $trainMetadata.Length -or $digitMetric.DataSha256 -ne (Get-FileHash -LiteralPath $trainFixture -Algorithm SHA256).Hash) {
        throw 'Report does not identify the exact input bytes.'
    }
    $validation = @(& $evaluator -CsvPath $validationFixture -Split val)
    $validationAggregate = $validation | Where-Object ConfidenceTier -eq 'gold+silver aggregate'
    if ($validationAggregate.Count -ne 30 -or ($validationAggregate | Where-Object Feature -eq 'auth_token').TP -ne 1) {
        throw 'Explicit validation evaluation failed.'
    }

    foreach ($invalidPath in @($testFixture, $wrongSplitFixture)) {
        $failedAsExpected = $false
        try { $null = @(& $evaluator -CsvPath $invalidPath -Split train) } catch { $failedAsExpected = $true }
        if (-not $failedAsExpected) { throw 'Feature scanner accepted test data or rows outside the requested split.' }
    }
    Write-Output 'PASS: URL feature metrics, aggregate tiers, checksums, validation mode, and test-split guards'
}
finally { Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force -ErrorAction SilentlyContinue }
