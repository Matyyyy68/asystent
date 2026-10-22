$ErrorActionPreference = 'Stop'
$fixtureDirectory = Join-Path $env:TEMP ('sentinel-phishvn-evaluation-' + [Guid]::NewGuid().ToString('N'))
$fixture = Join-Path $fixtureDirectory 'url_test.csv'
$nonTestFixture = Join-Path $fixtureDirectory 'wrong-split.csv'
$otherNameFixture = Join-Path $fixtureDirectory 'not-official-test.csv'
[void](New-Item -ItemType Directory -Path $fixtureDirectory)
$header = 'id,url,label,tier,split'
$testRows = @(
    '1,https://example.test/,benign,gold,test',
    '2,https://login.example.test/account,phishing,silver,test',
    '3,https://payment.example.test/verify,phishing,bronze,test'
)
Set-Content -LiteralPath $fixture -Value (@($header) + $testRows) -Encoding UTF8
Set-Content -LiteralPath $nonTestFixture -Value (@($header) + @('1,https://example.test/,benign,gold,train')) -Encoding UTF8
Set-Content -LiteralPath $otherNameFixture -Value @('id,url,label,tier', '1,https://example.test/,benign,gold') -Encoding UTF8

try {
    $evaluator = Join-Path $PSScriptRoot 'evaluate-phishvn.ps1'
    $result = @(& $evaluator -CsvPath $fixture)
    if ($result.Count -ne 3) { throw 'Expected aggregate and one row per selected gold/silver tier.' }
    $aggregate = $result | Where-Object ConfidenceTier -eq 'gold+silver aggregate'
    if ($aggregate.Rows -ne 2 -or $result.ConfidenceTier -contains 'bronze') {
        throw 'Default evaluation must include gold/silver and exclude bronze.'
    }
    if (($aggregate.TP + $aggregate.FP + $aggregate.TN + $aggregate.FN) -ne $aggregate.Rows) {
        throw 'Aggregate confusion matrix does not account for all selected rows.'
    }
    $withBronze = @(& $evaluator -CsvPath $fixture -Tiers @('gold', 'silver', 'bronze'))
    $bronzeAggregate = $withBronze | Where-Object ConfidenceTier -eq 'gold+silver+bronze aggregate'
    if ($bronzeAggregate.Rows -ne 3) { throw 'Explicit bronze inclusion did not include all fixture rows.' }

    foreach ($invalidPath in @($nonTestFixture, $otherNameFixture)) {
        $failedAsExpected = $false
        try { $null = @(& $evaluator -CsvPath $invalidPath) } catch { $failedAsExpected = $true }
        if (-not $failedAsExpected) { throw 'Evaluator accepted a non-test or unidentified dataset split.' }
    }
    Write-Output 'PASS: PhishVN tier filtering, aggregate confusion matrix, explicit bronze inclusion, and official test-split guard'
}
finally {
    Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
