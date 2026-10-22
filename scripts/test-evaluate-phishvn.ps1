$ErrorActionPreference = 'Stop'
$fixtureDirectory = Join-Path $env:TEMP ('sentinel-phishvn-evaluation-' + [Guid]::NewGuid().ToString('N'))
$fixture = Join-Path $fixtureDirectory 'url_test.csv'
$validationFixture = Join-Path $fixtureDirectory 'url_val.csv'
$nonTestFixture = Join-Path $fixtureDirectory 'wrong-split.csv'
$otherNameFixture = Join-Path $fixtureDirectory 'not-official-test.csv'
[void](New-Item -ItemType Directory -Path $fixtureDirectory)
$header = 'id,url,label,tier,split'
$testRows = @(
    '1,https://example.test/,benign,gold,test',
    '2,https://login.example.test/account,phishing,silver,test',
    '3,https://payment.example.test/verify,phishing,bronze,test',
    '4,help.example.test/docs,benign,gold,test'
)
Set-Content -LiteralPath $fixture -Value (@($header) + $testRows) -Encoding UTF8
Set-Content -LiteralPath $validationFixture -Value (@($header) + @('5,help.example.test/docs,benign,gold,val')) -Encoding UTF8
Set-Content -LiteralPath $nonTestFixture -Value (@($header) + @('1,https://example.test/,benign,gold,train')) -Encoding UTF8
Set-Content -LiteralPath $otherNameFixture -Value @('id,url,label,tier', '1,https://example.test/,benign,gold') -Encoding UTF8

try {
    $evaluator = Join-Path $PSScriptRoot 'evaluate-phishvn.ps1'
    $result = @(& $evaluator -CsvPath $fixture)
    if ($result.Count -ne 3) { throw 'Expected aggregate and one row per selected gold/silver tier.' }
    $aggregate = $result | Where-Object ConfidenceTier -eq 'gold+silver aggregate'
    if ($aggregate.Rows -ne 3 -or $aggregate.InvalidUrl -ne 0 -or $result.ConfidenceTier -contains 'bronze') {
        throw 'Default evaluation must include gold/silver and exclude bronze.'
    }
    $fixtureMetadata = Get-Item -LiteralPath $fixture
    $fixtureHash = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
    if ($aggregate.DataSizeBytes -ne $fixtureMetadata.Length -or $aggregate.DataSha256 -ne $fixtureHash) {
        throw 'Evaluation report must identify the exact CSV byte size and SHA-256.'
    }
    if (($aggregate.TP + $aggregate.FP + $aggregate.TN + $aggregate.FN) -ne $aggregate.Rows) {
        throw 'Aggregate confusion matrix does not account for all selected rows.'
    }
    $withBronze = @(& $evaluator -CsvPath $fixture -Tiers 'gold,silver,bronze')
    $bronzeAggregate = $withBronze | Where-Object ConfidenceTier -eq 'gold+silver+bronze aggregate'
    if ($bronzeAggregate.Rows -ne 4 -or $bronzeAggregate.InvalidUrl -ne 0) { throw 'Explicit bronze inclusion or scheme-stripped URL parsing failed.' }
    $validation = @(& $evaluator -CsvPath $validationFixture -Split val)
    if (($validation | Where-Object ConfidenceTier -eq 'gold+silver aggregate').Rows -ne 1) {
        throw 'Explicit validation-split evaluation did not accept its matching split.'
    }

    foreach ($invalidPath in @($nonTestFixture, $otherNameFixture)) {
        $failedAsExpected = $false
        try { $null = @(& $evaluator -CsvPath $invalidPath) } catch { $failedAsExpected = $true }
        if (-not $failedAsExpected) { throw 'Evaluator accepted a non-test or unidentified dataset split.' }
    }
    Write-Output 'PASS: PhishVN tier filtering, split guard, aggregate confusion matrix, scheme-stripped URL parsing, and explicit bronze inclusion'
}
finally {
    Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
