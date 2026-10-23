$ErrorActionPreference = 'Stop'
$fixtureDirectory = Join-Path $env:TEMP ('sentinel-cert-feed-eval-guard-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $fixtureDirectory)
try {
    $trainFixture = Join-Path $fixtureDirectory 'url_train.csv'
    $validationFixture = Join-Path $fixtureDirectory 'url_val.csv'
    $testFixture = Join-Path $fixtureDirectory 'url_test.csv'
    Set-Content -LiteralPath $trainFixture -Value 'url,label,tier,split' -Encoding UTF8
    Set-Content -LiteralPath $validationFixture -Value 'url,label,tier,split' -Encoding UTF8
    Set-Content -LiteralPath $testFixture -Value 'url,label,tier,split' -Encoding UTF8

    $evaluator = Join-Path $PSScriptRoot 'evaluate-phishvn-cert-feed.ps1'
    $source = Get-Content -LiteralPath $evaluator -Raw
    $networkUpdate = $source.IndexOf('$reputation.UpdateAsync()', [StringComparison]::Ordinal)
    $inputGuard = $source.IndexOf('Input checksum does not match', [StringComparison]::Ordinal)
    if ($networkUpdate -lt 0 -or $inputGuard -lt 0 -or $inputGuard -gt $networkUpdate) {
        throw 'Official split checksum validation must occur before the CERT network update.'
    }
    if ($source -notmatch 'test split is not accepted' -or $source -notmatch 'URLsOpened = 0' -or $source -match 'Invoke-WebRequest|Invoke-RestMethod|Resolve-DnsName|HttpClient') {
        throw 'Evaluator must reject test data, report that URLs are not opened, and avoid URL/DNS requests.'
    }

    $failedAsExpected = $false
    try { $null = @(& $evaluator -TrainCsvPath $testFixture -ValidationCsvPath $validationFixture) } catch { $failedAsExpected = $true }
    if (-not $failedAsExpected) { throw 'Evaluator accepted a test split.' }

    $failedAsExpected = $false
    try { $null = @(& $evaluator -TrainCsvPath $trainFixture -ValidationCsvPath $validationFixture) } catch { $failedAsExpected = $true }
    if (-not $failedAsExpected) { throw 'Evaluator accepted files without the official train/validation checksums.' }
    Write-Output 'PASS: only checksum-pinned PhishVN train/validation can reach the CERT fetch; test split is rejected.'
}
finally { Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force -ErrorAction SilentlyContinue }
