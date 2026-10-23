$ErrorActionPreference = 'Stop'
$evaluator = Join-Path $PSScriptRoot 'evaluate-phishvn-brand-candidates.ps1'
$source = Get-Content -LiteralPath $evaluator -Raw
if ($source -notmatch "ValidateSet\('train', 'val'\)" -or
    $source -notmatch 'url_\$Split\.csv' -or
    $source -notmatch '568E788EDA4BDF62531ADCDDD093373EF6A1E97FEEC1354063AE337325367B61' -or
    $source -notmatch 'D9EF64D29DF6639AF698EF228E5AF5EC6F8AE44C8F1A1DD1367F9BA6D073D81F' -or
    $source -notmatch '\$fields\[\$splitIndex\] -cne \$Split') {
    throw 'Brand candidate evaluator must pin official train/validation data and reject other splits.'
}

$fixtureDirectory = Join-Path $env:TEMP ('sentinel-phishvn-brand-candidates-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $fixtureDirectory)
$testFixture = Join-Path $fixtureDirectory 'url_test.csv'
$wrongSplitFixture = Join-Path $fixtureDirectory 'url_val.csv'
Set-Content -LiteralPath $testFixture -Value @('url,label,tier,split','https://amazon-login.example.test/,phishing,gold,test') -Encoding UTF8
Set-Content -LiteralPath $wrongSplitFixture -Value @('url,label,tier,split','https://amazon-login.example.test/,phishing,gold,train') -Encoding UTF8
try {
    $rejectedTest = $false
    try { $null = @(& $evaluator -CsvPath $testFixture -Split test) } catch { $rejectedTest = $true }
    if (-not $rejectedTest) { throw 'Brand candidate evaluator accepted the test split.' }

    $rejectedWrongFile = $false
    try { $null = @(& $evaluator -CsvPath $wrongSplitFixture -Split train) } catch { $rejectedWrongFile = $true }
    if (-not $rejectedWrongFile) { throw 'Brand candidate evaluator accepted a file with the wrong split name.' }
    Write-Output 'PASS: brand candidate evaluator pins train/validation checksums and rejects the test split.'
}
finally { Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force -ErrorAction SilentlyContinue }
