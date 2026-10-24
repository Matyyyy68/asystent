param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$expectedSourceSha256 = 'FCCCE1A99282B3CD8A1FE08FA83350FE44F7AFC4C8889A6D0A94EF9C4D7897E3'
$expectedRows = 149726L
$expectedBenign = 94919L
$expectedPhishing = 54807L
$splitSeed = 'sentinel-mendeley-3jddhy2f6s-v1-domain-v1'
# Mendeley reports class totals but not the numeric mapping. The CSV's exact
# counts match the page's legitimate/phishing totals, so 0=benign, 1=phish is an explicit inference.

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$coreAssembly = Join-Path $repositoryRoot 'src\Sentinel.Core\bin\Release\net10.0\Sentinel.Core.dll'
if (-not (Test-Path -LiteralPath $coreAssembly -PathType Leaf)) {
    throw 'Build Sentinel.Core first with: dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release'
}
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -Path $coreAssembly

$resolvedCsv = (Resolve-Path -LiteralPath $CsvPath).Path
$sourceSha256 = (Get-FileHash -LiteralPath $resolvedCsv -Algorithm SHA256).Hash
if ($sourceSha256 -cne $expectedSourceSha256) {
    throw 'Input checksum does not match the pinned Mendeley Data v1 CSV; no URL values were logged.'
}

$tempRoot = Join-Path $env:TEMP ('sentinel-mendeley-url-evaluation-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $tempRoot)
$preparedCsv = Join-Path $tempRoot 'prepared.csv'
$inputStream = [IO.FileStream]::new($resolvedCsv, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
$parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($inputStream, [Text.Encoding]::UTF8, $true)
$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
$parser.SetDelimiters(',')
$parser.HasFieldsEnclosedInQuotes = $true
$writer = [IO.StreamWriter]::new($preparedCsv, $false, [Text.UTF8Encoding]::new($false))
$domainNames = [Sentinel.Core.Analysis.DomainNames]::new()
$seenUrlHashes = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$domainSplits = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$trainDomains = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$testDomains = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$labelCounts = @{ '0' = 0L; '1' = 0L }
$splitRows = @{ train = 0L; test = 0L }
$duplicateRows = 0L
$recordCount = 0L

function Get-Sha256Hex([string]$Value) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value)))
}

function Get-CsvField([string]$Value) {
    '"' + $Value.Replace('"', '""') + '"'
}

try {
    $headers = $parser.ReadFields()
    if ($headers.Length -ne 2 -or $headers[0] -cne 'URL' -or $headers[1] -cne 'Label') {
        throw 'Expected exact CSV headers URL,Label; no URL values were logged.'
    }
    $writer.WriteLine('url,label,split')

    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields()
        if ($null -eq $fields -or $fields.Length -ne 2) { throw 'Malformed source record; no URL values were logged.' }
        $recordCount++
        $url = $fields[0].Trim()
        $sourceLabel = $fields[1].Trim()
        if ($sourceLabel -notin '0', '1' -or $url.Length -eq 0) { throw 'Invalid source row; no URL values were logged.' }
        $labelCounts[$sourceLabel]++
        $urlHash = Get-Sha256Hex $url
        if ($seenUrlHashes.ContainsKey($urlHash)) {
            if ($seenUrlHashes[$urlHash] -cne $sourceLabel) { throw 'Duplicate URL has conflicting labels; no URL values were logged.' }
            $duplicateRows++
            continue
        }
        $seenUrlHashes.Add($urlHash, $sourceLabel)

        $urlForParsing = if ($url -match '^[A-Za-z][A-Za-z0-9+.-]*://') { $url } else { 'https://' + $url }
        $registrableDomain = $null
        $parsedUri = $null
        try {
            if ([Uri]::TryCreate($urlForParsing, [UriKind]::Absolute, [ref]$parsedUri) -and
                $parsedUri.Scheme -in 'http', 'https' -and -not [string]::IsNullOrWhiteSpace($parsedUri.Host)) {
                $registrableDomain = $domainNames.RegistrableDomain($parsedUri.IdnHost)
            }
        } catch { $registrableDomain = $null }
        $domainKey = if ([string]::IsNullOrWhiteSpace($registrableDomain)) { 'invalid:' + $urlHash } else { $registrableDomain }
        if (-not $domainSplits.ContainsKey($domainKey)) {
            $bucketHash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($splitSeed + '|' + $domainKey))
            $bucket = [BitConverter]::ToUInt32($bucketHash, 0) % 10
            $domainSplits.Add($domainKey, $(if ($bucket -lt 3) { 'test' } else { 'train' }))
        }
        $split = $domainSplits[$domainKey]
        if ($split -eq 'train') { [void]$trainDomains.Add($domainKey) } else { [void]$testDomains.Add($domainKey) }
        $splitRows[$split]++
        $label = if ($sourceLabel -eq '1') { 'phish' } else { 'benign' }
        if ($split -eq 'test') { $writer.WriteLine((Get-CsvField $url) + ',' + $label + ',test') }
    }
    $writer.Flush()
    $writer.Dispose()
    $writer = $null

    if ($recordCount -ne $expectedRows -or $labelCounts['0'] -ne $expectedBenign -or $labelCounts['1'] -ne $expectedPhishing) {
        throw 'Source row counts do not match the pinned public dataset metadata; no URL values were logged.'
    }
    $domainOverlap = @($trainDomains | Where-Object { $testDomains.Contains($_) }).Count
    if ($domainOverlap -ne 0) { throw 'Registrable-domain split overlap detected.' }

    $evaluator = Join-Path $repositoryRoot 'scripts\evaluate-url-label-csv.ps1'
    $metrics = & $evaluator -CsvPath $preparedCsv -DatasetName 'Mendeley Phishing URL dataset v1, deterministic domain holdout' -Split test -PhishingLabels @('phish')
    [pscustomobject]@{
        Dataset = 'Mendeley Phishing URL dataset v1 (10.17632/3jddhy2f6s.1)'
        SourceSha256 = $sourceSha256
        SourceRows = $recordCount
        SourceBenignLabel0 = $labelCounts['0']
        SourcePhishingLabel1 = $labelCounts['1']
        LabelMapping = '0=benign,1=phish (inferred from exact match to Mendeley class totals)'
        DuplicateRowsSkipped = $duplicateRows
        SplitSeed = $splitSeed
        DomainGroups = $domainSplits.Count
        TrainDomains = $trainDomains.Count
        TestDomains = $testDomains.Count
        DomainOverlap = $domainOverlap
        TrainRows = $splitRows.train
        TestRows = $splitRows.test
        Evaluation = $metrics
    }
}
finally {
    if ($null -ne $writer) { $writer.Dispose() }
    $parser.Close()
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
