param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvPath,
    [ValidateRange(1, 99)]
    [int]$DomainHoldoutPercent = 30,
    [string]$SplitSeed = 'sentinel-url-phish-domain-v1'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$coreAssembly = Join-Path $repositoryRoot 'src\Sentinel.Core\bin\Release\net10.0\Sentinel.Core.dll'
if (-not (Test-Path -LiteralPath $coreAssembly -PathType Leaf)) {
    throw 'Build Sentinel.Core first with: dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release'
}

Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -Path $coreAssembly
$domainNames = [Sentinel.Core.Analysis.DomainNames]::new()
$engine = [Sentinel.Core.Analysis.ThreatAnalysisEngine]::new(
    [Sentinel.Core.Analysis.UrlAnalyzer]::new($domainNames))
$timestamp = [DateTimeOffset]::UnixEpoch
$resolvedCsv = (Resolve-Path -LiteralPath $CsvPath).Path
$stream = [IO.FileStream]::new($resolvedCsv, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
if ($stream.Length -gt 100MB) { $stream.Dispose(); throw 'URL-Phish CSV exceeds the 100 MiB evaluation limit.' }
$dataSizeBytes = $stream.Length
$dataSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream))
$stream.Position = 0
$parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($stream, [Text.Encoding]::UTF8, $true)
$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
$parser.SetDelimiters(',')
$parser.HasFieldsEnclosedInQuotes = $true
$utf8 = [Text.Encoding]::UTF8
$partitions = @{
    DomainTrain = @{ Rows = 0L; Domains = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); TP = 0L; FP = 0L; TN = 0L; FN = 0L; InvalidUrl = 0L }
    DomainHoldout = @{ Rows = 0L; Domains = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); TP = 0L; FP = 0L; TN = 0L; FN = 0L; InvalidUrl = 0L }
}

try {
    $headers = $parser.ReadFields()
    $urlIndex = [Array]::IndexOf($headers, 'url')
    $labelIndex = [Array]::IndexOf($headers, 'label')
    if ($urlIndex -lt 0 -or $labelIndex -lt 0) {
        throw 'Expected URL-Phish CSV columns url and label were not found.'
    }

    [long]$record = 1
    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields()
        $record++
        if ($null -eq $fields -or $fields.Length -le [Math]::Max($urlIndex, $labelIndex)) {
            throw "Malformed URL-Phish CSV row near record $record; URL values are omitted."
        }
        $label = $fields[$labelIndex]
        if ($label -notin '0', '1') { throw "Unexpected label near record $record; URL values are omitted." }

        $url = $fields[$urlIndex]
        $uri = $null
        $validUrl = [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$uri) -and $uri.Scheme -in @('http', 'https')
        if ($validUrl) {
            $urlHost = $uri.IdnHost.TrimEnd('.').ToLowerInvariant()
            $domainKey = $domainNames.RegistrableDomain($urlHost)
            if ([string]::IsNullOrWhiteSpace($domainKey)) { $domainKey = $urlHost }
            $analysisUrl = $url
        } else {
            $invalidHash = [Security.Cryptography.SHA256]::HashData($utf8.GetBytes("invalid-url`n$url"))
            $domainKey = 'invalid:' + [Convert]::ToHexString($invalidHash)
            $analysisUrl = $url
        }
        $splitHash = [Security.Cryptography.SHA256]::HashData($utf8.GetBytes("$SplitSeed`n$domainKey"))
        $bucket = [Convert]::ToUInt32([Convert]::ToHexString($splitHash, 0, 4), 16) % 100
        $partitionName = if ($bucket -lt $DomainHoldoutPercent) { 'DomainHoldout' } else { 'DomainTrain' }
        $partition = $partitions[$partitionName]
        [void]$partition.Domains.Add($domainKey)
        $context = [Sentinel.Core.Analysis.AnalysisContext]::new('offline-url-phish-evaluation', '', $timestamp,
            [Sentinel.Core.Analysis.NavigationSignal]::new($analysisUrl))
        $assessment = $engine.Analyze($context)
        $predictedPhishing = $assessment.Risk -ge [Sentinel.Core.RiskLevel]::Moderate
        $actualPhishing = $label -eq '1'
        $partition.Rows++
        if (-not $validUrl) { $partition.InvalidUrl++ }
        if ($actualPhishing) {
            if ($predictedPhishing) { $partition.TP++ } else { $partition.FN++ }
        } else {
            if ($predictedPhishing) { $partition.FP++ } else { $partition.TN++ }
        }
    }

    $overlap = @($partitions.DomainTrain.Domains | Where-Object { $partitions.DomainHoldout.Domains.Contains($_) })
    if ($overlap.Count -gt 0) { throw 'Registrable-domain leakage found between evaluation partitions.' }
    foreach ($name in @('DomainTrain', 'DomainHoldout')) {
        $item = $partitions[$name]
        [pscustomobject]@{
            Dataset = 'URL-Phish v1 (URL-only, no feed, deterministic registrable-domain partition)'
            Partition = $name
            SplitSeed = $SplitSeed
            HoldoutPercent = $DomainHoldoutPercent
            Domains = $item.Domains.Count
            Rows = $item.Rows
            InvalidUrl = $item.InvalidUrl
            TP = $item.TP
            FP = $item.FP
            TN = $item.TN
            FN = $item.FN
            Precision = [Math]::Round($item.TP / [Math]::Max(1, $item.TP + $item.FP), 6)
            Recall = [Math]::Round($item.TP / [Math]::Max(1, $item.TP + $item.FN), 6)
            FalsePositiveRate = [Math]::Round($item.FP / [Math]::Max(1, $item.FP + $item.TN), 6)
            Threshold = 'Moderate'
            RulesVersion = [Sentinel.Core.Analysis.ThreatAnalysisEngine]::RulesVersion
            URLsOpened = 0
            DataFile = [IO.Path]::GetFileName($resolvedCsv)
            DataSizeBytes = $dataSizeBytes
            DataSha256 = $dataSha256
        }
    }
}
finally {
    $parser.Close()
}
