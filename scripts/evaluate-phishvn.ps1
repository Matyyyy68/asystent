param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvPath,
    [ValidateSet('train', 'val', 'test')]
    [string]$Split = 'test',
    [string[]]$Tiers = @('gold', 'silver')
)

$ErrorActionPreference = 'Stop'
$requestedTiers = @($Tiers | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() })
$invalidTiers = @($requestedTiers | Where-Object { $_ -notin 'gold', 'silver', 'bronze' })
if ($requestedTiers.Count -eq 0 -or $invalidTiers.Count -gt 0) {
    throw 'Tiers must be a comma- or space-separated combination of gold, silver, and bronze.'
}
$Tiers = @(@('gold', 'silver', 'bronze') | Where-Object { $_ -in $requestedTiers } | Sort-Object -Unique)
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
$csvStream = [IO.FileStream]::new($resolvedCsv, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
$dataSizeBytes = $csvStream.Length
$dataSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($csvStream))
$csvStream.Position = 0
$parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($csvStream, [Text.Encoding]::UTF8, $true)
$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
$parser.SetDelimiters(',')
$parser.HasFieldsEnclosedInQuotes = $true
$counts = @{}
foreach ($tier in $Tiers) {
    $counts[$tier] = @{ Rows = 0L; TP = 0L; FP = 0L; TN = 0L; FN = 0L; InvalidUrl = 0L }
}

try {
    $headers = $parser.ReadFields()
    $urlIndex = [Array]::IndexOf($headers, 'url')
    $labelIndex = [Array]::IndexOf($headers, 'label')
    $tierIndex = [Array]::IndexOf($headers, 'tier')
    $splitIndex = [Array]::IndexOf($headers, 'split')
    if ($urlIndex -lt 0 -or $labelIndex -lt 0 -or $tierIndex -lt 0) {
        throw 'Expected PhishVN CSV columns url, label, and tier were not found.'
    }
    if ($splitIndex -lt 0 -and [IO.Path]::GetFileName($resolvedCsv) -cne "url_$Split.csv") {
        throw "Input must be the official url_$Split.csv file or include a split column identifying every row as $Split."
    }

    [long]$record = 1
    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields()
        $record++
        if ($null -eq $fields -or $fields.Length -le [Math]::Max($urlIndex, [Math]::Max($labelIndex, $tierIndex))) {
            throw "Malformed PhishVN CSV row near record $record; no URL values were logged."
        }
        if ($splitIndex -ge 0 -and ($fields.Length -le $splitIndex -or $fields[$splitIndex] -cne $Split)) {
            throw "Input contains a row outside the requested $Split split near record $record; no URL values were logged."
        }

        $tier = $fields[$tierIndex].ToLowerInvariant()
        $label = $fields[$labelIndex].ToLowerInvariant()
        if ($tier -notin 'gold', 'silver', 'bronze') {
            throw "Unexpected confidence tier near record $record; no URL values were logged."
        }
        if ($label -notin 'phishing', 'benign') {
            throw "Unexpected label near record $record; no URL values were logged."
        }
        if ($tier -notin $Tiers) { continue }

        $url = $fields[$urlIndex]
        # PhishVN includes scheme-stripped URLs. Add HTTPS only as a parser prefix;
        # the dataset does not establish the actual transport scheme for these rows.
        $analysisUrl = if ($url -match '^[A-Za-z][A-Za-z0-9+.-]*://') { $url } else { 'https://' + $url }
        $navigation = [Sentinel.Core.Analysis.NavigationSignal]::new($analysisUrl)
        $context = [Sentinel.Core.Analysis.AnalysisContext]::new("offline-phishvn-$Split-evaluation", '', $timestamp, $navigation)
        $assessment = $engine.Analyze($context)
        $predictedPhishing = $assessment.Risk -ge [Sentinel.Core.RiskLevel]::Moderate
        $actualPhishing = $label -eq 'phishing'
        $bucket = $counts[$tier]
        $bucket.Rows++
        if ($assessment.Uncertainties -contains 'Podany adres nie jest poprawnym adresem HTTP/HTTPS.') { $bucket.InvalidUrl++ }
        if ($actualPhishing) {
            if ($predictedPhishing) { $bucket.TP++ } else { $bucket.FN++ }
        } else {
            if ($predictedPhishing) { $bucket.FP++ } else { $bucket.TN++ }
        }
    }

    $selected = @(@('gold', 'silver', 'bronze') | Where-Object { $_ -in $Tiers })
    $total = @{ Rows = 0L; TP = 0L; FP = 0L; TN = 0L; FN = 0L; InvalidUrl = 0L }
    foreach ($tier in $selected) {
        foreach ($key in @('Rows', 'TP', 'FP', 'TN', 'FN', 'InvalidUrl')) { $total[$key] += $counts[$tier][$key] }
    }
    if ($total.Rows -eq 0) { throw "The official $Split split has no rows in the selected confidence tiers." }

    $aggregateName = [string]::Join('+', $selected) + ' aggregate'
    foreach ($entry in @(@{ Tier = $aggregateName; Counts = $total }) + @($selected | ForEach-Object { @{ Tier = $_; Counts = $counts[$_] } })) {
        $item = $entry.Counts
        [pscustomobject]@{
            Dataset = "PhishVN v3.1.0 official temporal/group-domain $Split split"
            ConfidenceTier = $entry.Tier
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
