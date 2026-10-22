param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvPath,
    [ValidateSet('gold', 'silver', 'bronze')]
    [string[]]$Tiers = @('gold', 'silver')
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
$parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($resolvedCsv, [Text.Encoding]::UTF8, $true)
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
    if ($splitIndex -lt 0 -and [IO.Path]::GetFileName($resolvedCsv) -cne 'url_test.csv') {
        throw 'Input must be the official url_test.csv file or include a split column identifying every row as test.'
    }

    [long]$record = 1
    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields()
        $record++
        if ($null -eq $fields -or $fields.Length -le [Math]::Max($urlIndex, [Math]::Max($labelIndex, $tierIndex))) {
            throw "Malformed PhishVN CSV row near record $record; no URL values were logged."
        }
        if ($splitIndex -ge 0 -and ($fields.Length -le $splitIndex -or $fields[$splitIndex] -cne 'test')) {
            throw "Input contains a non-test row near record $record; no URL values were logged."
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
        $navigation = [Sentinel.Core.Analysis.NavigationSignal]::new($url)
        $context = [Sentinel.Core.Analysis.AnalysisContext]::new('offline-phishvn-test-evaluation', '', $timestamp, $navigation)
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
    if ($total.Rows -eq 0) { throw 'The official test split has no rows in the selected confidence tiers.' }

    $aggregateName = [string]::Join('+', $selected) + ' aggregate'
    foreach ($entry in @(@{ Tier = $aggregateName; Counts = $total }) + @($selected | ForEach-Object { @{ Tier = $_; Counts = $counts[$_] } })) {
        $item = $entry.Counts
        [pscustomobject]@{
            Dataset = 'PhishVN v3.1.0 official temporal/group-domain test split'
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
        }
    }
}
finally {
    $parser.Close()
}
