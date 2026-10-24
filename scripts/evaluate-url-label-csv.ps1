param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvPath,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DatasetName,
    [Parameter(Mandatory = $true)]
    [ValidateSet('train', 'validation', 'test')]
    [string]$Split = 'test',
    [string[]]$PhishingLabels = @('phish', 'phishing')
)

$ErrorActionPreference = 'Stop'
if ($DatasetName.Length -gt 120 -or $DatasetName -match '[\x00-\x1f]') { throw 'DatasetName must be a short, printable label.' }
$normalizedPhishingLabels = @($PhishingLabels | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
if ($normalizedPhishingLabels.Count -eq 0 -or @($normalizedPhishingLabels | Where-Object { $_ -notin 'phish', 'phishing' }).Count -gt 0) {
    throw 'PhishingLabels may contain only phish and phishing.'
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$coreAssembly = Join-Path $repositoryRoot 'src\Sentinel.Core\bin\Release\net10.0\Sentinel.Core.dll'
if (-not (Test-Path -LiteralPath $coreAssembly -PathType Leaf)) { throw 'Build Sentinel.Core first with: dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release' }
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -Path $coreAssembly
$engine = [Sentinel.Core.Analysis.ThreatAnalysisEngine]::new([Sentinel.Core.Analysis.UrlAnalyzer]::new([Sentinel.Core.Analysis.DomainNames]::new()))
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
$counts = @{ Rows = 0L; TP = 0L; FP = 0L; TN = 0L; FN = 0L; InvalidUrl = 0L }

try {
    $headers = $parser.ReadFields()
    $urlIndex = [Array]::IndexOf($headers, 'url')
    $labelIndex = [Array]::IndexOf($headers, 'label')
    $splitIndex = [Array]::IndexOf($headers, 'split')
    if ($urlIndex -lt 0 -or $labelIndex -lt 0 -or $splitIndex -lt 0) { throw 'Expected CSV columns url, label, and split were not found.' }
    [long]$record = 1
    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields()
        $record++
        if ($null -eq $fields -or $fields.Length -le [Math]::Max($urlIndex, [Math]::Max($labelIndex, $splitIndex))) {
            throw "Malformed row near record $record; no URL values were logged."
        }
        if ($fields[$splitIndex] -cne $Split) { throw "Input contains a row outside the requested $Split split near record $record; no URL values were logged." }
        $label = $fields[$labelIndex].Trim().ToLowerInvariant()
        if ($label -ne 'benign' -and $label -notin $normalizedPhishingLabels) { throw "Unexpected label near record $record; no URL values were logged." }
        $url = $fields[$urlIndex]
        $analysisUrl = if ($url -match '^[A-Za-z][A-Za-z0-9+.-]*://') { $url } else { 'https://' + $url }
        $navigation = [Sentinel.Core.Analysis.NavigationSignal]::new($analysisUrl)
        $context = [Sentinel.Core.Analysis.AnalysisContext]::new("offline-$Split-evaluation", '', $timestamp, $navigation)
        $assessment = $engine.Analyze($context)
        $predictedPhishing = $assessment.Risk -ge [Sentinel.Core.RiskLevel]::Moderate
        $actualPhishing = $label -in $normalizedPhishingLabels
        $counts.Rows++
        if ($assessment.Uncertainties -contains 'Podany adres nie jest poprawnym adresem HTTP/HTTPS.') { $counts.InvalidUrl++ }
        if ($actualPhishing) {
            if ($predictedPhishing) { $counts.TP++ } else { $counts.FN++ }
        } else {
            if ($predictedPhishing) { $counts.FP++ } else { $counts.TN++ }
        }
    }

    if ($counts.Rows -eq 0) { throw "The $Split split contains no rows." }
    [pscustomobject]@{
        Dataset = $DatasetName
        Split = $Split
        Rows = $counts.Rows
        InvalidUrl = $counts.InvalidUrl
        TP = $counts.TP
        FP = $counts.FP
        TN = $counts.TN
        FN = $counts.FN
        Precision = [Math]::Round($counts.TP / [Math]::Max(1, $counts.TP + $counts.FP), 6)
        Recall = [Math]::Round($counts.TP / [Math]::Max(1, $counts.TP + $counts.FN), 6)
        FalsePositiveRate = [Math]::Round($counts.FP / [Math]::Max(1, $counts.FP + $counts.TN), 6)
        Threshold = 'Moderate'
        RulesVersion = [Sentinel.Core.Analysis.ThreatAnalysisEngine]::RulesVersion
        URLsOpened = 0
        DataFile = [IO.Path]::GetFileName($resolvedCsv)
        DataSizeBytes = $dataSizeBytes
        DataSha256 = $dataSha256
    }
}
finally {
    $parser.Close()
}
