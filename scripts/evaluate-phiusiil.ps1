param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvPath,
    [ValidateRange(1, 99)]
    [int]$DomainHoldoutPercent = 30,
    [string]$SplitSeed = 'sentinel-f03-domain-holdout-v1'
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
$utf8 = [Text.Encoding]::UTF8
$train = @{ Rows = 0L; Domains = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); TP = 0L; FP = 0L; TN = 0L; FN = 0L; InvalidUrl = 0L }
$holdout = @{ Rows = 0L; Domains = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); TP = 0L; FP = 0L; TN = 0L; FN = 0L; InvalidUrl = 0L }

$parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new((Resolve-Path -LiteralPath $CsvPath).Path, [Text.Encoding]::UTF8, $true)
$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
$parser.SetDelimiters(',')
$parser.HasFieldsEnclosedInQuotes = $true

try {
    $headers = $parser.ReadFields()
    $urlIndex = [Array]::IndexOf($headers, 'URL')
    $labelIndex = [Array]::IndexOf($headers, 'label')
    if ($urlIndex -lt 0 -or $labelIndex -lt 0) {
        throw 'Expected CSV columns URL and label were not found.'
    }

    $engine = [Sentinel.Core.Analysis.ThreatAnalysisEngine]::new(
        [Sentinel.Core.Analysis.UrlAnalyzer]::new($domainNames))
    $timestamp = [DateTimeOffset]::UnixEpoch
    [long]$truePositive = 0
    [long]$falsePositive = 0
    [long]$trueNegative = 0
    [long]$falseNegative = 0
    [long]$invalidUrl = 0
    [long]$rows = 0

    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields()
        if ($null -eq $fields -or $fields.Length -le [Math]::Max($urlIndex, $labelIndex)) {
            throw "Malformed CSV row near record $($rows + 2); no URL values were logged."
        }

        $url = $fields[$urlIndex]
        $label = $fields[$labelIndex]
        if ($label -notin '0', '1') {
            throw "Unexpected label near record $($rows + 2); no URL values were logged."
        }

        $navigation = [Sentinel.Core.Analysis.NavigationSignal]::new($url)
        $context = [Sentinel.Core.Analysis.AnalysisContext]::new('offline-dataset-evaluation', '', $timestamp, $navigation)
        $assessment = $engine.Analyze($context)
        $predictedPhishing = $assessment.Risk -ge [Sentinel.Core.RiskLevel]::Moderate
        $actualPhishing = $label -eq '0' # UCI label 0 = phishing; 1 = legitimate.

        # Assign whole registrable domains using a deterministic hash independent of URL labels and row order.
        $splitUri = $null
        $validForSplit = [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$splitUri) -and $splitUri.Scheme -in @('http', 'https')
        if ($validForSplit) {
            $splitHost = $splitUri.IdnHost.TrimEnd('.').ToLowerInvariant()
            $domainKey = $domainNames.RegistrableDomain($splitHost)
            if ([string]::IsNullOrWhiteSpace($domainKey)) { $domainKey = $splitHost }
        } else {
            $invalidHash = [Security.Cryptography.SHA256]::HashData($utf8.GetBytes("invalid-url`n$url"))
            $domainKey = 'invalid:' + [Convert]::ToHexString($invalidHash)
        }
        $splitHash = [Security.Cryptography.SHA256]::HashData($utf8.GetBytes("$SplitSeed`n$domainKey"))
        $splitBucket = [Convert]::ToUInt32([Convert]::ToHexString($splitHash, 0, 4), 16) % 100
        $partition = if ($splitBucket -lt $DomainHoldoutPercent) { $holdout } else { $train }
        $partition.Rows++
        [void]$partition.Domains.Add($domainKey)
        if ($assessment.Uncertainties -contains 'Podany adres nie jest poprawnym adresem HTTP/HTTPS.') { $partition.InvalidUrl++ }
        if ($actualPhishing) {
            if ($predictedPhishing) { $partition.TP++ } else { $partition.FN++ }
        } else {
            if ($predictedPhishing) { $partition.FP++ } else { $partition.TN++ }
        }

        if ($assessment.Uncertainties -contains 'Podany adres nie jest poprawnym adresem HTTP/HTTPS.') {
            $invalidUrl++
        }
        if ($actualPhishing) {
            if ($predictedPhishing) { $truePositive++ } else { $falseNegative++ }
        } else {
            if ($predictedPhishing) { $falsePositive++ } else { $trueNegative++ }
        }
        $rows++
    }

    [pscustomobject]@{
        Dataset = 'UCI PhiUSIIL (URL column only; webpage features ignored)'
        Rows = $rows
        Phishing = $truePositive + $falseNegative
        Legitimate = $falsePositive + $trueNegative
        InvalidUrl = $invalidUrl
        TP = $truePositive
        FP = $falsePositive
        TN = $trueNegative
        FN = $falseNegative
        Precision = [Math]::Round($truePositive / [Math]::Max(1, $truePositive + $falsePositive), 6)
        Recall = [Math]::Round($truePositive / [Math]::Max(1, $truePositive + $falseNegative), 6)
        FalsePositiveRate = [Math]::Round($falsePositive / [Math]::Max(1, $falsePositive + $trueNegative), 6)
        Threshold = 'Moderate'
        RulesVersion = [Sentinel.Core.Analysis.ThreatAnalysisEngine]::RulesVersion
        URLsOpened = 0
    }
    foreach ($entry in @(@{ Name = 'DomainTrain'; Counts = $train }, @{ Name = 'DomainHoldout'; Counts = $holdout })) {
        $counts = $entry.Counts
        [pscustomobject]@{
            Partition = $entry.Name
            SplitSeed = $SplitSeed
            HoldoutPercent = $DomainHoldoutPercent
            Domains = $counts.Domains.Count
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
        }
    }
}
finally {
    $parser.Close()
}
