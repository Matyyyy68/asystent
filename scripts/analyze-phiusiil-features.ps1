param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$coreAssembly = Join-Path $repositoryRoot 'src\Sentinel.Core\bin\Release\net10.0\Sentinel.Core.dll'
if (-not (Test-Path -LiteralPath $coreAssembly -PathType Leaf)) {
    throw 'Build Sentinel.Core first with: dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release'
}

Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -Path $coreAssembly

$featureNames = @('length75', 'length120', 'length200', 'host30', 'host50', 'hostLabels4', 'hostLabels5',
    'hyphens3', 'digits6', 'queryPairs4', 'pathSlashes4', 'authPath')
$counts = @{}
foreach ($name in $featureNames) { $counts[$name] = [long[]]::new(2) }
$compoundCounts = @{}
foreach ($threshold in 1..7) { $compoundCounts[$threshold] = [long[]]::new(2) }
$dimensionCounts = @{}
foreach ($threshold in 3..4) { $dimensionCounts[$threshold] = [long[]]::new(2) }

$parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new((Resolve-Path -LiteralPath $CsvPath).Path, [Text.Encoding]::UTF8, $true)
$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
$parser.SetDelimiters(',')
$parser.HasFieldsEnclosedInQuotes = $true

try {
    $headers = $parser.ReadFields()
    $urlIndex = [Array]::IndexOf($headers, 'URL')
    $labelIndex = [Array]::IndexOf($headers, 'label')
    if ($urlIndex -lt 0 -or $labelIndex -lt 0) { throw 'Expected CSV columns URL and label were not found.' }

    $analyzer = [Sentinel.Core.Analysis.UrlAnalyzer]::new([Sentinel.Core.Analysis.DomainNames]::new())
    [long]$truePositive = 0
    [long]$falsePositive = 0
    [long]$trueNegative = 0
    [long]$falseNegative = 0
    [long]$rows = 0

    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields()
        if ($null -eq $fields -or $fields.Length -le [Math]::Max($urlIndex, $labelIndex)) {
            throw "Malformed CSV row near record $($rows + 2); no URL values were logged."
        }
        $url = $fields[$urlIndex]
        $label = $fields[$labelIndex]
        if ($label -notin '0', '1') { throw "Unexpected label near record $($rows + 2); no URL values were logged." }

        $analysis = $analyzer.Analyze($url)
        $score = 0
        foreach ($indicator in $analysis.Indicators) { $score += $indicator.Weight }
        $alert = $score -ge 3
        $phishing = $label -eq '0'
        if ($phishing -and $alert) { $truePositive++ }
        elseif ($phishing) { $falseNegative++ }
        elseif ($alert) { $falsePositive++ }
        else { $trueNegative++ }

        $uri = $null
        $valid = [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$uri) -and $uri.Scheme -in @('http', 'https')
        if ($valid) {
            $uriHost = $uri.Host
            $pathAndQuery = $uri.PathAndQuery
            $absolutePath = $uri.AbsolutePath
            $hostLabels = $uriHost.Split('.').Length
            $queryPairs = if ($uri.Query.Length -gt 1) { ([regex]::Matches($uri.Query, '&')).Count + 1 } else { 0 }
            $authPath = $pathAndQuery -match '(?i)(^|[/?&=._-])(?:login|log-in|signin|sign-in|verify|verification|account|password|auth|payment|wallet)(?=$|[/?&=._-])'
            $flags = @(
                ($url.Length -ge 75),
                ($url.Length -ge 120),
                ($url.Length -ge 200),
                ($uriHost.Length -ge 30),
                ($uriHost.Length -ge 50),
                ($hostLabels -ge 4),
                ($hostLabels -ge 5),
                (([regex]::Matches($uriHost, '-')).Count -ge 3),
                (([regex]::Matches($pathAndQuery, '\d')).Count -ge 6),
                ($queryPairs -ge 4),
                (([regex]::Matches($absolutePath, '/')).Count -ge 4),
                $authPath
            )
            for ($index = 0; $index -lt $featureNames.Length; $index++) {
                if (-not $flags[$index] -or $alert) { continue }
                if ($phishing) { $counts[$featureNames[$index]][0]++ }
                else { $counts[$featureNames[$index]][1]++ }
            }
            if (-not $alert) {
                $structuralCount = 0
                foreach ($index in @(0, 4, 6, 7, 8, 9, 10)) {
                    if ($flags[$index]) { $structuralCount++ }
                }
                for ($threshold = 1; $threshold -le $structuralCount; $threshold++) {
                    if ($phishing) { $compoundCounts[$threshold][0]++ }
                    else { $compoundCounts[$threshold][1]++ }
                }
                $dimensions = @(
                    $flags[0],
                    ($flags[4] -or $flags[6] -or $flags[7]),
                    ($flags[8] -or $flags[9]),
                    $flags[10]
                )
                $dimensionCount = @($dimensions | Where-Object { $_ }).Count
                foreach ($threshold in 3..4) {
                    if ($dimensionCount -lt $threshold) { continue }
                    if ($phishing) { $dimensionCounts[$threshold][0]++ }
                    else { $dimensionCounts[$threshold][1]++ }
                }
            }
        }
        $rows++
    }

    [pscustomobject]@{
        Dataset = 'UCI PhiUSIIL URL only; exploratory, full dataset previously inspected'
        Rows = $rows
        TP = $truePositive
        FP = $falsePositive
        TN = $trueNegative
        FN = $falseNegative
        RulesVersion = [Sentinel.Core.Analysis.ThreatAnalysisEngine]::RulesVersion
    }
    foreach ($name in $featureNames) {
        $addedTp = $counts[$name][0]
        $addedFp = $counts[$name][1]
        [pscustomobject]@{
            Feature = $name
            AddedTP = $addedTp
            AddedFP = $addedFp
            RecallIfAdded = [Math]::Round(($truePositive + $addedTp) / [Math]::Max(1, $truePositive + $falseNegative), 6)
            FalsePositiveRateIfAdded = [Math]::Round(($falsePositive + $addedFp) / [Math]::Max(1, $falsePositive + $trueNegative), 6)
        }
    }
    foreach ($threshold in 1..7) {
        $addedTp = $compoundCounts[$threshold][0]
        $addedFp = $compoundCounts[$threshold][1]
        [pscustomobject]@{
            CompoundRule = "At least $threshold distinct structural features"
            AddedTP = $addedTp
            AddedFP = $addedFp
            RecallIfAdded = [Math]::Round(($truePositive + $addedTp) / [Math]::Max(1, $truePositive + $falseNegative), 6)
            FalsePositiveRateIfAdded = [Math]::Round(($falsePositive + $addedFp) / [Math]::Max(1, $falsePositive + $trueNegative), 6)
        }
    }
    foreach ($threshold in 3..4) {
        $addedTp = $dimensionCounts[$threshold][0]
        $addedFp = $dimensionCounts[$threshold][1]
        [pscustomobject]@{
            CompoundRule = "At least $threshold of 4 distinct dimensions"
            AddedTP = $addedTp
            AddedFP = $addedFp
            RecallIfAdded = [Math]::Round(($truePositive + $addedTp) / [Math]::Max(1, $truePositive + $falseNegative), 6)
            FalsePositiveRateIfAdded = [Math]::Round(($falsePositive + $addedFp) / [Math]::Max(1, $falsePositive + $trueNegative), 6)
        }
    }
}
finally {
    $parser.Close()
}
