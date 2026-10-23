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
$engine = [Sentinel.Core.Analysis.ThreatAnalysisEngine]::new([Sentinel.Core.Analysis.UrlAnalyzer]::new($domainNames))
$timestamp = [DateTimeOffset]::UnixEpoch
$resolvedCsv = (Resolve-Path -LiteralPath $CsvPath).Path
$fileName = [IO.Path]::GetFileName($resolvedCsv)
if ($fileName -cne 'Dataset.csv' -and $fileName -cne 'sentinel-url-phish-v1-65z9twcx3r.csv') { throw 'Feature scan accepts only URL-Phish v1 Dataset.csv (including its verified local snapshot name).' }
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
$partitions = @{}
foreach ($name in 'DomainTrain', 'DomainHoldout') {
    $partitions[$name] = @{ Domains = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); Features = @{} }
}
$thresholds = @(
    @{ Name = 'registered_label_len>=16'; Test = { param($url,$uri,$hostName,$registered) $registered.Split('.')[0].Length -ge 16 } },
    @{ Name = 'registered_label_len>=20'; Test = { param($url,$uri,$hostName,$registered) $registered.Split('.')[0].Length -ge 20 } },
    @{ Name = 'registered_label_entropy>=3.5'; Test = { param($url,$uri,$hostName,$registered) (Get-Entropy $registered.Split('.')[0]) -ge 3.5 } },
    @{ Name = 'registered_label_entropy>=4.0'; Test = { param($url,$uri,$hostName,$registered) (Get-Entropy $registered.Split('.')[0]) -ge 4.0 } },
    @{ Name = 'digit_ratio>=0.25'; Test = { param($url,$uri,$hostName,$registered) (Get-DigitRatio $registered.Split('.')[0]) -ge 0.25 } },
    @{ Name = 'digit_ratio>=0.40'; Test = { param($url,$uri,$hostName,$registered) (Get-DigitRatio $registered.Split('.')[0]) -ge 0.40 } },
    @{ Name = 'digit_run>=4'; Test = { param($url,$uri,$hostName,$registered) $hostName -match '\d{4,}' } },
    @{ Name = 'letter_digit_transitions>=4'; Test = { param($url,$uri,$hostName,$registered) ([regex]::Matches($hostName,'(?:(?<=\p{L})\d|\d(?=\p{L}))')).Count -ge 4 } },
    @{ Name = 'vowel_ratio<=0.20_len>=10'; Test = { param($url,$uri,$hostName,$registered) $label=$registered.Split('.')[0]; $label.Length -ge 10 -and (([regex]::Matches($label,'[aeiou]')).Count / [Math]::Max(1,$label.Length)) -le 0.20 } },
    @{ Name = 'repeated_char_run>=4'; Test = { param($url,$uri,$hostName,$registered) $hostName -match '(.)\1{3,}' } }
)
foreach ($partition in $partitions.Values) {
    foreach ($feature in $thresholds + @(@{Name='engine_plus_entropy4'},@{Name='engine_or_entropy4'})) { $partition.Features[$feature.Name] = @{ Rows=0L; TP=0L; FP=0L; TN=0L; FN=0L } }
}

function Get-Entropy([string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) { return 0.0 }
    $counts = @{}; foreach ($character in $Value.ToCharArray()) { $counts[[string]$character]++ }
    $entropy = 0.0
    foreach ($count in $counts.Values) { $probability = $count / $Value.Length; $entropy -= $probability * [Math]::Log($probability, 2) }
    return $entropy
}
function Get-DigitRatio([string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) { return 0.0 }
    return ([regex]::Matches($Value,'\d')).Count / $Value.Length
}

try {
    $headers = $parser.ReadFields()
    $urlIndex = [Array]::IndexOf($headers, 'url'); $labelIndex = [Array]::IndexOf($headers, 'label')
    if ($urlIndex -lt 0 -or $labelIndex -lt 0) { throw 'Expected URL-Phish CSV columns url and label were not found.' }
    [long]$record = 1
    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields(); $record++
        if ($null -eq $fields -or $fields.Length -le [Math]::Max($urlIndex,$labelIndex)) { throw "Malformed URL-Phish CSV row near record $record; URL values are omitted." }
        $label = $fields[$labelIndex]
        if ($label -notin '0','1') { throw "Unexpected label near record $record; URL values are omitted." }
        $url = $fields[$urlIndex]; $uri = $null
        $valid = [Uri]::TryCreate($url,[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -in 'http','https'
        if ($valid) {
            $hostName = $uri.IdnHost.TrimEnd('.').ToLowerInvariant()
            $registered = $domainNames.RegistrableDomain($hostName); if ([string]::IsNullOrWhiteSpace($registered)) { $registered = $hostName }
            $domainKey = $registered
        } else {
            $hash = [Security.Cryptography.SHA256]::HashData($utf8.GetBytes("invalid-url`n$url"))
            $domainKey = 'invalid:' + [Convert]::ToHexString($hash); $hostName = ''; $registered = ''
        }
        $splitHash = [Security.Cryptography.SHA256]::HashData($utf8.GetBytes("$SplitSeed`n$domainKey"))
        $bucket = [Convert]::ToUInt32([Convert]::ToHexString($splitHash,0,4),16) % 100
        $partition = $partitions[$(if ($bucket -lt $DomainHoldoutPercent) { 'DomainHoldout' } else { 'DomainTrain' })]
        [void]$partition.Domains.Add($domainKey)
        foreach ($feature in $thresholds) {
            $hit = $valid -and (& $feature.Test $url $uri $hostName $registered)
            $counts = $partition.Features[$feature.Name]; $counts.Rows++
            if ($label -eq '1') { if ($hit) { $counts.TP++ } else { $counts.FN++ } }
            else { if ($hit) { $counts.FP++ } else { $counts.TN++ } }
        }
        $baseDetected = $false; $entropyDetected = $false; $score = 0; $indicatorCount = 0
        if ($valid) {
            $assessment = $engine.Analyze([Sentinel.Core.Analysis.AnalysisContext]::new('offline-url-phish-feature-evaluation','',$timestamp,
                [Sentinel.Core.Analysis.NavigationSignal]::new($url)))
            $baseDetected = $assessment.Risk -ge [Sentinel.Core.RiskLevel]::Moderate
            $entropyDetected = (Get-Entropy $registered.Split('.')[0]) -ge 4.0
            $score = [int](($assessment.Indicators | Measure-Object -Property Weight -Sum).Sum)
            $indicatorCount = $assessment.Indicators.Count
        }
        $newScore = $score + [int]$entropyDetected
        $newCount = $indicatorCount + [int]$entropyDetected
        $newRisk = if ($newScore -eq 0) { 0 } elseif ($newScore -le 2) { 1 } elseif ($newScore -lt 7 -or $newCount -lt 2) { 2 } elseif ($newScore -lt 12 -or $newCount -lt 3) { 3 } else { 4 }
        $outcomes = @{ engine_plus_entropy4 = $newRisk -ge [Sentinel.Core.RiskLevel]::Moderate; engine_or_entropy4 = $baseDetected -or $entropyDetected }
        foreach ($name in $outcomes.Keys) {
            $counts = $partition.Features[$name]; $counts.Rows++
            if ($label -eq '1') { if ($outcomes[$name]) { $counts.TP++ } else { $counts.FN++ } }
            else { if ($outcomes[$name]) { $counts.FP++ } else { $counts.TN++ } }
        }
    }
    foreach ($featureName in @($thresholds.Name) + @('engine_plus_entropy4','engine_or_entropy4')) {
        foreach ($name in 'DomainTrain','DomainHoldout') {
            $counts = $partitions[$name].Features[$featureName]
            [pscustomobject]@{ Dataset='URL-Phish v1; fixed diagnostic features; registrable-domain split'; Feature=$featureName; Partition=$name; Rows=$counts.Rows; Domains=$partitions[$name].Domains.Count; TP=$counts.TP; FP=$counts.FP; TN=$counts.TN; FN=$counts.FN; Recall=[Math]::Round($counts.TP/[Math]::Max(1,$counts.TP+$counts.FN),6); FalsePositiveRate=[Math]::Round($counts.FP/[Math]::Max(1,$counts.FP+$counts.TN),6); SplitSeed=$SplitSeed; DataFile=$fileName; DataSizeBytes=$dataSizeBytes; DataSha256=$dataSha256; URLsOpened=0 }
        }
    }
    if (@($partitions.DomainTrain.Domains | Where-Object { $partitions.DomainHoldout.Domains.Contains($_) }).Count -ne 0) {
        throw 'Registrable-domain leakage found between evaluation partitions.'
    }
}
finally { $parser.Close() }
