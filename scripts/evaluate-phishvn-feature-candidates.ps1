param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvPath,
    [ValidateSet('train', 'val')]
    [string]$Split = 'train',
    [string[]]$Tiers = @('gold', 'silver')
)

$ErrorActionPreference = 'Stop'
$requestedTiers = @($Tiers | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() })
$invalidTiers = @($requestedTiers | Where-Object { $_ -notin 'gold', 'silver', 'bronze' })
if ($requestedTiers.Count -eq 0 -or $invalidTiers.Count -gt 0) {
    throw 'Tiers must be a comma- or space-separated combination of gold, silver, and bronze.'
}
$Tiers = @(@('gold', 'silver', 'bronze') | Where-Object { $_ -in $requestedTiers } | Sort-Object -Unique)
$resolvedCsv = (Resolve-Path -LiteralPath $CsvPath).Path
$fileName = [IO.Path]::GetFileName($resolvedCsv)
if ($fileName -cne "url_$Split.csv") {
    throw "Feature scans accept only the official url_$Split.csv split; the test split is deliberately excluded."
}

$stream = [IO.FileStream]::new($resolvedCsv, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
$dataSizeBytes = $stream.Length
$dataSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream))
$stream.Position = 0
Add-Type -AssemblyName Microsoft.VisualBasic
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$coreAssembly = Join-Path $repositoryRoot 'src\Sentinel.Core\bin\Release\net10.0\Sentinel.Core.dll'
if (-not (Test-Path -LiteralPath $coreAssembly -PathType Leaf)) {
    $stream.Dispose(); throw 'Build Sentinel.Core first with: dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release'
}
Add-Type -Path $coreAssembly
$domainNames = [Sentinel.Core.Analysis.DomainNames]::new()
$parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($stream, [Text.Encoding]::UTF8, $true)
$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
$parser.SetDelimiters(',')
$parser.HasFieldsEnclosedInQuotes = $true
$counts = @{}
$counts['aggregate'] = @{}
$featureNames = @(
    'url_len>=100', 'url_len>=150', 'url_len>=200',
    'host_len>=40', 'host_len>=60', 'host_len>=80',
    'path_len>=30', 'path_len>=50', 'path_len>=80',
    'host_labels>=5', 'host_labels>=6',
    'digits>=4', 'digits>=6', 'hyphens>=3', 'hyphens>=5',
    'path_segments>=4', 'path_segments>=6',
    'query_params>=3', 'query_params>=5', 'percent_escape', 'at_sign',
    'ip_literal', 'punycode', 'auth_token', 'auth_token_in_host', 'long_label>=25',
    'subdomain_long>=20', 'unusual_port', 'encoded_slash', 'registered_label_entropy>=4.0'
)
function Get-Entropy([string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) { return 0.0 }
    $frequencies = @{}
    foreach ($character in $Value.ToCharArray()) { $frequencies[[string]$character]++ }
    $entropy = 0.0
    foreach ($count in $frequencies.Values) { $probability = $count / $Value.Length; $entropy -= $probability * [Math]::Log($probability, 2) }
    return $entropy
}
foreach ($tier in $Tiers) {
    $counts[$tier] = @{}
    foreach ($feature in $featureNames) {
        $counts[$tier][$feature] = @{ Rows = 0L; TP = 0L; FP = 0L; TN = 0L; FN = 0L }
    }
}
foreach ($feature in $featureNames) {
    $counts['aggregate'][$feature] = @{ Rows = 0L; TP = 0L; FP = 0L; TN = 0L; FN = 0L }
}

try {
    $headers = $parser.ReadFields()
    if ($null -eq $headers) { throw 'CSV is empty.' }
    $urlIndex = [Array]::IndexOf($headers, 'url')
    $labelIndex = [Array]::IndexOf($headers, 'label')
    $tierIndex = [Array]::IndexOf($headers, 'tier')
    $splitIndex = [Array]::IndexOf($headers, 'split')
    if ($urlIndex -lt 0 -or $labelIndex -lt 0 -or $tierIndex -lt 0) {
        throw 'Expected PhishVN CSV columns url, label, and tier were not found.'
    }

    [long]$record = 1
    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields()
        $record++
        $maxIndex = [Math]::Max($urlIndex, [Math]::Max($labelIndex, $tierIndex))
        if ($null -eq $fields -or $fields.Length -le $maxIndex -or ($splitIndex -ge 0 -and $fields.Length -le $splitIndex)) {
            throw "Malformed PhishVN CSV row near record $record; no URL values were logged."
        }
        if ($splitIndex -ge 0 -and $fields[$splitIndex] -cne $Split) {
            throw "Input contains a row outside the requested $Split split near record $record; no URL values were logged."
        }

        $tier = $fields[$tierIndex].ToLowerInvariant()
        $label = $fields[$labelIndex].ToLowerInvariant()
        if ($tier -notin 'gold', 'silver', 'bronze' -or $label -notin 'phishing', 'benign') {
            throw "Unexpected confidence tier or label near record $record; no URL values were logged."
        }
        if ($tier -notin $Tiers) { continue }

        $rawUrl = $fields[$urlIndex]
        $analysisUrl = if ($rawUrl -match '^[A-Za-z][A-Za-z0-9+.-]*://') { $rawUrl } else { 'https://' + $rawUrl }
        $uri = $null
        if (-not [Uri]::TryCreate($analysisUrl, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin 'http', 'https') {
            throw "Invalid URL near record $record; no URL values were logged."
        }
        $hostName = $uri.Host.ToLowerInvariant().TrimEnd('.')
        $registeredDomain = $domainNames.RegistrableDomain($hostName)
        if ([string]::IsNullOrWhiteSpace($registeredDomain)) { $registeredDomain = $hostName }
        $registeredLabel = $registeredDomain.Split('.')[0]
        $labels = @($hostName.Split('.') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $path = $uri.AbsolutePath
        $query = $uri.Query
        $digitCount = ([regex]::Matches($hostName, '\d')).Count
        $hyphenCount = ([regex]::Matches($hostName, '-')).Count
        $pathSegments = @($path.Split('/') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
        $queryParams = ([regex]::Matches($query, '(?:^|&)[^=&]+=[^&]*')).Count
        $longSubdomain = @($labels | Select-Object -SkipLast 2 | Where-Object { $_.Length -ge 20 }).Count -gt 0
        $longLabel = @($labels | Where-Object { $_.Length -ge 25 }).Count -gt 0
        $isIp = [Uri]::CheckHostName($hostName) -eq [UriHostNameType]::IPv4
        $features = @{
            'url_len>=100' = $rawUrl.Length -ge 100; 'url_len>=150' = $rawUrl.Length -ge 150; 'url_len>=200' = $rawUrl.Length -ge 200
            'host_len>=40' = $hostName.Length -ge 40; 'host_len>=60' = $hostName.Length -ge 60; 'host_len>=80' = $hostName.Length -ge 80
            'path_len>=30' = $path.Length -ge 30; 'path_len>=50' = $path.Length -ge 50; 'path_len>=80' = $path.Length -ge 80
            'host_labels>=5' = $labels.Count -ge 5; 'host_labels>=6' = $labels.Count -ge 6
            'digits>=4' = $digitCount -ge 4; 'digits>=6' = $digitCount -ge 6
            'hyphens>=3' = $hyphenCount -ge 3; 'hyphens>=5' = $hyphenCount -ge 5
            'path_segments>=4' = $pathSegments -ge 4; 'path_segments>=6' = $pathSegments -ge 6
            'query_params>=3' = $queryParams -ge 3; 'query_params>=5' = $queryParams -ge 5
            'percent_escape' = $rawUrl -match '%[0-9a-f]{2}'; 'at_sign' = $rawUrl.Contains('@')
            'ip_literal' = $isIp; 'punycode' = $hostName.Contains('xn--')
            'auth_token' = $rawUrl -match '(?i)(login|verify|secure|account|password|signin|confirm|update)'
            'auth_token_in_host' = $hostName -match '(?i)(login|verify|secure|account|password|signin|confirm|update)'; 'long_label>=25' = $longLabel
            'subdomain_long>=20' = $longSubdomain; 'unusual_port' = $uri.Port -notin 80, 443
            'encoded_slash' = $rawUrl -match '(?i)%2f|%5c'; 'registered_label_entropy>=4.0' = (Get-Entropy $registeredLabel) -ge 4.0
        }

        $actualPhishing = $label -eq 'phishing'
        foreach ($feature in $featureNames) {
            foreach ($bucket in @($counts[$tier][$feature], $counts['aggregate'][$feature])) {
                $bucket.Rows++
                if ($actualPhishing) {
                    if ($features[$feature]) { $bucket.TP++ } else { $bucket.FN++ }
                } elseif ($features[$feature]) { $bucket.FP++ } else { $bucket.TN++ }
            }
        }
    }

    $aggregateTier = (@('gold', 'silver', 'bronze') | Where-Object { $_ -in $Tiers }) -join '+'
    foreach ($tier in @('aggregate') + @(@('gold', 'silver', 'bronze') | Where-Object { $_ -in $Tiers })) {
        foreach ($feature in $featureNames) {
            $bucket = $counts[$tier][$feature]
            if ($bucket.Rows -eq 0) { continue }
            [pscustomobject]@{
                Dataset = 'PhishVN v3.1.0 official temporal/group-domain split'
                Split = $Split
                ConfidenceTier = if ($tier -eq 'aggregate') { $aggregateTier + ' aggregate' } else { $tier }
                Feature = $feature
                Rows = $bucket.Rows
                TP = $bucket.TP; FP = $bucket.FP; TN = $bucket.TN; FN = $bucket.FN
                Precision = [Math]::Round($bucket.TP / [Math]::Max(1, $bucket.TP + $bucket.FP), 6)
                Recall = [Math]::Round($bucket.TP / [Math]::Max(1, $bucket.TP + $bucket.FN), 6)
                FalsePositiveRate = [Math]::Round($bucket.FP / [Math]::Max(1, $bucket.FP + $bucket.TN), 6)
                URLsOpened = 0
                DataFile = $fileName
                DataSizeBytes = $dataSizeBytes
                DataSha256 = $dataSha256
            }
        }
    }
}
finally {
    $parser.Close()
}
