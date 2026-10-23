param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$TrainCsvPath,
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ValidationCsvPath,
    [string[]]$Tiers = @('gold', 'silver')
)

$ErrorActionPreference = 'Stop'
$requestedTiers = @($Tiers | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() })
$invalidTiers = @($requestedTiers | Where-Object { $_ -notin 'gold', 'silver', 'bronze' })
if ($requestedTiers.Count -eq 0 -or $invalidTiers.Count -gt 0) {
    throw 'Tiers must be a combination of gold, silver, and bronze.'
}
$tiersToUse = @(@('gold', 'silver', 'bronze') | Where-Object { $_ -in $requestedTiers } | Sort-Object -Unique)
$brandTokenPattern = '(?i)(?:^|[^a-z0-9])(?:vietcombank|vietinbank|agribank|bidv|techcombank|mbbank|vpbank|acb|sacombank|shopee|momo|zalopay)(?=$|[^a-z0-9])'

function Get-SplitMetrics([string]$CsvPath, [string]$ExpectedSplit) {
    $resolvedPath = (Resolve-Path -LiteralPath $CsvPath).Path
    $stream = [IO.FileStream]::new($resolvedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $fileSize = $stream.Length
    $fileHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream))
    $stream.Position = 0
    $parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($stream, [Text.Encoding]::UTF8, $true)
    $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
    $parser.SetDelimiters(',')
    $parser.HasFieldsEnclosedInQuotes = $true
    try {
        $headers = $parser.ReadFields()
        $domainIndex = [Array]::IndexOf($headers, 'domain')
        $labelIndex = [Array]::IndexOf($headers, 'label')
        $tierIndex = [Array]::IndexOf($headers, 'tier')
        $splitIndex = [Array]::IndexOf($headers, 'split')
        if ($domainIndex -lt 0 -or $labelIndex -lt 0 -or $tierIndex -lt 0) {
            throw 'Expected PhishVN CSV columns domain, label, and tier were not found.'
        }
        if ($splitIndex -lt 0 -and [IO.Path]::GetFileName($resolvedPath) -cne "url_$ExpectedSplit.csv") {
            throw "Input must be the official url_$ExpectedSplit.csv file or include a split column identifying every row as $ExpectedSplit."
        }

        [long]$rows = 0; [long]$tp = 0; [long]$fp = 0; [long]$tn = 0; [long]$fn = 0
        [long]$record = 1
        while (-not $parser.EndOfData) {
            $fields = $parser.ReadFields()
            $record++
            $requiredIndex = [Math]::Max($domainIndex, [Math]::Max($labelIndex, [Math]::Max($tierIndex, $splitIndex)))
            if ($null -eq $fields -or $fields.Length -le $requiredIndex) {
                throw "Malformed PhishVN CSV row near record $record."
            }
            if ($splitIndex -ge 0 -and $fields[$splitIndex] -cne $ExpectedSplit) {
                throw "Input contains a row outside the requested $ExpectedSplit split near record $record."
            }
            $tier = $fields[$tierIndex].ToLowerInvariant()
            $label = $fields[$labelIndex].ToLowerInvariant()
            if ($tier -notin 'gold', 'silver', 'bronze') { throw "Unexpected confidence tier near record $record." }
            if ($label -notin 'phishing', 'benign') { throw "Unexpected label near record $record." }
            if ($tier -notin $tiersToUse) { continue }

            $isPhishing = $label -eq 'phishing'
            $matched = $fields[$domainIndex] -match $brandTokenPattern
            $rows++
            if ($isPhishing) { if ($matched) { $tp++ } else { $fn++ } }
            else { if ($matched) { $fp++ } else { $tn++ } }
        }
        if ($rows -eq 0) { throw "The $ExpectedSplit split has no rows in the selected tiers." }
        [pscustomobject]@{
            Dataset = 'PhishVN v3.1.0 official temporal/group-domain split'
            Split = $ExpectedSplit
            Tiers = [string]::Join('+', $tiersToUse)
            Rows = $rows
            TP = $tp
            FP = $fp
            TN = $tn
            FN = $fn
            Recall = [Math]::Round($tp / [Math]::Max(1, $tp + $fn), 6)
            FalsePositiveRate = [Math]::Round($fp / [Math]::Max(1, $fp + $tn), 6)
            Feature = 'dataset domain field contains a bounded token from a fixed Vietnamese-bank/platform list'
            BrandTokens = 'vietcombank,vietinbank,agribank,bidv,techcombank,mbbank,vpbank,acb,sacombank,shopee,momo,zalopay'
            DataFile = [IO.Path]::GetFileName($resolvedPath)
            DataSizeBytes = $fileSize
            DataSha256 = $fileHash
            URLsOpened = 0
        }
    }
    finally { $parser.Close() }
}

$trainResult = Get-SplitMetrics -CsvPath $TrainCsvPath -ExpectedSplit 'train'
$validationResult = Get-SplitMetrics -CsvPath $ValidationCsvPath -ExpectedSplit 'val'
@($trainResult, $validationResult)
