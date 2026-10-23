param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CsvPath,
    [Parameter(Mandatory = $true)]
    [ValidateSet('train', 'val')]
    [string]$Split
)

$ErrorActionPreference = 'Stop'
$expected = @{
    train = '568E788EDA4BDF62531ADCDDD093373EF6A1E97FEEC1354063AE337325367B61'
    val   = 'D9EF64D29DF6639AF698EF228E5AF5EC6F8AE44C8F1A1DD1367F9BA6D073D81F'
}
$resolvedCsv = (Resolve-Path -LiteralPath $CsvPath).Path
if ([IO.Path]::GetFileName($resolvedCsv) -cne "url_$Split.csv") {
    throw "Input must be the official url_$Split.csv file; only train and validation are accepted."
}
$actualHash = (Get-FileHash -LiteralPath $resolvedCsv -Algorithm SHA256).Hash
if ($actualHash -cne $expected[$Split]) { throw "PhishVN $Split checksum mismatch; no rows were evaluated." }

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$coreAssembly = Join-Path $repositoryRoot 'src\Sentinel.Core\bin\Release\net10.0\Sentinel.Core.dll'
if (-not (Test-Path -LiteralPath $coreAssembly -PathType Leaf)) {
    throw 'Build Sentinel.Core first with: dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release'
}
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -Path $coreAssembly
$domains = [Sentinel.Core.Analysis.DomainNames]::new()

# Preselected brands not currently in UrlAnalyzer. Canonical domains are
# allowlisted so legitimate owner-controlled sites are excluded from matching.
$brandDomains = [ordered]@{
    amazon        = @('amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.co.jp', 'amazon.in', 'amazon.it', 'amazon.es', 'amazon.com.au', 'amazonaws.com')
    facebook      = @('facebook.com', 'fb.com', 'fb.me', 'messenger.com')
    instagram     = @('instagram.com', 'cdninstagram.com')
    netflix       = @('netflix.com')
    linkedin      = @('linkedin.com', 'linkedin.cn', 'lnkd.in')
    dropbox       = @('dropbox.com')
    spotify       = @('spotify.com')
    steam         = @('steampowered.com', 'steamcommunity.com')
    chase         = @('chase.com')
    wellsfargo    = @('wellsfargo.com')
    bankofamerica = @('bankofamerica.com')
    coinbase      = @('coinbase.com')
}

function Get-EditDistance([string]$left, [string]$right) {
    if ([Math]::Abs($left.Length - $right.Length) -gt 1) { return 2 }
    $previous = [int[]]::new($right.Length + 1)
    for ($j = 0; $j -le $right.Length; $j++) { $previous[$j] = $j }
    for ($i = 1; $i -le $left.Length; $i++) {
        $next = [int[]]::new($right.Length + 1)
        $next[0] = $i
        for ($j = 1; $j -le $right.Length; $j++) {
            $cost = if ($left[$i - 1] -ceq $right[$j - 1]) { 0 } else { 1 }
            $next[$j] = [Math]::Min([Math]::Min($next[$j - 1] + 1, $previous[$j] + 1), $previous[$j - 1] + $cost)
        }
        $previous = $next
    }
    return $previous[$right.Length]
}

$counts = @{}
foreach ($brand in $brandDomains.Keys) { $counts[$brand] = @{ TP = 0L; FP = 0L } }
$union = @{ Rows = 0L; TP = 0L; FP = 0L; TN = 0L; FN = 0L }
$stream = [IO.File]::Open($resolvedCsv, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
$parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($stream, [Text.Encoding]::UTF8, $true)
$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
$parser.SetDelimiters(',')
$parser.HasFieldsEnclosedInQuotes = $true
try {
    $headers = $parser.ReadFields()
    $urlIndex = [Array]::IndexOf($headers, 'url')
    $labelIndex = [Array]::IndexOf($headers, 'label')
    $tierIndex = [Array]::IndexOf($headers, 'tier')
    $splitIndex = [Array]::IndexOf($headers, 'split')
    if ($urlIndex -lt 0 -or $labelIndex -lt 0 -or $tierIndex -lt 0 -or $splitIndex -lt 0) {
        throw 'Expected url, label, tier, and split columns were not found.'
    }
    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields()
        if ($fields.Length -le [Math]::Max($splitIndex, [Math]::Max($urlIndex, [Math]::Max($labelIndex, $tierIndex)))) {
            throw 'Malformed PhishVN row; no URL values were logged.'
        }
        if ($fields[$splitIndex] -cne $Split) { throw "Input contains a row outside the requested $Split split; no URL values were logged." }
        $tier = $fields[$tierIndex].ToLowerInvariant()
        if ($tier -notin @('gold', 'silver')) { continue }
        $label = $fields[$labelIndex].ToLowerInvariant()
        if ($label -notin @('phishing', 'benign')) { throw 'Unexpected label; no URL values were logged.' }

        $value = $fields[$urlIndex]
        if ($value -notmatch '^[A-Za-z][A-Za-z0-9+.-]*://') { $value = 'https://' + $value }
        $uri = [Uri]::new($value)
        $hostName = [Sentinel.Core.Analysis.DomainNames]::Ascii($uri.IdnHost)
        $registered = $domains.RegistrableDomain($hostName)
        $matched = [Collections.Generic.List[string]]::new()
        if ($registered) {
            $registeredLabel = $registered.Split('.')[0]
            $hostLabels = $hostName.Split('.')
            $subdomainCount = $hostLabels.Length - $registered.Split('.').Length
            $subdomains = @()
            if ($subdomainCount -gt 0) { $subdomains = $hostLabels[0..($subdomainCount - 1)] }
            foreach ($brand in $brandDomains.Keys) {
                $legitimate = $false
                foreach ($legalDomain in $brandDomains[$brand]) {
                    if ([Sentinel.Core.Analysis.DomainNames]::Within($hostName, $legalDomain)) { $legitimate = $true; break }
                }
                if ($legitimate) { continue }
                $lookalike = $registeredLabel -ne $brand -and (Get-EditDistance $registeredLabel $brand) -eq 1
                $brandSuffix = @("$brand-login", "$brand-secure", "$brand-account", "$brand-sso") -contains $registeredLabel
                if (($subdomains -contains $brand) -or $lookalike -or $brandSuffix) { $matched.Add($brand) }
            }
        }

        $union.Rows++
        if ($matched.Count -gt 0) {
            foreach ($brand in $matched) {
                if ($label -eq 'phishing') { $counts[$brand].TP++ } else { $counts[$brand].FP++ }
            }
            if ($label -eq 'phishing') { $union.TP++ } else { $union.FP++ }
        } elseif ($label -eq 'phishing') { $union.FN++ } else { $union.TN++ }
    }
} finally { $parser.Dispose() }

foreach ($brand in $brandDomains.Keys) {
    [pscustomobject]@{ Split = $Split; Brand = $brand; TP = $counts[$brand].TP; FP = $counts[$brand].FP }
}
Write-Host "Aggregate split=$Split candidate=expanded-brand-impersonation rows=$($union.Rows) TP=$($union.TP) FP=$($union.FP) TN=$($union.TN) FN=$($union.FN) inputSha256=$actualHash"
