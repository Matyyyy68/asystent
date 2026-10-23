param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$TrainCsvPath,
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ValidationCsvPath
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$coreAssembly = Join-Path $repositoryRoot 'src\Sentinel.Core\bin\Release\net10.0\Sentinel.Core.dll'
if (-not (Test-Path -LiteralPath $coreAssembly -PathType Leaf)) {
    throw 'Build Sentinel.Core first with: dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release'
}

$testRuntimeDirectory = Join-Path $repositoryRoot 'tests\Sentinel.Tests\bin\Release\net10.0'
if (-not (Test-Path -LiteralPath (Join-Path $testRuntimeDirectory 'Microsoft.Data.Sqlite.dll') -PathType Leaf)) {
    throw 'Build tests/Sentinel.Tests in Release first so the evaluator can load the SQLite runtime.'
}
$env:PATH = (Join-Path $testRuntimeDirectory 'runtimes\win-x64\native') + [IO.Path]::PathSeparator + $env:PATH
foreach ($dependency in @('SQLitePCLRaw.core.dll', 'SQLitePCLRaw.provider.e_sqlite3.dll', 'SQLitePCLRaw.batteries_v2.dll', 'Microsoft.Data.Sqlite.dll')) {
    Add-Type -Path (Join-Path $testRuntimeDirectory $dependency)
}
[SQLitePCL.Batteries_V2]::Init()
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -Path $coreAssembly
$resolvedInputs = @(
    @{ Split = 'train'; Path = (Resolve-Path -LiteralPath $TrainCsvPath).Path },
    @{ Split = 'val'; Path = (Resolve-Path -LiteralPath $ValidationCsvPath).Path }
)
foreach ($input in $resolvedInputs) {
    if ([IO.Path]::GetFileName($input.Path) -cne "url_$($input.Split).csv") {
        throw "Input must be the official url_$($input.Split).csv; test split is not accepted."
    }
}
$expectedDatasets = @{
    train = @{ Size = 7826219L; Sha256 = '568E788EDA4BDF62531ADCDDD093373EF6A1E97FEEC1354063AE337325367B61' }
    val = @{ Size = 1476590L; Sha256 = 'D9EF64D29DF6639AF698EF228E5AF5EC6F8AE44C8F1A1DD1367F9BA6D073D81F' }
}
foreach ($input in $resolvedInputs) {
    $file = Get-Item -LiteralPath $input.Path
    $hash = (Get-FileHash -LiteralPath $input.Path -Algorithm SHA256).Hash
    if ($file.Length -ne $expectedDatasets[$input.Split].Size -or $hash -cne $expectedDatasets[$input.Split].Sha256) {
        throw "Input checksum does not match the official PhishVN $($input.Split) split; evaluation stopped before network access."
    }
}

$temporaryDirectory = Join-Path $env:TEMP ('sentinel-cert-phishvn-eval-' + [Guid]::NewGuid().ToString('N'))
$reputation = $null
try {
    $reputation = [Sentinel.Core.Analysis.DomainReputation]::new($temporaryDirectory)
    $reputation.UpdateAsync().GetAwaiter().GetResult()
    $feedStatus = $reputation.Status([DateTimeOffset]::UtcNow)
    if ($feedStatus.Count -le 0 -or $feedStatus.Expired -or $feedStatus.Version -notmatch '^[A-F0-9]{64}$') {
        throw 'The current CERT feed did not produce a valid, fresh snapshot.'
    }

    $evaluationAt = [DateTimeOffset]::UtcNow
    $rows = foreach ($input in $resolvedInputs) {
        $stream = [IO.FileStream]::new($input.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $size = $stream.Length
        $sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream))
        if ($size -ne $expectedDatasets[$input.Split].Size -or $sha256 -cne $expectedDatasets[$input.Split].Sha256) {
            $stream.Dispose()
            throw "Input checksum does not match the official PhishVN $($input.Split) split; evaluation stopped before parsing."
        }
        $stream.Position = 0
        $parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($stream, [Text.Encoding]::UTF8, $true)
        $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
        $parser.SetDelimiters(',')
        $parser.HasFieldsEnclosedInQuotes = $true
        $count = @{ Rows = 0L; TP = 0L; FP = 0L; TN = 0L; FN = 0L; InvalidUrl = 0L }
        $records = [System.Collections.Generic.List[object]]::new()
        try {
            $headers = $parser.ReadFields()
            $urlIndex = [Array]::IndexOf($headers, 'url')
            $labelIndex = [Array]::IndexOf($headers, 'label')
            $tierIndex = [Array]::IndexOf($headers, 'tier')
            $splitIndex = [Array]::IndexOf($headers, 'split')
            if ($urlIndex -lt 0 -or $labelIndex -lt 0 -or $tierIndex -lt 0) {
                throw 'Expected PhishVN columns url, label, and tier were not found.'
            }

            [long]$record = 1
            while (-not $parser.EndOfData) {
                $fields = $parser.ReadFields()
                $record++
                if ($null -eq $fields -or $fields.Length -le [Math]::Max($urlIndex, [Math]::Max($labelIndex, $tierIndex))) {
                    throw "Malformed PhishVN row near record $record; no URL values were logged."
                }
                if ($splitIndex -ge 0 -and ($fields.Length -le $splitIndex -or $fields[$splitIndex] -cne $input.Split)) {
                    throw "Input contains a row outside the requested $($input.Split) split near record $record."
                }
                $label = $fields[$labelIndex].ToLowerInvariant()
                $tier = $fields[$tierIndex].ToLowerInvariant()
                if ($label -notin 'phishing', 'benign' -or $tier -notin 'gold', 'silver', 'bronze') {
                    throw "Unexpected label or confidence tier near record $record; no URL values were logged."
                }
                if ($tier -notin 'gold', 'silver') { continue }

                $url = $fields[$urlIndex]
                $candidate = if ($url -match '^[A-Za-z][A-Za-z0-9+.-]*://') { $url } else { 'https://' + $url }
                $uri = $null
                $isValid = [Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$uri)
                if ($isValid) {
                    if ($uri.Scheme -in 'http', 'https' -and [Uri]::CheckHostName($uri.IdnHost) -eq [UriHostNameType]::Dns) {
                    } else {
                        $isValid = $false
                    }
                }
                $count.Rows++
                $actual = $label -eq 'phishing'
                if (-not $isValid) {
                    $count.InvalidUrl++
                    if ($actual) { $count.FN++ } else { $count.TN++ }
                } else {
                    $records.Add([pscustomobject]@{ Host = $uri.IdnHost; ActualPhishing = $actual })
                }
            }
        }
        finally { $parser.Close() }

        $matchedHosts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        for ($offset = 0; $offset -lt $records.Count; $offset += 2000) {
            $batch = [System.Collections.Generic.List[string]]::new()
            $limit = [Math]::Min($offset + 2000, $records.Count)
            for ($index = $offset; $index -lt $limit; $index++) { $batch.Add($records[$index].Host) }
            foreach ($host in $reputation.FindMatches($batch, $evaluationAt)) { [void]$matchedHosts.Add($host) }
        }
        foreach ($recordValue in $records) {
            $matched = $matchedHosts.Contains($recordValue.Host)
            if ($recordValue.ActualPhishing) {
                if ($matched) { $count.TP++ } else { $count.FN++ }
            } else {
                if ($matched) { $count.FP++ } else { $count.TN++ }
            }
        }

        [pscustomobject]@{
            Dataset = 'PhishVN v3.1.0 official ' + $input.Split + ' split; gold+silver'
            Rows = $count.Rows
            InvalidUrl = $count.InvalidUrl
            TP = $count.TP
            FP = $count.FP
            TN = $count.TN
            FN = $count.FN
            Precision = [Math]::Round($count.TP / [Math]::Max(1, $count.TP + $count.FP), 6)
            Recall = [Math]::Round($count.TP / [Math]::Max(1, $count.TP + $count.FN), 6)
            FalsePositiveRate = [Math]::Round($count.FP / [Math]::Max(1, $count.FP + $count.TN), 6)
            FeedDomainCount = $feedStatus.Count
            FeedFetchedAt = $feedStatus.FetchedAt
            FeedSha256 = $feedStatus.Version
            DataFile = [IO.Path]::GetFileName($input.Path)
            DataSizeBytes = $size
            DataSha256 = $sha256
            URLsOpened = 0
            RulesVersion = [Sentinel.Core.Analysis.ThreatAnalysisEngine]::RulesVersion
        }
    }
    $rows
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) { Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force }
}
