param([switch]$AllowNetwork)

$ErrorActionPreference = 'Stop'
if (-not $AllowNetwork) {
    throw 'This research evaluation fetches PhreshPhish data from Hugging Face. Pass -AllowNetwork to authorize dataset downloads.'
}
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$temporaryRoot = [IO.Path]::GetFullPath($env:TEMP)
$temporaryDirectory = [IO.Path]::GetFullPath((Join-Path $temporaryRoot ('sentinel-phreshphish-' + [Guid]::NewGuid().ToString('N'))))
if (-not $temporaryDirectory.StartsWith($temporaryRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary dataset path escaped the OS temporary directory.'
}
[void](New-Item -ItemType Directory -Path $temporaryDirectory)
$csvPath = Join-Path $temporaryDirectory 'phreshphish-test-url-label.csv'
$node = (Get-Command node.exe -ErrorAction Stop).Source
$extractor = Join-Path $PSScriptRoot 'extract-test-columns.mjs'

try {
    $extractorOutput = @(& $node $extractor $csvPath --allow-network)
    if ($LASTEXITCODE -ne 0) { throw 'PhreshPhish column extraction failed.' }
    $extraction = $extractorOutput[-1] | ConvertFrom-Json
    if (-not (Test-Path -LiteralPath $csvPath -PathType Leaf)) { throw 'The extractor did not create its temporary CSV.' }
    $result = & (Join-Path $repositoryRoot 'scripts\evaluate-url-label-csv.ps1') `
        -CsvPath $csvPath -DatasetName "PhreshPhish 1.0.1 ($($extraction.datasetRevision))" -Split test -PhishingLabels phish
    $report = [pscustomobject]@{
        Extraction = $extraction
        Evaluation = $result
    }
    $report | ConvertTo-Json -Depth 5
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        $resolvedTemporary = (Resolve-Path -LiteralPath $temporaryDirectory).Path
        if (-not $resolvedTemporary.StartsWith($temporaryRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing cleanup outside the OS temporary directory.'
        }
        Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
    }
}
