param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PythonPath
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$temporaryRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
$temporaryDirectory = [IO.Path]::GetFullPath((Join-Path $temporaryRoot ('sentinel-phreshphish-training-' + [Guid]::NewGuid().ToString('N'))))
if (-not $temporaryDirectory.StartsWith($temporaryRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary experiment path escaped the OS temporary directory.'
}
[void](New-Item -ItemType Directory -Path $temporaryDirectory)
$packages = Join-Path $temporaryDirectory 'python-packages'
$csvPath = Join-Path $temporaryDirectory 'phreshphish-train-url-label.csv'
$manifestPath = Join-Path $temporaryDirectory 'extract-manifest.json'
$testCsvPath = Join-Path $temporaryDirectory 'phreshphish-test-url-label.csv'
$testManifestPath = Join-Path $temporaryDirectory 'test-extract-manifest.json'
$outputDirectory = Join-Path $temporaryDirectory 'results'
$node = (Get-Command node.exe -ErrorAction Stop).Source
$python = (Resolve-Path -LiteralPath $PythonPath).Path
$extractor = Join-Path $PSScriptRoot 'extract-train-columns.mjs'
$modelScript = Join-Path $PSScriptRoot 'train-url-model.py'
$testScript = Join-Path $PSScriptRoot 'test_train_url_model.py'
$pslPath = Join-Path $repositoryRoot 'src\Sentinel.Core\Data\public_suffix_list.dat'
$evaluationScript = Join-Path $repositoryRoot 'scripts\evaluate-url-label-csv.ps1'
$previousPythonPath = $env:PYTHONPATH

try {
    & $python -m pip install --target $packages --no-cache-dir --only-binary=:all: -r (Join-Path $PSScriptRoot 'requirements-research.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Could not install pinned research-only Python dependencies into the temporary directory.' }
    $env:PYTHONPATH = if ([string]::IsNullOrEmpty($previousPythonPath)) { $packages } else { $packages + [IO.Path]::PathSeparator + $previousPythonPath }
    & $python $testScript
    if ($LASTEXITCODE -ne 0) { throw 'Research split/model guard tests failed.' }

    $extractorOutput = @(& $node $extractor $csvPath)
    if ($LASTEXITCODE -ne 0) { throw 'PhreshPhish train column extraction failed.' }
    $extraction = $extractorOutput[-1] | ConvertFrom-Json
    [IO.File]::WriteAllText($manifestPath, ($extraction | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))

    $testExtractor = Join-Path $PSScriptRoot 'extract-test-columns.mjs'
    $testExtractorOutput = @(& $node $testExtractor $testCsvPath)
    if ($LASTEXITCODE -ne 0) { throw 'Pinned PhreshPhish test URL extraction failed.' }
    $testExtraction = $testExtractorOutput[-1] | ConvertFrom-Json
    if ($testExtraction.datasetRevision -ne $extraction.datasetRevision) { throw 'Dataset revision changed between train and test extraction.' }
    [IO.File]::WriteAllText($testManifestPath, ($testExtraction | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))

    $modelOutput = @(& $python $modelScript --csv $csvPath --manifest $manifestPath --psl $pslPath --output $outputDirectory `
        --official-test-csv $testCsvPath --test-manifest $testManifestPath)
    if ($LASTEXITCODE -ne 0) { throw 'Train-only research model screening failed.' }
    $modelReport = Get-Content -LiteralPath (Join-Path $outputDirectory 'model-screening-report.json') -Raw | ConvertFrom-Json

    $thresholdResults = foreach ($thresholdName in @('calibratedFpr_0.1%', 'calibratedFpr_0.5%', 'calibratedFpr_1.0%')) {
        [pscustomobject]@{
            CalibrationTarget = $thresholdName
            Calibration = $modelReport.calibrationAndDomainHoldout.$thresholdName.calibration
            DomainHoldout = $modelReport.calibrationAndDomainHoldout.$thresholdName.registrableDomainHoldout
            OfficialTest = $modelReport.officialTestOnce.$thresholdName
        }
    }

    $productRules = & $evaluationScript -CsvPath (Join-Path $outputDirectory 'phreshphish-train-derived-holdout.csv') `
        -DatasetName "PhreshPhish train-derived domain holdout ($($modelReport.revision))" -Split test -PhishingLabels phish
    [pscustomobject]@{
        DatasetRevision = $modelReport.revision
        TrainRows = $extraction.rows
        TrainCsvSha256 = $extraction.extractedCsvSha256
        TrainRecordIdsSha256 = $modelReport.sourceRecordIdsSha256
        TestRows = $testExtraction.rows
        TestCsvSha256 = $testExtraction.extractedCsvSha256
        Model = $modelReport.model
        Parameters = $modelReport.parameters
        SplitRows = $modelReport.splitRows
        SplitLabelCounts = $modelReport.splitLabelCounts
        ThresholdResults = $thresholdResults
        FrozenProductRules = $productRules
    } | ConvertTo-Json -Depth 10
}
finally {
    $env:PYTHONPATH = $previousPythonPath
    if (Test-Path -LiteralPath $temporaryDirectory) {
        $resolvedTemporary = (Resolve-Path -LiteralPath $temporaryDirectory).Path
        if (-not $resolvedTemporary.StartsWith($temporaryRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing cleanup outside the OS temporary directory.'
        }
        Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
    }
}
