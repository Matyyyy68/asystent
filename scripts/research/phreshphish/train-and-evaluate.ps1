param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$PythonPath,
    [string]$ReportOutputPath,
    [switch]$AllowNetwork
)

$ErrorActionPreference = 'Stop'
if (-not $AllowNetwork) {
    throw 'This research experiment downloads PhreshPhish data and installs temporary packages. Pass -AllowNetwork to authorize network access.'
}
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$reportPath = if ([string]::IsNullOrWhiteSpace($ReportOutputPath)) {
    Join-Path $repositoryRoot 'docs\PHRESHPHISH-OFFICIAL-BENCHMARKS.json'
} else {
    [IO.Path]::GetFullPath($ReportOutputPath)
}
$isDefaultReportPath = [string]::IsNullOrWhiteSpace($ReportOutputPath)
if (-not $reportPath.StartsWith($repositoryRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The durable research summary must be saved inside the repository.'
}
if (-not $isDefaultReportPath -and (Test-Path -LiteralPath $reportPath)) { throw 'Refusing to overwrite an existing custom benchmark report.' }
$temporaryRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')
$temporaryDirectory = [IO.Path]::GetFullPath((Join-Path $temporaryRoot ('sentinel-phreshphish-training-' + [Guid]::NewGuid().ToString('N'))))
if (-not $temporaryDirectory.StartsWith($temporaryRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary experiment path escaped the OS temporary directory.'
}
[void](New-Item -ItemType Directory -Path $temporaryDirectory)
$packages = Join-Path $temporaryDirectory 'python-packages'
$nodeTools = Join-Path $temporaryDirectory 'node-tools'
$csvPath = Join-Path $temporaryDirectory 'phreshphish-train-url-label.csv'
$manifestPath = Join-Path $temporaryDirectory 'extract-manifest.json'
$testCsvPath = Join-Path $temporaryDirectory 'phreshphish-test-url-label.csv'
$testManifestPath = Join-Path $temporaryDirectory 'test-extract-manifest.json'
$benchmarkTestCsvPath = Join-Path $temporaryDirectory 'phreshphish-full-test-url-label.csv'
$benchmarkTestManifestPath = Join-Path $temporaryDirectory 'full-test-extract-manifest.json'
$benchmarkDirectory = Join-Path $temporaryDirectory 'official-benchmarks'
$outputDirectory = Join-Path $temporaryDirectory 'results'
$node = (Get-Command node.exe -ErrorAction Stop).Source
$python = (Resolve-Path -LiteralPath $PythonPath).Path
$extractor = Join-Path $nodeTools 'extract-train-columns.mjs'
$modelScript = Join-Path $PSScriptRoot 'train-url-model.py'
$testScript = Join-Path $PSScriptRoot 'test_train_url_model.py'
$pslPath = Join-Path $repositoryRoot 'src\Sentinel.Core\Data\public_suffix_list.dat'
$evaluationScript = Join-Path $repositoryRoot 'scripts\evaluate-url-label-csv.ps1'
$previousPythonPath = $env:PYTHONPATH

try {
    [void](New-Item -ItemType Directory -Path $nodeTools)
    foreach ($name in @('package.json', 'package-lock.json', 'dataset-metadata.mjs', 'extract-train-columns.mjs', 'extract-test-columns.mjs', 'extract-official-benchmarks.mjs')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $nodeTools
    }
    & npm.cmd ci --prefix $nodeTools --ignore-scripts --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'Could not install pinned research-only Node dependencies into the temporary directory.' }

    & $python -m pip install --target $packages --no-cache-dir --only-binary=:all: -r (Join-Path $PSScriptRoot 'requirements-research.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Could not install pinned research-only Python dependencies into the temporary directory.' }
    $env:PYTHONPATH = if ([string]::IsNullOrEmpty($previousPythonPath)) { $packages } else { $packages + [IO.Path]::PathSeparator + $previousPythonPath }
    & $python $testScript
    if ($LASTEXITCODE -ne 0) { throw 'Research split/model guard tests failed.' }

    $extractorOutput = @(& $node $extractor $csvPath --allow-network)
    if ($LASTEXITCODE -ne 0) { throw 'PhreshPhish train column extraction failed.' }
    $extraction = $extractorOutput[-1] | ConvertFrom-Json
    [IO.File]::WriteAllText($manifestPath, ($extraction | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))

    $testExtractor = Join-Path $nodeTools 'extract-test-columns.mjs'
    $testExtractorOutput = @(& $node $testExtractor $testCsvPath --allow-network)
    if ($LASTEXITCODE -ne 0) { throw 'Pinned PhreshPhish test URL extraction failed.' }
    $testExtraction = $testExtractorOutput[-1] | ConvertFrom-Json
    if ($testExtraction.datasetRevision -ne $extraction.datasetRevision) { throw 'Dataset revision changed between train and test extraction.' }
    [IO.File]::WriteAllText($testManifestPath, ($testExtraction | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))

    $benchmarkTestOutput = @(& $node $testExtractor $benchmarkTestCsvPath --allow-network --include-previously-inspected-row)
    if ($LASTEXITCODE -ne 0) { throw 'Full PhreshPhish test score extraction failed.' }
    $benchmarkTestExtraction = $benchmarkTestOutput[-1] | ConvertFrom-Json
    if ($benchmarkTestExtraction.datasetRevision -ne $extraction.datasetRevision) { throw 'Dataset revision changed before benchmark scoring.' }
    [IO.File]::WriteAllText($benchmarkTestManifestPath, ($benchmarkTestExtraction | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))

    $modelOutput = @(& $python $modelScript --csv $csvPath --manifest $manifestPath --psl $pslPath --output $outputDirectory `
        --official-test-csv $testCsvPath --test-manifest $testManifestPath `
        --benchmark-test-csv $benchmarkTestCsvPath --benchmark-test-manifest $benchmarkTestManifestPath)
    if ($LASTEXITCODE -ne 0) { throw 'Train-only research model screening failed.' }
    $modelReport = Get-Content -LiteralPath (Join-Path $outputDirectory 'model-screening-report.json') -Raw | ConvertFrom-Json

    $benchmarkExtractor = Join-Path $nodeTools 'extract-official-benchmarks.mjs'
    $benchmarkOutput = @(& $node $benchmarkExtractor $benchmarkDirectory --allow-network)
    if ($LASTEXITCODE -ne 0) { throw 'Official PhreshPhish benchmark list extraction failed.' }
    $benchmarkInventory = $benchmarkOutput[-1] | ConvertFrom-Json
    if ($benchmarkInventory.revision -ne $extraction.datasetRevision -or $benchmarkInventory.files -ne 976) {
        throw 'Official benchmark inventory revision or file count changed.'
    }
    $benchmarkReportPath = Join-Path $outputDirectory 'official-benchmark-report.json'
    $scorePath = Join-Path $outputDirectory 'phreshphish-full-test-scores.csv'
    $benchmarkEvaluator = Join-Path $PSScriptRoot 'evaluate-official-benchmarks.py'
    $benchmarkEvaluationOutput = @(& $python $benchmarkEvaluator --scores $scorePath `
        --score-sha256 $modelReport.fullTestBenchmarkScores.scoreCsvSha256 `
        --model-report (Join-Path $outputDirectory 'model-screening-report.json') `
        --benchmark-directory $benchmarkDirectory --output $benchmarkReportPath)
    if ($LASTEXITCODE -ne 0) { throw 'Official PhreshPhish low-base-rate benchmark evaluation failed.' }
    $benchmarkReport = Get-Content -LiteralPath $benchmarkReportPath -Raw | ConvertFrom-Json
    $benchmarkFileManifest = Get-Content -LiteralPath (Join-Path $benchmarkDirectory 'manifest.json') -Raw | ConvertFrom-Json
    $benchmarkSummary = foreach ($groupName in @('benchmark-005', 'benchmark-010', 'benchmark-050', 'benchmark-100', 'benchmark-500')) {
        foreach ($thresholdName in @('calibratedFpr_0.1%', 'calibratedFpr_0.5%', 'calibratedFpr_1.0%')) {
            $entry = $benchmarkReport.groups.$groupName.$thresholdName
            [pscustomobject]@{
                BaseRate = $groupName
                CalibrationTarget = $thresholdName
                Benchmarks = $entry.benchmarks
                SharedBenignRows = $entry.sharedBenignRows
                PhishRowsPerBenchmarkRange = $entry.phishRowsPerBenchmarkRange
                PrecisionMean = $entry.metrics.precision.mean
                PrecisionCI95 = $entry.metrics.precision.confidence95
                RecallMean = $entry.metrics.recall.mean
                RecallCI95 = $entry.metrics.recall.confidence95
                FalsePositiveRateMean = $entry.metrics.falsePositiveRate.mean
                FalsePositiveRateCI95 = $entry.metrics.falsePositiveRate.confidence95
            }
        }
    }

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
    $runSummary = [pscustomobject]@{
        DatasetRevision = $modelReport.revision
        LicenseScope = 'CC BY 4.0; anti-phishing research only; no product model generated or distributed'
        TrainRows = $extraction.rows
        TrainCsvSha256 = $extraction.extractedCsvSha256
        TrainRecordIdsSha256 = $modelReport.sourceRecordIdsSha256
        TestRows = $testExtraction.rows
        TestCsvSha256 = $testExtraction.extractedCsvSha256
        FullBenchmarkTestRows = $benchmarkTestExtraction.rows
        FullBenchmarkTestCsvSha256 = $benchmarkTestExtraction.extractedCsvSha256
        Model = $modelReport.model
        Parameters = $modelReport.parameters
        SplitRows = $modelReport.splitRows
        SplitLabelCounts = $modelReport.splitLabelCounts
        ThresholdResults = $thresholdResults
        FrozenProductRules = $productRules
        BenchmarkInventorySha256 = $benchmarkReport.benchmarkInventorySha256
        BenchmarkFileChecksums = @($benchmarkFileManifest.files)
        ModelScoresSha256 = $benchmarkReport.modelScoresSha256
        BenchmarkBootstrap = $benchmarkReport.bootstrap
        OfficialLowBaseRateBenchmarkResults = @($benchmarkSummary)
        BenchmarkReport = [IO.Path]::GetRelativePath($repositoryRoot, $reportPath)
    }
    [IO.File]::WriteAllText($reportPath, ($runSummary | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    $runSummary | Select-Object * -ExcludeProperty BenchmarkFileChecksums | ConvertTo-Json -Depth 12
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
