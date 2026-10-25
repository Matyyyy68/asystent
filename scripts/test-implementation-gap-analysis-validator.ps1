$ErrorActionPreference = 'Stop'

$source = Join-Path $PSScriptRoot '..\docs\IMPLEMENTATION_GAP_ANALYSIS.md'
$validator = Join-Path $PSScriptRoot 'test-implementation-gap-analysis.ps1'
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('sentinel-gap-matrix-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

function Invoke-MatrixValidator([string]$CandidatePath) {
  $output = & pwsh -NoProfile -File $validator -Path $CandidatePath 2>&1
  return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($output -join "`n") }
}

try {
  $valid = Join-Path $tempRoot 'valid.md'
  Copy-Item -LiteralPath $source -Destination $valid
  $result = Invoke-MatrixValidator $valid
  if ($result.ExitCode -ne 0) { throw "Valid matrix was rejected: $($result.Output)" }

  $missingPriority = Join-Path $tempRoot 'missing-priority.md'
  $content = Get-Content -LiteralPath $source -Raw
  $content = $content.Replace(' | P0 / M | Build/testy źródła', ' | Build/testy źródła')
  Set-Content -LiteralPath $missingPriority -Value $content -NoNewline -Encoding utf8
  $result = Invoke-MatrixValidator $missingPriority
  if ($result.ExitCode -eq 0) { throw 'Matrix validator accepted a row with a missing priority column' }

  $invalidStatus = Join-Path $tempRoot 'invalid-status.md'
  $content = Get-Content -LiteralPath $source -Raw
  $content = $content.Replace('| F01 Build klienta i UI | DONE_AND_VERIFIED |', '| F01 Build klienta i UI | UNKNOWN_STATUS |')
  Set-Content -LiteralPath $invalidStatus -Value $content -NoNewline -Encoding utf8
  $result = Invoke-MatrixValidator $invalidStatus
  if ($result.ExitCode -eq 0) { throw 'Matrix validator accepted an unknown status' }

  $duplicateId = Join-Path $tempRoot 'duplicate-id.md'
  $content = Get-Content -LiteralPath $source -Raw
  $content = $content.Replace('| F02 Instalator per-user |', '| F01 Instalator per-user |')
  Set-Content -LiteralPath $duplicateId -Value $content -NoNewline -Encoding utf8
  $result = Invoke-MatrixValidator $duplicateId
  if ($result.ExitCode -eq 0) { throw 'Matrix validator accepted a duplicate/non-sequential ID' }

  Write-Output 'Implementation gap matrix validator tests: PASS (valid, missing priority, invalid status, duplicate ID)'
} finally {
  Remove-Item -LiteralPath $tempRoot -Recurse -Force
}
