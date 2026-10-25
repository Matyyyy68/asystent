param([string]$Path)
$ErrorActionPreference = 'Stop'

$analysisPath = if ([string]::IsNullOrWhiteSpace($Path)) {
  Join-Path $PSScriptRoot '..\docs\IMPLEMENTATION_GAP_ANALYSIS.md'
} else {
  $Path
}
if (-not (Test-Path -LiteralPath $analysisPath -PathType Leaf)) {
  throw "Implementation gap analysis not found: $analysisPath"
}

$lines = Get-Content -LiteralPath $analysisPath
$header = $lines | Where-Object { $_ -match '^\|\s*ID\s*/\s*funkcja\s*\|' } | Select-Object -First 1
if (-not $header) { throw 'Function matrix header was not found' }
$headerCells = $header.Split('|')
$headerColumnCount = $headerCells.Length - 2
if ($headerColumnCount -ne 6) {
  throw "Function matrix must have six columns; found $headerColumnCount"
}
$expectedHeaders = @('ID / funkcja', 'Status', 'Dowód i brak', 'Zależności', 'Priorytet / złożoność', 'Kryteria akceptacji')
$actualHeaders = @($headerCells[1..($headerCells.Length - 2)] | ForEach-Object { $_.Trim() })
for ($index = 0; $index -lt $expectedHeaders.Count; $index++) {
  if ($actualHeaders[$index] -ne $expectedHeaders[$index]) {
    throw "Function matrix header $($index + 1) must be '$($expectedHeaders[$index])'; found '$($actualHeaders[$index])'"
  }
}

$rows = @($lines | Where-Object { $_ -match '^\|\s*F\d{2}\b' })
if ($rows.Count -ne 21) {
  throw "Function matrix must contain 21 rows F01-F21; found $($rows.Count)"
}

$expectedIds = @(1..21 | ForEach-Object { 'F{0:D2}' -f $_ })
for ($index = 0; $index -lt $rows.Count; $index++) {
  $line = $rows[$index]
  $parts = $line.Split('|')
  $hasTrailingDelimiter = $line.TrimEnd().EndsWith('|')
  $columnCount = $parts.Length - 1
  if ($hasTrailingDelimiter) { $columnCount-- }
  if ($columnCount -ne $headerColumnCount) {
    throw "Matrix row $($expectedIds[$index]) has $columnCount columns; expected $headerColumnCount"
  }

  $lastCellIndex = if ($hasTrailingDelimiter) { $parts.Length - 2 } else { $parts.Length - 1 }
  $cells = @($parts[1..$lastCellIndex] | ForEach-Object { $_.Trim() })
  if ($cells[0] -notmatch ('^' + [regex]::Escape($expectedIds[$index]) + '\b')) {
    throw "Matrix row $($index + 1) must be $($expectedIds[$index]); found '$($cells[0])'"
  }
  foreach ($cellIndex in 0..5) {
    if ([string]::IsNullOrWhiteSpace($cells[$cellIndex])) {
      throw "Matrix row $($expectedIds[$index]) has an empty column $($cellIndex + 1)"
    }
  }
  $status = $cells[1].Trim('`')
  if ($status -notmatch '^(DONE_AND_VERIFIED|PARTIALLY_IMPLEMENTED|BLOCKED)(?:\b|$)') {
    throw "Matrix row $($expectedIds[$index]) has unrecognized status '$($cells[1])'"
  }
  if ($cells[4] -notmatch '^P[0-3]\s*/\s*[SML]$') {
    throw "Matrix row $($expectedIds[$index]) has invalid priority/complexity '$($cells[4])'"
  }
}

Write-Output 'Implementation gap matrix structure: PASS (21 rows, 6 columns, priorities and complexity present)'
