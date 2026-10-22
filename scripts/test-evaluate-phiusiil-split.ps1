$ErrorActionPreference = 'Stop'
$fixture = Join-Path $env:TEMP ('sentinel-domain-split-' + [Guid]::NewGuid().ToString('N') + '.csv')
$lines = @'
URL,label
https://a.test/login,0
https://login.a.test/account,0
https://b.test/login,1
https://login.b.test/account,1
https://c.test/login,0
https://login.c.test/account,0
https://d.test/login,1
https://login.d.test/account,1
https://e.test/login,0
https://login.e.test/account,0
https://f.test/login,1
https://login.f.test/account,1
https://g.test/login,0
https://login.g.test/account,0
https://h.test/login,1
https://login.h.test/account,1
not a URL,0
'@ -split "`r?`n"
$lines = $lines | Where-Object { $_.Length -gt 0 }
Set-Content -LiteralPath $fixture -Value $lines -Encoding UTF8

try {
    $evaluator = Join-Path $PSScriptRoot 'evaluate-phiusiil.ps1'
    $first = @(& $evaluator -CsvPath $fixture -DomainHoldoutPercent 50 -SplitSeed 'regression-seed')
    $second = @(& $evaluator -CsvPath $fixture -DomainHoldoutPercent 50 -SplitSeed 'regression-seed')
    $train = $first | Where-Object Partition -eq 'DomainTrain'
    $holdout = $first | Where-Object Partition -eq 'DomainHoldout'
    if ($first.Count -ne 3 -or $train.Count -ne 1 -or $holdout.Count -ne 1) {
        throw 'Expected overall, domain-train, and domain-holdout metric rows.'
    }
    if (($train.Domains + $holdout.Domains) -ne 9 -or ($train.Rows + $holdout.Rows) -ne 17) {
        throw 'Domain split lost rows or assigned a domain to both partitions.'
    }
    if ($train.Domains -eq 0 -or $holdout.Domains -eq 0 -or ($train.InvalidUrl + $holdout.InvalidUrl) -ne 1) {
        throw 'Expected non-empty partitions and a separately grouped invalid URL.'
    }
    if (($train.TP + $train.FP + $train.TN + $train.FN) -ne $train.Rows -or
        ($holdout.TP + $holdout.FP + $holdout.TN + $holdout.FN) -ne $holdout.Rows) {
        throw 'Partition confusion matrices do not account for all rows.'
    }
    foreach ($partition in @('DomainTrain', 'DomainHoldout')) {
        $before = $first | Where-Object Partition -eq $partition
        $after = $second | Where-Object Partition -eq $partition
        if ($before.Domains -ne $after.Domains -or $before.Rows -ne $after.Rows -or
            $before.TP -ne $after.TP -or $before.FP -ne $after.FP -or
            $before.TN -ne $after.TN -or $before.FN -ne $after.FN) {
            throw 'Domain partition is not deterministic for a fixed seed.'
        }
    }
    Write-Output 'PASS: deterministic registrable-domain holdout, domain grouping, invalid rows, and confusion matrices'
}
finally {
    Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
}
