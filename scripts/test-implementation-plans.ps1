$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$plansDirectory = Join-Path $repositoryRoot 'docs\implementation-plans'
$planFiles = @(Get-ChildItem -LiteralPath $plansDirectory -Filter 'PLAN-*.md' -File | Sort-Object Name)
if ($planFiles.Count -lt 12) { throw "Expected at least 12 implementation plans; found $($planFiles.Count)." }

$expectedTitlePatterns = @(
    'Cel',
    'Stan obecny',
    'Braki',
    'Decyzje',
    'Zaleznosci',
    'Etapy',
    'Pliki|Zmiany w plikach',
    'Prywatnosc|Bezpieczenstwo',
    'Testy',
    'Akceptacj',
    'Ryzyka',
    'Status'
)
$headingPattern = '^\s*(?<number>\d+)\.\s+\*\*(?<title>[^*]+)\*\*'
function Remove-TitleDiacritics([string]$text) {
    $decomposed = $text.Normalize([Text.NormalizationForm]::FormD)
    return [regex]::Replace($decomposed, '\p{Mn}', '')
}
foreach ($plan in $planFiles) {
    $headings = @(Select-String -LiteralPath $plan.FullName -Pattern $headingPattern | ForEach-Object {
        [pscustomobject]@{ Number = [int]$_.Matches[0].Groups['number'].Value; Title = $_.Matches[0].Groups['title'].Value }
    })
    for ($index = 0; $index -lt $headings.Count; $index++) {
        $expectedNumber = $index + 1
        if ($headings[$index].Number -ne $expectedNumber) {
            throw "$($plan.Name) numbered headings must be unique and sequential; expected $expectedNumber, found $($headings[$index].Number)."
        }
    }
    foreach ($number in 1..12) {
        $matchesForSection = @($headings | Where-Object Number -eq $number)
        if ($matchesForSection.Count -ne 1) {
            throw "$($plan.Name) must contain exactly one numbered section $number; found $($matchesForSection.Count)."
        }
        $titlePattern = Remove-TitleDiacritics $expectedTitlePatterns[$number - 1]
        $actualTitle = Remove-TitleDiacritics $matchesForSection[0].Title
        if ($actualTitle -notmatch $titlePattern) {
            throw "$($plan.Name) section $number has unexpected title '$($matchesForSection[0].Title)' (expected '$titlePattern'; normalized '$actualTitle')."
        }
    }
    if (-not ($headings | Where-Object Number -eq 12 | Select-Object -First 1).Title.Contains('Status')) {
        throw "$($plan.Name) must end its required plan structure with a status section."
    }
}

Write-Output "PASS: all $($planFiles.Count) implementation plans contain the required 12 sections."
