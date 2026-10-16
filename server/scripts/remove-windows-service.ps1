param([string]$DataDirectory = "$env:ProgramData\SentinelAI\Server", [switch]$DeleteData)
$ErrorActionPreference = 'Stop'
$serviceName = 'SentinelAI.Server'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Uruchom narzędzie jako administrator.' }
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Nie udało się usunąć usługi.' }
}
if ($DeleteData) {
    $path = [IO.Path]::GetFullPath($DataDirectory)
    if (Test-Path -LiteralPath $path) {
        $confirmation = Read-Host "Wpisz DELETE, aby trwale usunąć bazę i dane z $path"
        if ($confirmation -cne 'DELETE') { throw 'Usuwanie danych anulowano; pozostawiono je bez zmian.' }
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}
else { Write-Host "Usługę usunięto. Dane w %ProgramData%\SentinelAI\Server pozostawiono." }
