param(
    [Parameter(Mandatory = $true)][string]$ProgramDirectory,
    [string]$DataDirectory = "$env:ProgramData\SentinelAI\Server",
    [ValidateRange(1024, 65535)][int]$ApiPort = 5080
)
$ErrorActionPreference = 'Stop'
$serviceName = 'SentinelAI.Server'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Uruchom instalator jako administrator.' }
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -notin 2, 3) { throw 'Ten pakiet wymaga Windows Server.' }
$program = [IO.Path]::GetFullPath($ProgramDirectory)
$data = [IO.Path]::GetFullPath($DataDirectory)
$executable = Join-Path $program 'Sentinel.Server.Api.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw "Nie znaleziono pliku serwera: $executable" }
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Usługa już istnieje. Użyj procedury aktualizacji zamiast ponownej instalacji.' }
if (Get-NetTCPConnection -LocalPort $ApiPort -State Listen -ErrorAction SilentlyContinue) { throw "Port $ApiPort jest już zajęty." }
$drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($data))
if ($drive.AvailableFreeSpace -lt 1GB) { throw 'Wymagany jest co najmniej 1 GB wolnego miejsca na dysku danych.' }

New-Item -ItemType Directory -Force -Path $data | Out-Null
$serviceAccount = "NT SERVICE\$serviceName"
$create = & sc.exe create $serviceName binPath= "`"$executable`"" start= auto obj= $serviceAccount DisplayName= 'Sentinel AI Server'
if ($LASTEXITCODE -ne 0) { throw "Nie udało się utworzyć usługi: $($create -join ' ')" }
try {
    & sc.exe description $serviceName 'Centralny serwer zarządzania Sentinel AI.' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Nie udało się ustawić opisu usługi.' }
    & sc.exe sidtype $serviceName unrestricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Nie udało się włączyć identyfikatora usługi.' }
    & sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Nie udało się skonfigurować odzyskiwania po awarii.' }

    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString `
        -Value @("Sentinel__DataDirectory=$data", "ASPNETCORE_URLS=http://127.0.0.1:$ApiPort") -Force | Out-Null
    & icacls.exe $data /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' "$($serviceAccount):(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Nie udało się ograniczyć dostępu do katalogu danych.' }

    $previousDataDirectory = $env:Sentinel__DataDirectory
    try {
        $env:Sentinel__DataDirectory = $data
        & $executable --bootstrap-admin
        if ($LASTEXITCODE -ne 0) { throw 'Nie utworzono pierwszego konta administratora.' }
    }
    finally { $env:Sentinel__DataDirectory = $previousDataDirectory }

    Start-Service -Name $serviceName
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Seconds 1
        try {
            $response = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/readyz" -TimeoutSec 2
            if ($response.status -eq 'ready') { $ready = $true; break }
        }
        catch { }
    }
    if (-not $ready) { throw 'Usługa nie osiągnęła stanu ready w ciągu 30 sekund.' }
    Write-Host "Sentinel AI Server działa. Panel: http://127.0.0.1:$ApiPort/admin/"
    Write-Host "Dane użytkownika zachowano w: $data"
}
catch {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $serviceName | Out-Null
    throw
}
