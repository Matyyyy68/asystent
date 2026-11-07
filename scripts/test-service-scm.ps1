$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'SCM service integration test requires Windows.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$interactiveUserSid = $identity.User.Value
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'SCM service integration test requires the isolated Windows runner to be elevated.'
}

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$enginePublish = [IO.Path]::GetFullPath((Join-Path $repo 'artifacts/engine'))
$servicePublish = [IO.Path]::GetFullPath((Join-Path $repo 'artifacts/service'))
$tempRoot = [IO.Path]::GetFullPath((Join-Path $env:TEMP ('Sentinel-Service-SCM-' + [Guid]::NewGuid().ToString('N'))))
$serviceName = 'Sentinel AI Core'
$serviceDataRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'Sentinel AI Service'))
$serviceCreated = $false
$serviceDeleted = $false
$mayRemoveServiceDataRoot = $false

function Invoke-Sc([string[]] $Arguments) {
  $result = & sc.exe @Arguments 2>&1
  if ($LASTEXITCODE -ne 0) { throw "sc.exe $($Arguments[0]) failed with code ${LASTEXITCODE}: $($result -join ' ')" }
  return $result
}

function Assert-Within([string] $Child, [string] $Parent) {
  $parentPrefix = [IO.Path]::GetFullPath($Parent).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  $childFull = [IO.Path]::GetFullPath($Child)
  if (-not $childFull.StartsWith($parentPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing file operation outside intended root: $childFull"
  }
}

function Wait-ServiceState([string] $Name, [string] $Expected, [int] $TimeoutSeconds) {
  $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
  do {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status.ToString() -eq $Expected) { return $service }
    Start-Sleep -Milliseconds 250
  } while ([DateTimeOffset]::UtcNow -lt $deadline)
  $actual = (Get-Service -Name $Name -ErrorAction SilentlyContinue)?.Status
  throw "Service '$Name' did not reach $Expected; current state: $actual"
}

function Read-ServiceStatus {
  $statusPipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'SentinelAI.Service.Status.v1',
    [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None,
    [Security.Principal.TokenImpersonationLevel]::Impersonation)
  $statusReader = $null
  $statusWriter = $null
  try {
    $statusPipe.Connect(1500)
    $statusReader = [IO.StreamReader]::new($statusPipe, [Text.UTF8Encoding]::new($false), $false, 1024, $true)
    $statusWriter = [IO.StreamWriter]::new($statusPipe, [Text.UTF8Encoding]::new($false), 1024, $true)
    $statusWriter.AutoFlush = $true
    $requestId = 'engine-recovery-' + [Guid]::NewGuid().ToString('N')
    $statusWriter.WriteLine(('{"id":"' + $requestId + '","version":1,"method":"status"}'))
    $line = $statusReader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) { return $null }
    $response = $line | ConvertFrom-Json
    if ($response.id -ne $requestId -or $response.ok -ne $true -or $response.result.state -ne 'running' -or
        [string]::IsNullOrWhiteSpace($response.result.lastCollectionAtUtc)) { return $null }
    return $response.result
  } catch { return $null }
  finally {
    if ($null -ne $statusReader) { $statusReader.Dispose() }
    if ($null -ne $statusWriter) { $statusWriter.Dispose() }
    $statusPipe.Dispose()
  }
}

try {
  if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "Refusing to replace an existing Windows service named '$serviceName'."
  }
  if (Test-Path -LiteralPath $serviceDataRoot) {
    throw "Refusing to use existing service data directory '$serviceDataRoot'."
  }
  if (-not (Test-Path -LiteralPath (Join-Path $enginePublish 'Sentinel.Engine.exe') -PathType Leaf)) {
    throw "Engine publish is missing Sentinel.Engine.exe: $enginePublish"
  }
  if (-not (Test-Path -LiteralPath (Join-Path $servicePublish 'Sentinel.Service.exe') -PathType Leaf)) {
    throw "Service publish is missing Sentinel.Service.exe: $servicePublish"
  }

  New-Item -ItemType Directory -Path $tempRoot | Out-Null
  Assert-Within $tempRoot ([IO.Path]::GetTempPath())
  if (((Get-Item -LiteralPath $tempRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Refusing to use a reparse-point service test directory.'
  }
  Copy-Item -Path (Join-Path $enginePublish '*') -Destination $tempRoot -Recurse -Force
  Copy-Item -Path (Join-Path $servicePublish '*') -Destination $tempRoot -Recurse -Force
  $serviceExe = [IO.Path]::GetFullPath((Join-Path $tempRoot 'Sentinel.Service.exe'))
  if (-not (Test-Path -LiteralPath $serviceExe -PathType Leaf) -or
      -not (Test-Path -LiteralPath (Join-Path $tempRoot 'Sentinel.Engine.exe') -PathType Leaf)) {
    throw 'Isolated service directory does not contain both executable payloads.'
  }

  # LocalService cannot execute a user-private %TEMP% directory by default.
  # Grant it read/execute only on this unique test payload; service data keeps
  # its separate protected ProgramData DACL.
  & icacls.exe $tempRoot /grant '*S-1-5-19:(OI)(CI)(RX)' /T /C | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not grant LocalService read/execute access to the isolated service payload (icacls exit $LASTEXITCODE)." }

  $quotedBinPath = '"' + $serviceExe + '" --allowed-user-sid=' + $interactiveUserSid
  Invoke-Sc @('create', $serviceName, 'binPath=', $quotedBinPath, 'start=', 'demand', 'obj=', 'NT AUTHORITY\LocalService') | Out-Null
  $serviceCreated = $true
  $mayRemoveServiceDataRoot = $true
  # Use short recovery delays only for this disposable CI service so the crash/restart test stays bounded.
  Invoke-Sc @('failure', $serviceName, 'reset=', '86400', 'actions=', 'restart/1000/restart/1000/none/0') | Out-Null
  Invoke-Sc @('failureflag', $serviceName, '1') | Out-Null
  Invoke-Sc @('start', $serviceName) | Out-Null
  Wait-ServiceState $serviceName 'Running' 90 | Out-Null

  $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='Sentinel AI Core'"
  if ($serviceInfo.StartName -ne 'NT AUTHORITY\LocalService') {
    throw "Service is running under unexpected account '$($serviceInfo.StartName)'."
  }

  if (-not (Test-Path -LiteralPath $serviceDataRoot)) { throw 'Service did not create its protected ProgramData directory.' }
  $acl = Get-Acl -LiteralPath $serviceDataRoot
  if (-not $acl.AreAccessRulesProtected) { throw 'Service data directory inherited a non-protected DACL.' }
  $aclRules = @($acl.Access)
  $actualSids = @($aclRules | ForEach-Object {
    try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
    catch { throw "Unexpected non-SID ACL identity in service data directory: $($_.IdentityReference)" }
  } | Sort-Object -Unique)
  $expectedSids = @('S-1-5-18', 'S-1-5-19', 'S-1-5-32-544') | Sort-Object -Unique
  $badRules = @($aclRules | Where-Object {
    $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
    $_.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
    $_.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or
    $_.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None
  })
  if ($aclRules.Count -ne 3 -or $badRules.Count -ne 0 -or (Compare-Object -ReferenceObject $expectedSids -DifferenceObject $actualSids)) {
    throw "Service data directory has unexpected ACL SIDs: $($actualSids -join ', ')"
  }

  $logPath = Join-Path $serviceDataRoot 'service.log'
  $deadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
  do {
    $log = if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Raw } else { '' }
    if ($log.Contains('CORE_FIRST_COLLECTION_COMPLETED')) { break }
    Start-Sleep -Milliseconds 250
  } while ([DateTimeOffset]::UtcNow -lt $deadline)
  if (-not $log.Contains('CORE_FIRST_COLLECTION_COMPLETED')) {
    throw 'Service did not finish its first real Engine collection within 90 seconds.'
  }

  $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'SentinelAI.Service.Status.v1', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)
  $reader = $null
  $writer = $null
  try {
    $pipe.Connect(5000)
    $reader = [IO.StreamReader]::new($pipe, [Text.UTF8Encoding]::new($false), $false, 1024, $true)
    $writer = [IO.StreamWriter]::new($pipe, [Text.UTF8Encoding]::new($false), 1024, $true)
    $writer.AutoFlush = $true
    $writer.WriteLine('{"id":"scm-smoke","version":1,"method":"status"}')
    $statusLine = $reader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($statusLine)) { throw 'Service status pipe returned no response.' }
    $statusResponse = $statusLine | ConvertFrom-Json
    if ($statusResponse.id -ne 'scm-smoke' -or $statusResponse.version -ne 1 -or
        $statusResponse.ok -ne $true -or $statusResponse.result.state -ne 'running' -or
        [string]::IsNullOrWhiteSpace($statusResponse.result.lastCollectionAtUtc)) {
      throw "Service status pipe returned an unexpected health response: $statusLine"
    }
  } finally {
    if ($null -ne $reader) { $reader.Dispose() }
    if ($null -ne $writer) { $writer.Dispose() }
    $pipe.Dispose()
  }

  $electronPipeTest = Join-Path $PSScriptRoot 'test-service-status-pipe.cjs'
  $electronPipeOutput = & node $electronPipeTest 2>&1
  if ($LASTEXITCODE -ne 0) {
    $pipeFailure = if (Test-Path -LiteralPath $logPath) {
      Get-Content -LiteralPath $logPath | Where-Object { $_ -match 'STATUS_PIPE_REQUEST_FAILED' } | Select-Object -Last 1
    } else { $null }
    throw "Electron named-pipe health client failed: $($electronPipeOutput -join ' '); service pipe diagnostic: $pipeFailure"
  }
  Write-Host ($electronPipeOutput -join ' ')

  $agentPipeClient = Join-Path $enginePublish 'Sentinel.Agent.exe'
  $agentPipeTest = Start-Process -FilePath $agentPipeClient -ArgumentList '--self-test-service-events' -PassThru -WindowStyle Hidden
  if (-not $agentPipeTest.WaitForExit(10000)) {
    Stop-Process -Id $agentPipeTest.Id -Force -ErrorAction SilentlyContinue
    throw 'Sentinel.Agent event-pipe client did not complete its bounded smoke test.'
  }
  if ($agentPipeTest.ExitCode -ne 0) { throw "Sentinel.Agent event-pipe client failed with exit code $($agentPipeTest.ExitCode)." }

  $agentForwardingError = Join-Path $tempRoot 'agent-forwarding-self-test.stderr.txt'
  $agentForwardingTest = Start-Process -FilePath $agentPipeClient -ArgumentList '--self-test-service-event-forwarding' `
    -PassThru -WindowStyle Hidden -RedirectStandardError $agentForwardingError
  if (-not $agentForwardingTest.WaitForExit(10000)) {
    Stop-Process -Id $agentForwardingTest.Id -Force -ErrorAction SilentlyContinue
    throw 'Sentinel.Agent event-forwarding request did not receive a bounded Service acknowledgement.'
  }
  if ($agentForwardingTest.ExitCode -ne 0) {
    $diagnostic = if (Test-Path -LiteralPath $agentForwardingError) { (Get-Content -LiteralPath $agentForwardingError -Raw).Trim() } else { 'no diagnostic' }
    throw "Sentinel.Agent event-forwarding request failed with exit code $($agentForwardingTest.ExitCode): $diagnostic"
  }

  $agentDiagnosticsError = Join-Path $tempRoot 'agent-engine-diagnostics-self-test.stderr.txt'
  $agentDiagnosticsTest = Start-Process -FilePath $agentPipeClient -ArgumentList '--self-test-core-engine-diagnostics' `
    -PassThru -WindowStyle Hidden -RedirectStandardError $agentDiagnosticsError
  if (-not $agentDiagnosticsTest.WaitForExit(60000)) {
    Stop-Process -Id $agentDiagnosticsTest.Id -Force -ErrorAction SilentlyContinue
    throw 'Sentinel.Agent sanitized Engine diagnostics pipe test did not complete within 60 seconds.'
  }
  if ($agentDiagnosticsTest.ExitCode -ne 0) {
    $diagnostic = if (Test-Path -LiteralPath $agentDiagnosticsError) { (Get-Content -LiteralPath $agentDiagnosticsError -Raw).Trim() } else { 'no diagnostic' }
    throw "Sentinel.Agent sanitized Engine diagnostics pipe test failed with exit code $($agentDiagnosticsTest.ExitCode): $diagnostic"
  }

  $forwardedPipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'SentinelAI.Service.Status.v1', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)
  $forwardedReader = $null
  $forwardedWriter = $null
  try {
    $forwardedPipe.Connect(5000)
    $forwardedReader = [IO.StreamReader]::new($forwardedPipe, [Text.UTF8Encoding]::new($false), $false, 1024, $true)
    $forwardedWriter = [IO.StreamWriter]::new($forwardedPipe, [Text.UTF8Encoding]::new($false), 1024, $true)
    $forwardedWriter.AutoFlush = $true
    $forwardedWriter.WriteLine('{"id":"agent-forwarding-history","version":1,"method":"recentEvents"}')
    $forwardedLine = $forwardedReader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($forwardedLine)) { throw 'Service returned no history after Agent forwarding.' }
    $forwardedResponse = $forwardedLine | ConvertFrom-Json
    if ($forwardedResponse.id -ne 'agent-forwarding-history' -or $forwardedResponse.ok -ne $true -or
        -not ($forwardedResponse.result.events | Where-Object { $_.source -eq 'agent-forwarding-self-test' -and $_.category -eq 'Agent forwarding self-test' })) {
      throw "Agent acknowledged forwarding but its event was not present in Service history: $forwardedLine"
    }
  } finally {
    if ($null -ne $forwardedReader) { $forwardedReader.Dispose() }
    if ($null -ne $forwardedWriter) { $forwardedWriter.Dispose() }
    $forwardedPipe.Dispose()
  }

  $serviceBeforeCrash = Get-CimInstance Win32_Service -Filter "Name='Sentinel AI Core'"
  $serviceProcessId = [int]$serviceBeforeCrash.ProcessId
  $engineProcess = Get-CimInstance Win32_Process -Filter "Name='Sentinel.Engine.exe'" |
    Where-Object { [int]$_.ParentProcessId -eq $serviceProcessId } | Select-Object -First 1
  if ($serviceBeforeCrash.State -ne 'Running' -or $serviceProcessId -le 0 -or $null -eq $engineProcess -or [int]$engineProcess.ProcessId -le 0) {
    throw 'Could not identify the running isolated service and Engine processes for the Engine recovery test.'
  }
  $engineProcessId = [int]$engineProcess.ProcessId
  $engineStartsBeforeFailure = [regex]::Matches($log, 'ENGINE_STARTED under service account').Count
  $collectionBeforeEngineFailure = [DateTimeOffset]::Parse($statusResponse.result.lastCollectionAtUtc).ToUniversalTime()
  & taskkill.exe /PID $engineProcessId /T /F | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not terminate the isolated Engine process for its recovery test (exit $LASTEXITCODE)." }

  $engineRecoveryDeadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
  $engineRecoveryVerified = $false
  do {
    $log = if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Raw } else { '' }
    $currentService = Get-CimInstance Win32_Service -Filter "Name='Sentinel AI Core'"
    $currentEngine = Get-CimInstance Win32_Process -Filter "Name='Sentinel.Engine.exe'" |
      Where-Object { [int]$_.ParentProcessId -eq $serviceProcessId } | Select-Object -First 1
    if ([regex]::Matches($log, 'ENGINE_STARTED under service account').Count -gt $engineStartsBeforeFailure -and
        $currentService.State -eq 'Running' -and [int]$currentService.ProcessId -eq $serviceProcessId -and
        $null -ne $currentEngine -and [int]$currentEngine.ProcessId -ne $engineProcessId) {
      $currentStatus = Read-ServiceStatus
      if ($null -ne $currentStatus -and
          [DateTimeOffset]::Parse($currentStatus.lastCollectionAtUtc).ToUniversalTime() -gt $collectionBeforeEngineFailure) {
        $engineRecoveryVerified = $true
        break
      }
    }
    Start-Sleep -Milliseconds 500
  } while ([DateTimeOffset]::UtcNow -lt $engineRecoveryDeadline)
  if (-not $engineRecoveryVerified) {
    throw "Service did not restart Engine process $engineProcessId and report a fresh collection while retaining service PID $serviceProcessId."
  }
  Write-Host "PASS: Service restarted Engine process $engineProcessId while retaining service PID $serviceProcessId and reported a fresh collection."

  $serviceBeforeCrash = Get-CimInstance Win32_Service -Filter "Name='Sentinel AI Core'"
  $crashedProcessId = [int]$serviceBeforeCrash.ProcessId
  if ($serviceBeforeCrash.State -ne 'Running' -or $crashedProcessId -le 0) {
    throw 'Could not identify the running isolated service process for the recovery test.'
  }
  $collectionsBeforeCrash = [regex]::Matches($log, 'CORE_FIRST_COLLECTION_COMPLETED').Count
  & taskkill.exe /PID $crashedProcessId /T /F | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Could not terminate the isolated service process for its recovery test (exit $LASTEXITCODE)." }

  $restartDeadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
  $restartedService = $null
  do {
    $candidate = Get-CimInstance Win32_Service -Filter "Name='Sentinel AI Core'"
    if ($candidate.State -eq 'Running' -and [int]$candidate.ProcessId -gt 0 -and [int]$candidate.ProcessId -ne $crashedProcessId) {
      $restartedService = $candidate
      break
    }
    Start-Sleep -Milliseconds 250
  } while ([DateTimeOffset]::UtcNow -lt $restartDeadline)
  if ($null -eq $restartedService) {
    throw "SCM did not restart the isolated service after process $crashedProcessId terminated."
  }

  $collectionDeadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
  do {
    $log = if (Test-Path -LiteralPath $logPath) { Get-Content -LiteralPath $logPath -Raw } else { '' }
    if ([regex]::Matches($log, 'CORE_FIRST_COLLECTION_COMPLETED').Count -gt $collectionsBeforeCrash) { break }
    Start-Sleep -Milliseconds 250
  } while ([DateTimeOffset]::UtcNow -lt $collectionDeadline)
  if ([regex]::Matches($log, 'CORE_FIRST_COLLECTION_COMPLETED').Count -le $collectionsBeforeCrash) {
    throw 'SCM restarted the service process, but it did not complete a fresh Engine collection.'
  }
  Write-Host "PASS: SCM automatically restarted process $crashedProcessId as PID $($restartedService.ProcessId), and the Engine completed a fresh collection."

  Invoke-Sc @('stop', $serviceName) | Out-Null
  Wait-ServiceState $serviceName 'Stopped' 30 | Out-Null
  Write-Host 'PASS: SCM start/stop/recovery, LocalService identity, protected ProgramData DACL, first and post-recovery Engine collection, authenticated status and event pipes, Agent Engine diagnostics, Agent event read and Agent-to-Service persisted event forwarding.'
}
finally {
  if ($serviceCreated) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
      & sc.exe stop $serviceName | Out-Null
      try { Wait-ServiceState $serviceName 'Stopped' 30 | Out-Null } catch { Write-Warning $_ }
    }
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not delete the temporary SCM service; preserving its payload at '$tempRoot'." }
    $deleteDeadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    do {
      $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
      if ($null -eq $service) { break }
      Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deleteDeadline)
    $serviceDeleted = $null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)
    if (-not $serviceDeleted) { throw "Temporary SCM service remains registered; preserving its payload at '$tempRoot'." }
  } else {
    $serviceDeleted = $true
  }
  if ($serviceDeleted -and (Test-Path -LiteralPath $tempRoot)) {
    Assert-Within $tempRoot ([IO.Path]::GetTempPath())
    if (((Get-Item -LiteralPath $tempRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Refusing to delete reparse-point test directory '$tempRoot'."
    }
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
  if ($serviceDeleted -and $mayRemoveServiceDataRoot -and (Test-Path -LiteralPath $serviceDataRoot)) {
    $dataInfo = Get-Item -LiteralPath $serviceDataRoot -Force
    if (($dataInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Refusing to delete reparse-point service data directory '$serviceDataRoot'."
    }
    $expectedDataPath = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'Sentinel AI Service'))
    if (-not [String]::Equals($expectedDataPath,$serviceDataRoot,[StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to delete unexpected service data path '$serviceDataRoot'."
    }
    Remove-Item -LiteralPath $serviceDataRoot -Recurse -Force
  }
}

