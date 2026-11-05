# Protection Engine verification

## Automated tests

Run `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj`. The current local run for this change reports 470 passed and 2 environment-dependent skips. Desktop tests: `npm test` in `desktop` (111 passed). Self-contained Release Windows Engine publish: `dotnet publish src/Sentinel.Engine/Sentinel.Engine.csproj -c Release -r win-x64 --self-contained true`.

The suite exercises store migrations, bounded queues/snapshots, process parent rules, synthetic short-lived WMI input, WMI-to-image-inspection persistence, quarantine integrity, Downloads races, DNS parsing, reputation imports, service IPC and browser/UI behavior. A benign live-process WMI test checks a spawned `cmd.exe` when access is available; in the current sandbox WMI returns `ManagementException` and `Get-CimInstance` returns `Access denied`, so that test exercised the explicit snapshot-fallback state. The live WMI subscription was not validated here.

## Not covered by this run

- A real multi-source incident from file download through process start, network, risk and response in Windows.
- Live WFP/ETW, since those collectors are not implemented.
- Resource benchmarks on typical and older hardware.
- Physical clean-Windows install/reboot/upgrade testing.
- Independent threat-detection precision/recall holdout metrics.

CI on a Windows runner is required for packaging and integration claims; a runner is not the user's physical device. Existing runs are listed in [project progress](PROJECT_PROGRESS.md).
