# Protection Engine verification

## Automated tests

Run `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj`. Latest local verification: .NET 488 passed and 2 environment-dependent skips; targeted process/TCP/SQLite tests 117/117; targeted process-monitor tests 22/22; Downloads/SQLite/migration tests 141/141; Release solution build 0 warnings/errors; self-contained Engine publish and `node scripts/test-engine.cjs` passed before the latest correlation change. Full Windows CI [42071023558](https://github.com/Matyyyy68/asystent/actions/runs/42071023558) passed for complete-source head `23ca659`. Windows CI for the later WMI parent and process-network correlation changes is pending. The CI installation tests run in an isolated hosted Windows runner, not on the user's physical computer.

The suite exercises store migrations, bounded queues/snapshots, process parent rules, synthetic short-lived WMI input, WMI-to-image-inspection persistence, quarantine integrity, Downloads races, DNS parsing, reputation imports, service IPC and browser/UI behavior. `DownloadHashWmiProcessInspectionAndTcpObservationShareOneIncidentId` sends synthetic download-hash evidence through process-image inspection and TCP observation, then verifies a shared incident ID. It does not exercise live Windows events, a detector decision, automated response, or a user notification. A benign live-process WMI test checks a spawned `cmd.exe` when access is available; in the current sandbox WMI returns `ManagementException` and `Get-CimInstance` returns `Access denied`, so that test exercised the explicit snapshot-fallback state. The live WMI subscription was not validated here.

`ProtectionHealthEvaluatorTests` cover initialization, paused monitoring, stale collection, WSC attention, WMI unavailability, and fail-closed handling of unknown or degraded collector strings (including incomplete TCP tables, dropped Downloads queue events, and uninitialized DNS). The Engine health object is consumed by the UI, while a failed SCM service heartbeat remains an overriding limitation.

The Engine IPC integration self-test starts the published Engine with isolated storage and checks process lifecycle collection, Downloads/hash/quarantine behavior, analysis, and privacy constraints. The Windows SCM integration test verifies LocalService identity, protected ProgramData ACL, first collection, authenticated status/history pipes, Agent event forwarding and persistence. Downloads tests also cover feed-version recheck, checkpoint resume after restart, and idempotent match IDs. Neither synthetic IPC nor an isolated hosted runner proves live WMI delivery or installation behavior on a physical user PC.

## Not covered by this run

- A real multi-source incident from file download through process start, network, risk and response in Windows.
- Live WFP/ETW, since those collectors are not implemented.
- Resource benchmarks on typical and older hardware.
- Physical clean-Windows install/reboot/upgrade testing.
- Independent threat-detection precision/recall holdout metrics.

CI on a Windows runner is required for packaging and integration claims; a runner is not the user's physical device. Existing runs are listed in [project progress](PROJECT_PROGRESS.md).
