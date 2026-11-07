# Protection Engine verification

## Automated tests

Run `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj`. Latest full Windows verification: run [42413895883](https://github.com/Matyyyy68/asystent/actions/runs/42413895883), commit [`6669812`](https://github.com/Matyyyy68/asystent/commit/66698128a6cf0ebc7472d192eaa4732e0ec9c726), passed .NET 565/565 and all 23 workflow steps. It includes installer headless and visible cycles and a disposable SCM service crash/restart test: CI terminated process 3188, observed SCM restart as PID 5496, and required a fresh Engine collection. This verifies configured recovery on the hosted Windows runner; it is not a physical clean-Windows install/reboot test.

The suite exercises store migrations, bounded queues/snapshots, process parent rules, synthetic short-lived WMI input, WMI-to-image-inspection persistence, quarantine integrity, Downloads races, DNS parsing, reputation imports, service IPC and browser/UI behavior. A redaction regression verifies Defender-exclusion snapshots retain opaque identifiers and fingerprints only; live registry visibility still depends on Windows ACL and service context.

Process lifecycle correlation tests now cover WMI stop and snapshot disappearance evicting a recent PID association. `RecentProcessStartCacheRebuildIgnoresPidWhoseLatestLifecycleEventIsStop` also verifies restart reconstruction uses only the latest start/stop lifecycle event for each PID. These tests use synthetic events and SQLite; they do not validate live WMI delivery.
 `DownloadHashWmiProcessInspectionAndTcpObservationShareOneIncidentId` sends synthetic download-hash evidence through process-image inspection and TCP observation, then verifies a shared incident ID. It does not exercise live Windows events, a detector decision, automated response, or a user notification. A benign live-process WMI test checks a spawned `cmd.exe` when access is available; in the current sandbox WMI returns `ManagementException` and `Get-CimInstance` returns `Access denied`, so that test exercised the explicit snapshot-fallback state. The live WMI subscription was not validated here.

`ProtectionHealthEvaluatorTests` cover initialization, paused monitoring, stale collection, WSC attention, WMI unavailability, and fail-closed handling of unknown or degraded collector strings (including incomplete TCP tables, dropped Downloads queue events, and uninitialized DNS). The Engine health object is consumed by the UI, while a failed SCM service heartbeat remains an overriding limitation.

The Engine IPC integration self-test starts the published Engine with isolated storage and checks process lifecycle collection, Downloads/hash/quarantine behavior, analysis, and privacy constraints. The Windows SCM integration test verifies LocalService identity, protected ProgramData ACL, first collection, authenticated status/history pipes, Agent event forwarding and persistence. Downloads tests also cover feed-version recheck, checkpoint resume after restart, and idempotent match IDs. Neither synthetic IPC nor an isolated hosted runner proves live WMI delivery or installation behavior on a physical user PC.

## Not covered by this run

- A real multi-source incident from file download through process start, network, risk and response in Windows.
- Live WFP/ETW, since those collectors are not implemented.
- Resource benchmarks on typical and older hardware.
- Physical clean-Windows install/reboot/upgrade testing.
- Independent threat-detection precision/recall holdout metrics.

CI on a Windows runner is required for packaging and integration claims; a runner is not the user's physical device. Existing runs are listed in [project progress](PROJECT_PROGRESS.md).
