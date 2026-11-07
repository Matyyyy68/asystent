# Performance and resource controls

## Current bounds

- WMI process events use a 4,096-event queue; overflow drops the new event and exposes a counter.
- Process snapshots are capped at 10,000 PIDs, 100 persisted process changes per sample, and a 20,000-item backlog.
- Asynchronous process image inspection has a single reader, bounded channel capacity 33, and 256 MiB image limit.
- Downloads monitoring has bounded pending paths, a 100,000-entry baseline, at most 10 file inspections/512 MiB per sample, and 256 MiB per-file limit.
- TCP/UDP and persistence enumeration have per-sample caps. Database retention and event history are bounded by settings.

These are explicit workload limits, not product CPU/RAM service-level objectives. The benchmark now records Engine CPU, working set, collect latency, and observation rate/detection latency for a bounded TCP burst on the isolated Windows runner. The burst measures snapshot-observation delay and does not exercise WFP or packet inspection. No representative sustained event-load profile, older-hardware target, or fleet guarantee exists.

## Measurement methods

The Windows CI invokes `scripts/benchmark-engine.cjs --duration=30 --interval-ms=1000 --tcp-monitor --tcp-connections=32`. It creates 32 benign local client connections to one temporary listener, confirms each appears in Engine history, and prints CPU, working set, collect latency, and observed connection rate/delay. This is a short controlled snapshot workload, not a sustained traffic test or product SLO.

## Windows CI controlled burst measurement (2026-11-07)

Run [42315937630](https://github.com/Matyyyy68/asystent/actions/runs/42315937630) on an isolated Windows Server 2025 runner requested and observed 32/32 controlled TCP client connections. The Engine persisted 64 TCP snapshot events (client/server endpoints). Measured observed-client rate was 21.2 connections/s; detection latency was 1,511.5 ms median / 1,511.7 ms maximum, including 1-second polling. Across this 30-second profile, Engine CPU averaged 1.964% of total runner capacity, working set grew from 93.9 MiB to 132.9 MiB peak, and collect latency was 8.3 ms median / 479.2 ms maximum. This is a single hosted runner, with one bounded connection burst; it is not sustained-load performance, older-hardware evidence, or a product SLO.

## Local measurement (2026-11-05)

`node scripts/benchmark-engine.cjs --duration=30 --interval-ms=1000` completed 30 samples in a local Windows session: Engine CPU was 0.577% of total processor capacity, working set was 74.3 MiB at start and 79.9 MiB peak, and `collect` latency was 9.3 ms median / 126.4 ms maximum. The process snapshot contained 254 PIDs and no process changes. This is one short idle-like profile, not a workload stress test, event-throughput result, or fleet guarantee. No network listener was opened for this profile; storage used a disposable temp directory cleaned by the benchmark script.
