# Performance and resource controls

## Current bounds

- WMI process events use a 4,096-event queue; overflow drops the new event and exposes a counter.
- Process snapshots are capped at 10,000 PIDs, 100 persisted process changes per sample, and a 20,000-item backlog.
- Asynchronous process image inspection has a single reader, bounded channel capacity 33, and 256 MiB image limit.
- Downloads monitoring has bounded pending paths, a 100,000-entry baseline, at most 10 file inspections/512 MiB per sample, and 256 MiB per-file limit.
- TCP/UDP and persistence enumeration have per-sample caps. Database retention and event history are bounded by settings.

These are explicit workload limits, not measured CPU/RAM service-level objectives. The current test suite includes selected large-snapshot and bounded-queue cases, but no representative idle/event-load CPU or RAM benchmark, event-throughput target, or end-to-end detection-latency benchmark. Do not claim a quantified low CPU percentage until measured on supported hardware.
