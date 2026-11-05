# Response engine

## Current actions

- Rule and reputation findings are persisted as local security events and optionally presented through the Agent tray notification limiter.
- A user can explicitly quarantine eligible downloaded files. Quarantine stores origin/hash/reason metadata and verifies integrity before restore. Restoration of a known local-hash match uses a separate confirmation path.
- The process-image queue hashes and checks Authenticode asynchronously; it does not terminate the process.

## Not implemented

- Automatic termination or suspension of a process.
- WFP firewall rules or network isolation.
- Automatic quarantine based on AI or an unverified heuristic.
- A general policy engine that chooses and audits reversible response actions.

Notifications must state “detected” or “review recommended” unless code confirms that a specific action completed. “Blocked,” “isolated,” and “removed” are not valid claims for these detections. See [quarantine implementation](../src/Sentinel.Core/Analysis/DownloadedFileQuarantine.cs) and [autonomous protection limits](AUTONOMOUS_PROTECTION.md).
