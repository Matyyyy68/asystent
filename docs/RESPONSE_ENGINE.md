# Response engine

## Central response decision (2026-11-07)

`RiskEngine.DecideResponse` maps the evidence-derived `RiskLevel` to a bounded, auditable recommendation before a detection is persisted. Information is retained without an alert recommendation; Low is reviewed in history; Moderate recommends a notification and review; High and Critical recommend urgent user review. The recommendation code is appended to the persisted event text so the Engine, Service-forwarded event, history, and UI share the same decision context.

This policy does not terminate processes, block connections, or move files automatically. `AutomaticProtectionPerformed` remains false for every current action. Existing quarantine stays a separate user-confirmed operation restricted to eligible Downloads files. Notification delivery can still be disabled by the user's preference; the policy text is a recommendation and does not claim a toast was shown. Unit tests cover all severity mappings and invalid values.

## Existing actions

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
