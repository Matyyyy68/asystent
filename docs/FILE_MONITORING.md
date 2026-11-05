# File monitoring

## What runs

`DownloadedFileMonitor` watches the current Windows Downloads directory with `FileSystemWatcher`, persists a bounded fingerprint baseline, and reconciles it periodically so watcher overflow or service restart does not silently reset all history. A changed file is opened with sharing that permits normal use and checked for stable size/write time during SHA-256 calculation. Hashing runs even when no reputation list is configured; in that case the fingerprint is baselined without a threat-match verdict, and the UI reports the missing list. When a new local hash list is imported while monitoring is active, the monitor schedules a bounded recheck of the existing baseline. It records the feed timestamp and resumes an interrupted recheck after restart; stable event IDs prevent duplicate match alerts for the same feed version and hash. Each sample handles at most 10 files and 512 MiB total, with a 256 MiB per-file limit. The baseline is capped at 100,000 paths.

The persistence monitor also watches the user and common Startup folders with non-recursive, bounded-buffer `FileSystemWatcher` instances. Notifications only request an early snapshot; the existing snapshot diff remains the source of stored events and alerts. If watcher creation or delivery fails, the monitor exposes a degraded diagnostic and retains its periodic snapshot fallback. Watchers are disposed when monitoring is paused or the monitor stops. This covers the selected Startup folders; it is not system-wide file monitoring.

`DownloadedFileQuarantine` supports an explicit local quarantine/restore flow with hash verification and metadata. A local hash-list match is recorded as a signal; it is not an automatic malware verdict or automatic deletion.

## Does not run

- No system-wide minifilter or continuous monitoring of every directory.
- No repeated whole-disk scans.
- No automatic execution of unknown files or upload of file contents to an AI model.
- No verified signed, incremental malware database with provenance and expiry.
- No automatic quarantine based only on a weak heuristic.

The Downloads watcher and reconciliation path have tests for bounded work, symlink/junction races, persistence, and safe file handling. See [Windows monitoring](WINDOWS_MONITORING.md) and [privacy](PRIVACY.md).
