# File monitoring

## What runs

`DownloadedFileMonitor` watches the current Windows Downloads directory with `FileSystemWatcher`, persists a bounded fingerprint baseline, and reconciles it periodically so watcher overflow or service restart does not silently reset all history. A file is opened with sharing that permits normal use, checked for stable size/write time during SHA-256 calculation, and matched against an imported local hash list. Existing-file scanning is bounded; each sample handles at most 10 files and 512 MiB total, with a 256 MiB per-file limit. The baseline is capped at 100,000 paths.

`DownloadedFileQuarantine` supports an explicit local quarantine/restore flow with hash verification and metadata. A local hash-list match is recorded as a signal; it is not an automatic malware verdict or automatic deletion.

## Does not run

- No system-wide minifilter or continuous monitoring of every directory.
- No repeated whole-disk scans.
- No automatic execution of unknown files or upload of file contents to an AI model.
- No verified signed, incremental malware database with provenance and expiry.
- No automatic quarantine based only on a weak heuristic.

The Downloads watcher and reconciliation path have tests for bounded work, symlink/junction races, persistence, and safe file handling. See [Windows monitoring](WINDOWS_MONITORING.md) and [privacy](PRIVACY.md).
