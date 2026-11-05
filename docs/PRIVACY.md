# Privacy and event data

## Local collection

The Agent and Engine keep event history in a local SQLite database. Process collection stores PID/name and limited evidence; command lines, passwords, keystrokes, screenshots, packet payloads and HTTPS content are not collected by this engine. Process image paths and hashes are local metadata used for inspection and may be excluded from service forwarding.

Downloads scanning hashes file bytes locally; it does not send whole files to AI. DNS names, connection metadata and local feed lookups are processed locally. A DNS cache entry is not a record of full browsing history or process attribution.

## Sharing and limits

Enterprise context sharing is separate and requires configuration/consent. Agent-to-Service forwarding sends bounded, redacted event summaries and omits file paths/hashes. Local event retention follows settings. Feed updates contact their configured HTTPS source but do not include analyzed URLs/domains.

This page describes the code paths in the current build. It is not a promise that every optional integration is enabled. See [privacy/security audit](PRIVACY_AND_SECURITY.md) and [Windows event collection](WINDOWS_EVENT_COLLECTION.md).
