# Threat intelligence

## Implemented inputs

- Domain Reputation updates the CERT Polska domain feed over HTTPS, validates the feed format/checksum as implemented by the source adapter, and tracks refresh age/errors locally.
- URL, IP, and SHA-256 lists can be imported from local files into bounded local stores. File and IP list imports have byte limits; lookup stays local.
- A new SHA-256 feed version schedules a bounded recheck of the monitored Downloads baseline. The feed timestamp/checkpoint is stored locally so interrupted work can resume; repeated match events for the same feed version and hash are idempotent.
- MalwareBazaar lookup is an optional, explicit credential-backed feature; it is not required for baseline collection.

## Missing guarantees

There is no unified signed, versioned, incremental intelligence database spanning hashes/domains/IP/certificates/CVEs. Local user-imported lists do not carry a verified publisher signature, expiry, confidence or provenance contract. UI wording marks those matches as local and source-limited. No fabricated threat records are included. Offline rules and monitoring continue without remote reputation availability.

The product must expose feed source, last successful update and stale/unavailable status. It must not treat a missing feed as “clean.” See [privacy](PRIVACY.md), [network monitoring](NETWORK_MONITORING.md), and [detection](DETECTION_ENGINE.md).

