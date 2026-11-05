# Network monitoring

## Available observations

- Windows TCP/UDP tables are read through bounded native table APIs. The continuous monitor samples approximately once per Agent collect cycle and stores new eligible TCP observations plus local UDP endpoint observations. It has explicit count limits and associates a PID/name when Windows reports one.
- `WindowsDnsOperationalLogSource` reads the DNS Client Operational event log only if the channel is enabled and readable. A separate `ipconfig /displaydns` cache read is periodic. CERT Polska domain matches and imported local IP matches create local events.
- URL/IP/domain reputation data is checked locally after import/refresh. Network observations are not sent to a remote service by the default local lookup.

## Limits

This is not WFP, packet capture, NetFlow, or complete ETW. Very short TCP connections can be missed between snapshots. A UDP endpoint does not prove that a datagram was sent or identify its remote peer. DNS cache entries can outlive the query and do not prove which process made it. DoH/DoT, VPN and browser DNS can hide queries. Sentinel does not inspect packet payloads, decrypt HTTPS, or install a MITM certificate. It does not block a connection.

The UI and health status must say “snapshot/observation,” not imply a complete connection history. More detail: [Windows monitoring](WINDOWS_MONITORING.md), [privacy](PRIVACY.md).
