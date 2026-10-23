using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using Sentinel.Core.Analysis;

public sealed record ConnectionSnapshot(string Protocol, string LocalAddress, int LocalPort, string? RemoteAddress,
    int? RemotePort, string State, int ProcessId, string? ProcessName);

public sealed class ConnectionSnapshotBatch(IReadOnlyCollection<ConnectionSnapshot> connections,
    bool tcpTruncated = false, bool udpTruncated = false) : IReadOnlyCollection<ConnectionSnapshot>
{
    public IReadOnlyCollection<ConnectionSnapshot> Connections { get; } = connections ?? throw new ArgumentNullException(nameof(connections));
    public bool TcpTruncated { get; } = tcpTruncated;
    public bool UdpTruncated { get; } = udpTruncated;
    public int Count => Connections.Count;
    public IEnumerator<ConnectionSnapshot> GetEnumerator() => Connections.GetEnumerator();
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}

/// <summary>Opt-in, bounded polling of TCP metadata. It never inspects packet contents.</summary>
public sealed class TcpConnectionSnapshotMonitor
{
    private const int MaximumConnections = 10_000;
    private const int MaximumEventsPerSample = 100;
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(1);
    private readonly Func<CancellationToken, Task<IReadOnlyCollection<ConnectionSnapshot>>> capture;
    private readonly Func<int, string?, DateTimeOffset, Guid?> wasRecentlyObservedStart;
    private readonly Func<string, bool> matchesLocalIpFeed;
    private readonly TimeProvider timeProvider;
    private HashSet<string>? knownConnections;
    private HashSet<string>? knownUdpEndpoints;
    private bool knownTcpTruncated;
    private bool knownUdpTruncated;
    private DateTimeOffset? lastAttempt;
    private bool disabledModeHandled;

    public string State { get; private set; } = "Ciągła obserwacja TCP/UDP jest wyłączona.";

    public TcpConnectionSnapshotMonitor(
        Func<CancellationToken, Task<IReadOnlyCollection<ConnectionSnapshot>>> capture,
        TimeProvider? timeProvider = null,
        Func<int, string?, DateTimeOffset, Guid?>? wasRecentlyObservedStart = null,
        Func<string, bool>? matchesLocalIpFeed = null)
    {
        this.capture = capture ?? throw new ArgumentNullException(nameof(capture));
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.wasRecentlyObservedStart = wasRecentlyObservedStart ?? ((_, _, _) => null);
        this.matchesLocalIpFeed = matchesLocalIpFeed ?? (_ => false);
    }

    public async Task<int> CollectAsync(LocalStore store, bool enabled, bool paused, string excludedApplications,
        CancellationToken cancellationToken = default)
    {
        if (!enabled || paused)
        {
            if (!disabledModeHandled || knownConnections is not null || knownUdpEndpoints is not null)
            {
                try { await store.ResetNetworkMonitorSnapshotAsync(cancellationToken); }
                catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
                {
                    State = "Nie można unieważnić poprzedniej migawki TCP/UDP: baza osiągnęła limit lub brakuje miejsca.";
                    return 0;
                }
            }
            knownConnections = null;
            knownUdpEndpoints = null;
            knownTcpTruncated = false;
            knownUdpTruncated = false;
            lastAttempt = null;
            disabledModeHandled = true;
            State = enabled ? "Ciągła obserwacja TCP/UDP wstrzymana." : "Ciągła obserwacja TCP/UDP jest wyłączona.";
            return 0;
        }
        disabledModeHandled = false;

        var now = timeProvider.GetUtcNow();
        if (lastAttempt is { } previous && now - previous < SampleInterval) return 0;
        lastAttempt = now;

        IReadOnlyCollection<ConnectionSnapshot> sample;
        try { sample = await capture(cancellationToken); }
        catch (Exception exception)
        {
            try { await store.ResetNetworkMonitorSnapshotAsync(cancellationToken); }
            catch (SqliteException storageException) when (storageException.SqliteErrorCode == 13)
            {
                knownConnections = null;
                knownUdpEndpoints = null;
                knownTcpTruncated = false;
                knownUdpTruncated = false;
                State = "Migawka TCP/UDP niedostępna: " + exception.GetType().Name + "; nie można też unieważnić poprzedniej migawki z powodu braku miejsca w bazie.";
                return 0;
            }
            knownConnections = null;
            knownUdpEndpoints = null;
            knownTcpTruncated = false;
            knownUdpTruncated = false;
            State = "Migawka TCP/UDP niedostępna: " + exception.GetType().Name + "; po odzyskaniu źródła powstanie nowa baza porównania.";
            return 0;
        }

        var excluded = new HashSet<string>((excludedApplications ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.OrdinalIgnoreCase)
        { "Sentinel.Engine" };
        var batch = sample as ConnectionSnapshotBatch;
        var tcpCandidates = sample.Where(IsTrackable)
            .Where(connection => !excluded.Contains(connection.ProcessName ?? "unknown"))
            .Select(connection => (Key: ConnectionKey.From(connection).ToStorageKey(), Connection: connection))
            .GroupBy(item => item.Key, StringComparer.Ordinal)
            .Select(group => (Key: group.Key, Connection: group.First().Connection)).ToArray();

        var udpCandidates = sample.Where(IsTrackableUdpEndpoint)
            .Where(connection => !excluded.Contains(connection.ProcessName ?? "unknown"))
            .Select(connection => (Key: ConnectionKey.From(connection).ToStorageKey(), Connection: connection))
            .GroupBy(item => item.Key, StringComparer.Ordinal)
            .Select(group => (Key: group.Key, Connection: group.First().Connection)).ToArray();
        var tcpTruncated = (batch?.TcpTruncated ?? false) || tcpCandidates.Length > MaximumConnections;
        var udpTruncated = (batch?.UdpTruncated ?? false) || udpCandidates.Length > MaximumConnections;
        var currentTcp = tcpCandidates.OrderBy(item => item.Key, StringComparer.Ordinal).Take(MaximumConnections)
            .ToDictionary(item => item.Key, item => item.Connection, StringComparer.Ordinal);
        var currentUdp = udpCandidates.OrderBy(item => item.Key, StringComparer.Ordinal).Take(MaximumConnections)
            .ToDictionary(item => item.Key, item => item.Connection, StringComparer.Ordinal);

        if (knownConnections is null || knownUdpEndpoints is null)
        {
            NetworkMonitorSnapshot snapshot;
            try { snapshot = await store.ReadNetworkMonitorSnapshotAsync(cancellationToken); }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
            {
                State = "Nie można odczytać trwałej migawki TCP/UDP: baza osiągnęła limit lub brakuje miejsca.";
                return 0;
            }
            if (!snapshot.Initialized)
            {
                try
                {
                    await store.CommitNetworkMonitorChangesAsync([], currentTcp.Keys.Concat(currentUdp.Keys).ToArray(), [], cancellationToken, tcpTruncated, udpTruncated);
                }
                catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
                {
                    State = "Nie można zapisać bazy początkowej TCP/UDP: baza osiągnęła limit lub brakuje miejsca.";
                    return 0;
                }
                knownConnections = currentTcp.Keys.ToHashSet(StringComparer.Ordinal);
                knownUdpEndpoints = currentUdp.Keys.ToHashSet(StringComparer.Ordinal);
                knownTcpTruncated = tcpTruncated;
                knownUdpTruncated = udpTruncated;
                State = $"Ciągła migawka TCP/UDP działa; baza początkowa: {currentTcp.Count} połączeń TCP i {currentUdp.Count} endpointów UDP. Krótkie połączenia TCP mogą zostać pominięte; endpoint UDP nie potwierdza wysłania datagramu.";
                if (tcpTruncated || udpTruncated)
                    State += " Osiągnięto limit tabeli; alerty z niepełnej próbki są wstrzymane.";
                return 0;
            }
            knownConnections = snapshot.EndpointKeys.Where(key => key.StartsWith("TCP:", StringComparison.Ordinal)).ToHashSet(StringComparer.Ordinal);
            knownUdpEndpoints = snapshot.EndpointKeys.Where(key => key.StartsWith("UDP:", StringComparison.Ordinal)).ToHashSet(StringComparer.Ordinal);
            knownTcpTruncated = snapshot.TcpTruncated;
            knownUdpTruncated = snapshot.UdpTruncated;
        }

        var currentTcpKeys = currentTcp.Keys.ToHashSet(StringComparer.Ordinal);
        var currentUdpKeys = currentUdp.Keys.ToHashSet(StringComparer.Ordinal);
        var previousTcpTruncated = knownTcpTruncated;
        var previousUdpTruncated = knownUdpTruncated;
        var newConnections = (knownTcpTruncated || tcpTruncated) ? [] : currentTcpKeys.Except(knownConnections, StringComparer.Ordinal)
            .Select(key => (Key: key, Connection: currentTcp[key])).ToArray();
        var newUdpEndpoints = (knownUdpTruncated || udpTruncated) ? [] : currentUdpKeys.Except(knownUdpEndpoints, StringComparer.Ordinal)
            .Select(key => (Key: key, Connection: currentUdp[key])).ToArray();
        var candidates = newConnections.Select(item => (item.Key, item.Connection, IsUdp: false))
            .Concat(newUdpEndpoints.Select(item => (item.Key, item.Connection, IsUdp: true)))
            .OrderBy(item => item.Key, StringComparer.Ordinal).ToArray();
        var added = candidates.Take(MaximumEventsPerSample).ToArray();
        var events = added.Select(item =>
        {
            var connection = item.Connection;
            var ipReputationMatch = !item.IsUdp && connection.RemoteAddress is { } remoteAddress && SafeMatchesIpFeed(remoteAddress);
            var correlationId = connection.ProcessId >= 0 ? wasRecentlyObservedStart(connection.ProcessId, connection.ProcessName, now) : null;
            var processContext = !item.IsUdp && correlationId is not null
                ? " W ostatnich 60 sekundach zapisano zdarzenie pojawienia się tego PID; to wyłącznie korelacja czasowa, nie ocena zagrożenia."
                : "";
            var category = item.IsUdp ? "Zaobserwowano endpoint UDP" : ipReputationMatch ? "Połączenie z adresem na lokalnej liście IP" : "Zaobserwowano połączenie TCP";
            var explanation = item.IsUdp
                ? $"Nowa migawka endpointu UDP: {connection.LocalAddress}:{connection.LocalPort}, PID {connection.ProcessId}. Tabela Windows nie pokazuje adresu zdalnego ani nie potwierdza wysłania datagramu."
                : ipReputationMatch
                    ? $"Nowe połączenie TCP do {connection.RemoteAddress}:{connection.RemotePort} pasuje do lokalnie zaimportowanej listy adresów IP; proces: {connection.ProcessName ?? "unknown"} (PID {connection.ProcessId}).{processContext}"
                    : $"Nowa migawka TCP: {connection.LocalAddress}:{connection.LocalPort} → {connection.RemoteAddress}:{connection.RemotePort}, stan {connection.State}, PID {connection.ProcessId}.{processContext}";
            var recommendation = item.IsUdp
                ? "To lokalny endpoint UDP, nie dowód ruchu ani werdykt zagrożenia. Zweryfikuj proces i jego przeznaczenie."
                : ipReputationMatch
                    ? "Sprawdź źródło i datę importowanej listy oraz zweryfikuj proces. Sentinel nie blokuje ruchu, a dopasowanie zależy od jakości tej listy."
                    : "To metadane połączenia, nie werdykt zagrożenia. Zweryfikuj proces i adres zdalny.";
            return new SecurityEvent(0, now, ipReputationMatch ? RiskLevel.High : RiskLevel.Information, category, connection.ProcessName ?? "unknown",
                explanation, recommendation, EventStatus.New,
                EventId: Guid.NewGuid(), Source: item.IsUdp ? "udp-endpoint-snapshot" : "tcp-connection-snapshot",
                RuleVersion: ThreatAnalysisEngine.RulesVersion,
                ProcessId: connection.ProcessId >= 0 ? connection.ProcessId : null, ProcessName: connection.ProcessName,
                CorrelationId: correlationId,
                EvidenceCodes: item.IsUdp ? ["network.udp.local-endpoint-seen"] : ipReputationMatch
                    ? ["network.tcp.connection-snapshot", "reputation.ip-feed.match"]
                    : ["network.tcp.connection-snapshot"]);
        }).ToArray();

        var tcpBaselineReset = previousTcpTruncated || tcpTruncated;
        var udpBaselineReset = previousUdpTruncated || udpTruncated;
        var removedTcpKeys = knownConnections.Except(currentTcpKeys, StringComparer.Ordinal).ToArray();
        var removedUdpKeys = knownUdpEndpoints.Except(currentUdpKeys, StringComparer.Ordinal).ToArray();
        var addedTcpKeys = tcpBaselineReset
            ? currentTcpKeys.Except(knownConnections, StringComparer.Ordinal).ToArray()
            : added.Where(item => !item.IsUdp).Select(item => item.Key).ToArray();
        var addedUdpKeys = udpBaselineReset
            ? currentUdpKeys.Except(knownUdpEndpoints, StringComparer.Ordinal).ToArray()
            : added.Where(item => item.IsUdp).Select(item => item.Key).ToArray();
        var addedKeys = addedTcpKeys.Concat(addedUdpKeys).ToArray();
        var removedKeys = removedTcpKeys.Concat(removedUdpKeys).ToArray();
        var truncationChanged = knownTcpTruncated != tcpTruncated || knownUdpTruncated != udpTruncated;
        if (events.Length > 0 || addedKeys.Length > 0 || removedKeys.Length > 0 || truncationChanged)
        {
            try
            {
                await store.CommitNetworkMonitorChangesAsync(events, addedKeys, removedKeys, cancellationToken, tcpTruncated, udpTruncated);
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
            {
                State = "Historia nie przyjęła nowych połączeń: baza osiągnęła limit lub brakuje miejsca. Zmiany TCP pozostają do ponowienia.";
                return 0;
            }
        }
        knownConnections.ExceptWith(removedTcpKeys);
        knownConnections.UnionWith(addedTcpKeys);
        knownUdpEndpoints.ExceptWith(removedUdpKeys);
        knownUdpEndpoints.UnionWith(addedUdpKeys);
        if (tcpBaselineReset) knownConnections = currentTcpKeys;
        if (udpBaselineReset) knownUdpEndpoints = currentUdpKeys;
        knownTcpTruncated = tcpTruncated;
        knownUdpTruncated = udpTruncated;
        var pendingEvents = Math.Max(0, newConnections.Length - (tcpBaselineReset ? newConnections.Length : addedTcpKeys.Length))
            + Math.Max(0, newUdpEndpoints.Length - (udpBaselineReset ? newUdpEndpoints.Length : addedUdpKeys.Length));
        State = $"Ciągła migawka TCP/UDP działa; {currentTcp.Count} połączeń TCP i {currentUdp.Count} endpointów UDP, {events.Length} nowych zdarzeń, {pendingEvents} nowych endpointów oczekuje na kolejne próbki. Krótkie połączenia TCP mogą zostać pominięte; endpoint UDP nie potwierdza datagramu.";
        if (tcpTruncated || udpTruncated)
            State += " Osiągnięto limit tabeli; alerty z niepełnej próbki są wstrzymane.";
        else if (previousTcpTruncated || previousUdpTruncated)
            State += " Poprzednia próbka była niepełna; alerty wznowią się po kolejnej pełnej próbce.";
        return events.Length;
    }

    private static bool IsTrackable(ConnectionSnapshot connection)
    {
        if (!string.Equals(connection.Protocol, "TCP", StringComparison.OrdinalIgnoreCase) ||
            connection.RemoteAddress is null || connection.RemotePort is null ||
            connection.State is not ("Established" or "SynSent")) return false;
        if (!IPAddress.TryParse(connection.RemoteAddress, out var address)) return false;
        return !IPAddress.Any.Equals(address) && !IPAddress.IPv6Any.Equals(address) && !IPAddress.IsLoopback(address);
    }

    private bool SafeMatchesIpFeed(string address)
    {
        try { return matchesLocalIpFeed(address); }
        catch { return false; }
    }

    private static bool IsTrackableUdpEndpoint(ConnectionSnapshot connection) =>
        string.Equals(connection.Protocol, "UDP", StringComparison.OrdinalIgnoreCase) &&
        connection.RemoteAddress is null && connection.RemotePort is null && connection.State == "Endpoint" &&
        IPAddress.TryParse(connection.LocalAddress, out _) && connection.LocalPort is >= 0 and <= 65535;

    private sealed record ConnectionKey(string Protocol, string LocalAddress, int LocalPort, string? RemoteAddress, int? RemotePort,
        int ProcessId, string ProcessName, string State)
    {
        public static ConnectionKey From(ConnectionSnapshot item) => new(item.Protocol.ToUpperInvariant(), item.LocalAddress, item.LocalPort,
            item.RemoteAddress, item.RemotePort, item.ProcessId, item.ProcessName ?? "unknown", item.State);
        public string ToStorageKey() => Protocol + ":" + Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(this)));
    }
}
