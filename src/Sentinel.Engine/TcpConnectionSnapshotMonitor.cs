using System.Net;
using Sentinel.Core;
using Sentinel.Core.Analysis;

public sealed record ConnectionSnapshot(string Protocol, string LocalAddress, int LocalPort, string? RemoteAddress,
    int? RemotePort, string State, int ProcessId, string? ProcessName);

/// <summary>Opt-in, bounded polling of TCP metadata. It never inspects packet contents.</summary>
public sealed class TcpConnectionSnapshotMonitor
{
    private const int MaximumConnections = 10_000;
    private const int MaximumEventsPerSample = 100;
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(10);
    private readonly Func<CancellationToken, Task<IReadOnlyCollection<ConnectionSnapshot>>> capture;
    private readonly TimeProvider timeProvider;
    private HashSet<ConnectionKey>? knownConnections;
    private DateTimeOffset? lastAttempt;
    private long droppedEvents;

    public string State { get; private set; } = "Ciągła migawka TCP jest wyłączona.";

    public TcpConnectionSnapshotMonitor(
        Func<CancellationToken, Task<IReadOnlyCollection<ConnectionSnapshot>>> capture,
        TimeProvider? timeProvider = null)
    {
        this.capture = capture ?? throw new ArgumentNullException(nameof(capture));
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<int> CollectAsync(LocalStore store, bool enabled, bool paused, string excludedApplications,
        CancellationToken cancellationToken = default)
    {
        if (!enabled || paused)
        {
            knownConnections = null;
            lastAttempt = null;
            State = enabled ? "Ciągła migawka TCP wstrzymana." : "Ciągła migawka TCP jest wyłączona.";
            return 0;
        }

        var now = timeProvider.GetUtcNow();
        if (lastAttempt is { } previous && now - previous < SampleInterval) return 0;
        lastAttempt = now;

        IReadOnlyCollection<ConnectionSnapshot> sample;
        try { sample = await capture(cancellationToken); }
        catch (Exception exception)
        {
            knownConnections = null;
            State = "Migawka TCP niedostępna: " + exception.GetType().Name + "; po odzyskaniu źródła powstanie nowa baza porównania.";
            return 0;
        }

        var excluded = new HashSet<string>((excludedApplications ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.OrdinalIgnoreCase)
        { "Sentinel.Engine" };
        var current = sample.Where(IsTrackable)
            .Where(connection => !excluded.Contains(connection.ProcessName ?? "unknown"))
            .Take(MaximumConnections)
            .Select(ConnectionKey.From)
            .ToHashSet();

        if (knownConnections is null)
        {
            knownConnections = current;
            State = $"Ciągła migawka TCP działa; baza początkowa: {current.Count} połączeń. Krótkie połączenia mogą zostać pominięte.";
            return 0;
        }

        var newConnections = current.Except(knownConnections).ToArray();
        var added = newConnections.Take(MaximumEventsPerSample).ToArray();
        droppedEvents += newConnections.Length - added.Length;
        var events = added.Select(connection => new SecurityEvent(0, now, RiskLevel.Information,
            "Zaobserwowano połączenie TCP", connection.ProcessName,
            $"Nowa migawka TCP: {connection.LocalAddress}:{connection.LocalPort} → {connection.RemoteAddress}:{connection.RemotePort}, stan {connection.State}, PID {connection.ProcessId}.",
            "To metadane połączenia, nie werdykt zagrożenia. Zweryfikuj proces i adres zdalny.", EventStatus.New,
            EventId: Guid.NewGuid(), Source: "tcp-connection-snapshot", RuleVersion: ThreatAnalysisEngine.RulesVersion,
            ProcessId: connection.ProcessId >= 0 ? connection.ProcessId : null, ProcessName: connection.ProcessName)).ToArray();

        if (events.Length > 0) await store.AddLocalOnlyBatchAsync(events, cancellationToken);
        knownConnections = current;
        State = $"Ciągła migawka TCP działa; {current.Count} połączeń, {events.Length} nowych, pominięto łącznie {droppedEvents}. Krótkie połączenia mogą zostać pominięte.";
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

    private sealed record ConnectionKey(string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort,
        int ProcessId, string ProcessName, string State)
    {
        public static ConnectionKey From(ConnectionSnapshot item) => new(item.LocalAddress, item.LocalPort,
            item.RemoteAddress!, item.RemotePort!.Value, item.ProcessId, item.ProcessName ?? "unknown", item.State);
    }
}
