using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class TcpConnectionSnapshotMonitorTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-tcp-monitor-" + Guid.NewGuid());
    private static ConnectionSnapshot Connection(int port, string remote = "198.51.100.7", string process = "browser", int processId = 1234) =>
        new("TCP", "192.0.2.10", 50_000 + port, remote, port, "Established", processId, process);

    [Fact]
    public async Task RequiresOptInUsesBaselineAndRecordsOnlyNewExternalTcpMetadata()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        IReadOnlyCollection<ConnectionSnapshot> sample = [Connection(443)];
        var captures = 0;
        var monitor = new TcpConnectionSnapshotMonitor(_ => { captures++; return Task.FromResult(sample); }, clock);

        Assert.Equal(0, await monitor.CollectAsync(store, enabled: false, paused: false, ""));
        Assert.Equal(0, captures);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.Empty(await store.ReadAsync());

        sample = [Connection(443), Connection(8443), Connection(8080, "127.0.0.1"),
            Connection(53) with { Protocol = "UDP" }, Connection(22) with { State = "Listen" }, Connection(25, process: "excluded-app")];
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, "excluded-app"));
        Assert.Equal(1, captures);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false, "excluded-app"));

        var item = Assert.Single(await store.ReadAsync());
        Assert.Equal("Zaobserwowano połączenie TCP", item.Category);
        Assert.Equal("tcp-connection-snapshot", item.Source);
        Assert.Equal(1234, item.ProcessId);
        Assert.Equal("browser", item.ProcessName);
        Assert.Contains("198.51.100.7:8443", item.Explanation);
        Assert.Equal(RiskLevel.Information, item.Risk);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, "excluded-app"));
        Assert.Single(await store.ReadAsync());
    }

    [Fact]
    public async Task BoundsChangesAndUsesFreshBaselineAfterPauseOrSourceFailure()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        IReadOnlyCollection<ConnectionSnapshot> sample = [];
        var unavailable = false;
        Task<IReadOnlyCollection<ConnectionSnapshot>> Capture(CancellationToken _) => unavailable
            ? throw new IOException("synthetic TCP source failure") : Task.FromResult(sample);
        var monitor = new TcpConnectionSnapshotMonitor(Capture, clock);

        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        sample = Enumerable.Range(1, 150).Select(port => Connection(1000 + port)).ToArray();
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(100, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.Contains("50", monitor.State);
        Assert.Equal(100, (await store.ReadAsync()).Count);

        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: true, ""));
        Assert.Contains("wstrzymana", monitor.State);

        sample = [Connection(443)];
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        unavailable = true; clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.Contains("IOException", monitor.State);

        unavailable = false; sample = [Connection(443), Connection(9443)]; clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.Contains("baza początkowa", monitor.State);
        Assert.Equal(100, (await store.ReadAsync()).Count);
    }

    [Fact]
    public async Task CorrelatesNewTcpConnectionWithRecentlyObservedProcessStartAsInformationalContext()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var processSnapshot = new Dictionary<int, string>();
        var processMonitor = new ProcessSnapshotMonitor(() => new(processSnapshot));
        processSnapshot.Add(1234, "browser");
        Assert.Equal(1, await processMonitor.CollectAsync(store, paused: false, excludedApplications: ""));

        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        IReadOnlyCollection<ConnectionSnapshot> sample = [];
        var monitor = new TcpConnectionSnapshotMonitor(_ => Task.FromResult(sample), clock,
            processMonitor.WasRecentlyObservedStart);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        sample = [Connection(443, processId: 1234)];
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false, ""));

        var eventItem = Assert.Single(await store.ReadAsync(), item => item.Source == "tcp-connection-snapshot");
        Assert.Contains("korelacja czasowa", eventItem.Explanation);
        Assert.Equal(RiskLevel.Information, eventItem.Risk);
        Assert.Equal(new[] { "network.tcp.connection-snapshot" }, eventItem.EvidenceCodes);
        var processEvent = Assert.Single(await store.ReadAsync(), item => item.Source == "process-snapshot");
        Assert.NotNull(eventItem.CorrelationId);
        Assert.Equal(processEvent.CorrelationId, eventItem.CorrelationId);
        Assert.Null(processMonitor.WasRecentlyObservedStart(1234, clock.GetUtcNow().AddSeconds(61)));
    }

    [Theory]
    [InlineData("different-process")]
    [InlineData("unknown")]
    [InlineData(null)]
    public async Task DoesNotCorrelateReusedPidWhenProcessNameCannotBeMatched(string? processName)
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = new Dictionary<int, string>();
        var processMonitor = new ProcessSnapshotMonitor(() => new(snapshot));
        snapshot.Add(1234, "browser");
        Assert.Equal(1, await processMonitor.CollectAsync(store, paused: false, excludedApplications: ""));

        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        IReadOnlyCollection<ConnectionSnapshot> sample = [];
        var monitor = new TcpConnectionSnapshotMonitor(_ => Task.FromResult(sample), clock, processMonitor.WasRecentlyObservedStart);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        sample = [Connection(443, processId: 1234) with { ProcessName = processName }];
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false, ""));

        var connectionEvent = Assert.Single(await store.ReadAsync(), item => item.Source == "tcp-connection-snapshot");
        Assert.Null(connectionEvent.CorrelationId);
        Assert.DoesNotContain("korelacja czasowa", connectionEvent.Explanation);
    }

    [Fact]
    public async Task RecordsNewUdpLocalEndpointWithoutClaimingThatDatagramWasSent()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        IReadOnlyCollection<ConnectionSnapshot> sample =
        [new("UDP", "192.0.2.10", 53_000, null, null, "Endpoint", 4321, "dns-client")];
        var monitor = new TcpConnectionSnapshotMonitor(_ => Task.FromResult(sample), clock);

        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        sample = sample.Append(new("UDP", "192.0.2.10", 53_001, null, null, "Endpoint", 4321, "dns-client")).ToArray();
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false, ""));

        var item = Assert.Single(await store.ReadAsync());
        Assert.Equal("Zaobserwowano endpoint UDP", item.Category);
        Assert.Equal("udp-endpoint-snapshot", item.Source);
        Assert.Contains("nie potwierdza wysłania datagramu", item.Explanation);
        Assert.Equal(RiskLevel.Information, item.Risk);
    }

    [Fact]
    public async Task PersistsTcpUdpBaselineWithEventsAndResumesWithoutDuplicatesAfterRestart()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var existingTcp = Connection(443);
        var existingUdp = new ConnectionSnapshot("UDP", "192.0.2.10", 53_000, null, null, "Endpoint", 1234, "dns-client");
        IReadOnlyCollection<ConnectionSnapshot> sample = [existingTcp, existingUdp];
        var firstRun = new TcpConnectionSnapshotMonitor(_ => Task.FromResult(sample), clock);
        Assert.Equal(0, await firstRun.CollectAsync(store, enabled: true, paused: false, ""));

        var addedTcp = Connection(8443);
        var addedUdp = existingUdp with { LocalPort = 53_001 };
        sample = [existingTcp, existingUdp, addedTcp, addedUdp];
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(2, await firstRun.CollectAsync(store, enabled: true, paused: false, ""));

        var restartedMonitor = new TcpConnectionSnapshotMonitor(_ => Task.FromResult(sample), clock);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(0, await restartedMonitor.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.Equal(2, (await store.ReadAsync()).Count);

        sample = sample.Append(Connection(9443)).ToArray();
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(1, await restartedMonitor.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.Equal(3, (await store.ReadAsync()).Count);
    }

    [Fact]
    public async Task TruncatedNetworkSamplesSuppressAmbiguousAlertsAcrossRestartUntilCompleteSample()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        IReadOnlyCollection<ConnectionSnapshot> sample = [Connection(443)];
        var monitor = new TcpConnectionSnapshotMonitor(_ => Task.FromResult(sample), clock);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));

        sample = new ConnectionSnapshotBatch([Connection(443)], tcpTruncated: true);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.True((await store.ReadNetworkMonitorSnapshotAsync()).TcpTruncated);
        Assert.Contains("Osiągnięto limit tabeli", monitor.State);

        sample = new ConnectionSnapshotBatch([Connection(443), Connection(8443)], tcpTruncated: true);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.Empty(await store.ReadAsync());

        var restarted = new TcpConnectionSnapshotMonitor(_ => Task.FromResult(sample), clock);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(0, await restarted.CollectAsync(store, enabled: true, paused: false, ""));

        sample = new ConnectionSnapshotBatch([Connection(443), Connection(8443)]);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(0, await restarted.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.False((await store.ReadNetworkMonitorSnapshotAsync()).TcpTruncated);

        sample = new ConnectionSnapshotBatch([Connection(443), Connection(8443), Connection(9443)]);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(1, await restarted.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.Single(await store.ReadAsync());
    }

    [Fact]
    public async Task DisabledMonitoringInvalidatesPersistedBaselineBeforeNextOptIn()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        IReadOnlyCollection<ConnectionSnapshot> sample = [Connection(443)];
        var first = new TcpConnectionSnapshotMonitor(_ => Task.FromResult(sample), clock);
        Assert.Equal(0, await first.CollectAsync(store, enabled: true, paused: false, ""));

        sample = sample.Append(Connection(8443)).ToArray();
        Assert.Equal(0, await first.CollectAsync(store, enabled: false, paused: false, ""));
        var resumed = new TcpConnectionSnapshotMonitor(_ => Task.FromResult(sample), clock);
        Assert.Equal(0, await resumed.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.Empty(await store.ReadAsync());

        sample = sample.Append(Connection(9443)).ToArray();
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(1, await resumed.CollectAsync(store, enabled: true, paused: false, ""));
        Assert.Single(await store.ReadAsync());
    }

    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset current = now;
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan elapsed) => current += elapsed;
    }
}
