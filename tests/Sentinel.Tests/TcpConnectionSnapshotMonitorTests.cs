using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class TcpConnectionSnapshotMonitorTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-tcp-monitor-" + Guid.NewGuid());
    private static ConnectionSnapshot Connection(int port, string remote = "198.51.100.7", string process = "browser") =>
        new("TCP", "192.0.2.10", 50_000 + port, remote, port, "Established", 1234, process);

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

    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset current = now;
        public override DateTimeOffset GetUtcNow() => current;
        public void Advance(TimeSpan elapsed) => current += elapsed;
    }
}
