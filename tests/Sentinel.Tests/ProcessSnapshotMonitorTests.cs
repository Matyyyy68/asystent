using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ProcessSnapshotMonitorTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-process-monitor-" + Guid.NewGuid());

    [Fact]
    public async Task TenThousandProcessChangesAreCappedAndRecordedWithoutLosingStatus()
    {
        var snapshot = new Dictionary<int, string>();
        var monitor = new ProcessSnapshotMonitor(() => new Dictionary<int, string>(snapshot));
        var store = new LocalStore(directory);
        await store.InitializeAsync();
        for (var id = 1; id <= 10_500; id++) snapshot.Add(id, "synthetic-process");

        var started = System.Diagnostics.Stopwatch.StartNew();
        var added = await monitor.CollectAsync(store, paused: false, excludedApplications: "");
        started.Stop();

        Assert.Equal(100, added);
        Assert.Equal(100, (await store.ReadAsync()).Count);
        Assert.Contains("10000 PID, 100 zmian, pominięto łącznie 9900", monitor.State);
        Assert.Contains("Limit snapshotu osiągnięty", monitor.State);

        snapshot.Clear();
        var removed = await monitor.CollectAsync(store, paused: false, excludedApplications: "");
        Assert.Equal(100, removed);
        Assert.Equal(200, (await store.ReadAsync()).Count);
        Assert.Contains("100 zmian, pominięto łącznie 19800", monitor.State);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(30), $"10k process delta exceeded 30s: {started.Elapsed}");
    }

    [Fact]
    public async Task UnavailableProcessSourceIsReportedAndCollectionRecovers()
    {
        var unavailable = false;
        var snapshot = new Dictionary<int, string>();
        Dictionary<int, string> ReadSnapshot() => unavailable ? throw new IOException("synthetic source failure") : new(snapshot);
        var monitor = new ProcessSnapshotMonitor(ReadSnapshot);
        var store = new LocalStore(directory);
        await store.InitializeAsync();

        unavailable = true;
        Assert.Equal(0, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Contains("Snapshot procesów niedostępny: IOException", monitor.State);
        Assert.Empty(await store.ReadAsync());

        unavailable = false;
        snapshot.Add(43210, "recovered-process");
        Assert.Equal(1, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Contains("Snapshot procesów działa", monitor.State);
        Assert.Equal(43210, Assert.Single(await store.ReadAsync()).ProcessId);
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
