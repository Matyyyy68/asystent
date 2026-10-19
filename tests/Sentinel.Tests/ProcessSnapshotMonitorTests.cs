using Sentinel.Core;
using Microsoft.Data.Sqlite;
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

    [Fact]
    public async Task ProcessDeltaIsRetriedAfterHistoryDatabaseIsFull()
    {
        const long maximumBytes = 1024 * 1024;
        var store = new LocalStore(directory, maximumBytes);
        await store.InitializeAsync();
        var snapshot = new Dictionary<int, string> { [41] = "existing-process" };
        var monitor = new ProcessSnapshotMonitor(() => new(snapshot));
        var batchFailed = false;
        var full = false;
        SecurityEvent Filler() => new(0, DateTimeOffset.UtcNow, RiskLevel.Information, "Proces zaobserwowany", "new-process",
            "Windows pokazał nowy PID 99 o nazwie new-process od poprzedniej próbki. Krótkie procesy mogą zostać pominięte.",
            "To obserwacja metadanych, nie werdykt zagrożenia. Zweryfikuj pochodzenie procesu.", EventStatus.New,
            Source: "process-snapshot", RuleVersion: Sentinel.Core.Analysis.ThreatAnalysisEngine.RulesVersion,
            ProcessId: 99, ProcessName: "new-process");

        for (var batch = 0; batch < 100 && !batchFailed; batch++)
        {
            try { await store.AddLocalOnlyBatchAsync(Enumerable.Range(0, 100).Select(_ => Filler()).ToArray()); }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 13) { batchFailed = true; }
        }
        Assert.True(batchFailed);
        for (var attempt = 0; attempt < 100 && !full; attempt++)
        {
            try { await store.AddLocalOnlyAsync(Filler()); }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 13) { full = true; }
        }
        Assert.True(full);

        snapshot.Add(42, "new-process");
        Assert.Equal(0, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Contains("pozostają do ponowienia", monitor.State);
        Assert.DoesNotContain(await store.ReadAsync(), item => item.ProcessId == 42);

        await store.DeleteHistoryAsync();
        Assert.Equal(1, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(42, Assert.Single(await store.ReadAsync()).ProcessId);
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
