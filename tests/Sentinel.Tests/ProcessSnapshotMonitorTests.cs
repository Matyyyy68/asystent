using Sentinel.Core;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Sentinel.Tests;

public sealed class ProcessSnapshotMonitorTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-process-monitor-" + Guid.NewGuid());

    [Fact]
    public async Task ProcessBaselineSurvivesRestartAndCapturesChangesSinceLastRun()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = new Dictionary<int, string> { [41] = "existing-process" };
        var first = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(0, await first.CollectAsync(store, paused: false, excludedApplications: ""));

        snapshot.Add(42, "started-while-engine-stopped");
        var restarted = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(1, await restarted.CollectAsync(store, paused: false, excludedApplications: ""));
        var started = Assert.Single(await store.ReadAsync());
        Assert.Equal(42, started.ProcessId);
        Assert.Equal(new[] { "process.snapshot.new-pid", "process.image.path-unavailable" }, started.EvidenceCodes);

        var restartedAgain = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(0, await restartedAgain.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Single(await store.ReadAsync());
    }

    [Fact]
    public async Task ProcessStartPersistsLocalImagePathAndQueuesInspectionAfterCommit()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = new Dictionary<int, string> { [41] = "existing-process" };
        var queued = new List<(Guid EventId, string Path)>();
        var path = Path.Combine(directory, "synthetic.exe");
        var monitor = new ProcessSnapshotMonitor(() => new(snapshot), (_, _) => path,
            (eventId, imagePath) => { queued.Add((eventId, imagePath)); return true; });
        await monitor.CollectAsync(store, paused: false, excludedApplications: "");
        snapshot.Add(42, "new-process");

        Assert.Equal(1, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        var saved = Assert.Single(await store.ReadAsync());
        Assert.Equal(path, saved.ProcessImagePath);
        Assert.Equal("Pending", saved.ProcessImageSignatureStatus);
        Assert.Contains("process.image.path-available", saved.EvidenceCodes!);
        Assert.Equal((saved.EventId!.Value, path), Assert.Single(queued));
    }

    [Fact]
    public async Task PausedProcessMonitoringAdvancesPersistentBaselineWithoutAlerts()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = new Dictionary<int, string> { [41] = "existing-process" };
        var first = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(0, await first.CollectAsync(store, paused: false, excludedApplications: ""));

        snapshot.Add(42, "started-during-pause");
        Assert.Equal(0, await first.CollectAsync(store, paused: true, excludedApplications: ""));
        Assert.Contains("Zdarzenia procesów wstrzymane", first.State);
        Assert.Contains("baseline PID/nazw jest nadal aktualizowany", first.State);
        var restarted = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(0, await restarted.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Empty(await store.ReadAsync());
        Assert.Equal(2, (await store.ReadProcessMonitorSnapshotAsync()).Processes.Count);
    }

    [Fact]
    public async Task ExcludedProcessesAreNotWrittenToPersistentBaseline()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = new Dictionary<int, string> { [41] = "password-manager", [42] = "ordinary-app" };
        var monitor = new ProcessSnapshotMonitor(() => new(snapshot));

        Assert.Equal(0, await monitor.CollectAsync(store, paused: false, excludedApplications: "password-manager"));

        var persisted = await store.ReadProcessMonitorSnapshotAsync();
        Assert.True(persisted.Initialized);
        Assert.DoesNotContain(41, persisted.Processes.Keys);
        Assert.Equal("ordinary-app", persisted.Processes[42]);
    }

    [Fact]
    public async Task TenThousandProcessChangesAreCappedAndPersistedInBoundedBacklog()
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
        Assert.Contains("10000 PID, 100 zmian, kolejka 9900, odrzucono ponad limit łącznie 0", monitor.State);
        Assert.Equal(9_900, (await store.ReadPendingProcessChangesAsync()).Count);
        Assert.Contains("Limit snapshotu osiągnięty", monitor.State);

        snapshot.Clear();
        var removed = await monitor.CollectAsync(store, paused: false, excludedApplications: "");
        Assert.Equal(100, removed);
        Assert.Equal(200, (await store.ReadAsync()).Count);
        Assert.Contains("kolejka 19800, odrzucono ponad limit łącznie 0", monitor.State);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(30), $"10k process delta exceeded 30s: {started.Elapsed}");
    }

    [Fact]
    public async Task ProcessChangeBacklogDrainsAfterRestartWithoutDuplicateOrLostEvents()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = new Dictionary<int, string>();
        var monitor = new ProcessSnapshotMonitor(() => new(snapshot));
        for (var id = 1; id <= 250; id++) snapshot.Add(id, "synthetic-process");

        Assert.Equal(100, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(150, (await store.ReadPendingProcessChangesAsync()).Count);
        Assert.Equal(100, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(50, (await store.ReadPendingProcessChangesAsync()).Count);

        var restarted = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(50, await restarted.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(0, (await store.ReadPendingProcessChangesAsync()).Count);
        var events = await store.ReadAsync();
        Assert.Equal(250, events.Count);
        Assert.Equal(250, events.Select(item => item.EventId).Distinct().Count());
        Assert.Equal(Enumerable.Range(1, 250), events.Select(item => item.ProcessId!.Value).Order());
    }

    [Fact]
    public async Task DelayedBacklogStartDoesNotResolveImagePathAgainstPossiblyReusedPid()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = new Dictionary<int, string>();
        var resolvedPaths = 0;
        var monitor = new ProcessSnapshotMonitor(() => new(snapshot), (_, _) =>
        {
            resolvedPaths++;
            return Path.Combine(directory, "synthetic.exe");
        }, null);
        for (var id = 1; id <= 101; id++) snapshot.Add(id, "synthetic-process");

        Assert.Equal(100, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(100, resolvedPaths);
        Assert.Equal(1, (await store.ReadPendingProcessChangesAsync()).Count);

        Assert.Equal(1, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(100, resolvedPaths);
        var delayed = Assert.Single(await store.ReadAsync(), item => item.ProcessId == 101);
        Assert.Null(delayed.ProcessImagePath);
        Assert.Contains("process.image.path-unavailable", delayed.EvidenceCodes!);
    }

    [Fact]
    public async Task PausingProcessMonitoringClearsBacklogAndAdvancesBaselineWithoutAlerts()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = new Dictionary<int, string>();
        var monitor = new ProcessSnapshotMonitor(() => new(snapshot));
        for (var id = 1; id <= 250; id++) snapshot.Add(id, "synthetic-process");

        Assert.Equal(100, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(150, (await store.ReadPendingProcessChangesAsync()).Count);
        Assert.Equal(0, await monitor.CollectAsync(store, paused: true, excludedApplications: ""));
        Assert.Equal(0, (await store.ReadPendingProcessChangesAsync()).Count);

        var restarted = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(0, await restarted.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(100, (await store.ReadAsync()).Count);
    }

    [Fact]
    public async Task ProcessChangeBacklogHasHardLimitAndReportsOverflow()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = new Dictionary<int, string>();
        var monitor = new ProcessSnapshotMonitor(() => new(snapshot));
        for (var id = 1; id <= 9_000; id++) snapshot.Add(id, "first-name");
        Assert.Equal(100, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(8_900, (await store.ReadPendingProcessChangesAsync()).Count);

        for (var id = 1; id <= 9_000; id++) snapshot[id] = "second-name";
        Assert.Equal(100, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        var pending = await store.ReadPendingProcessChangesAsync();
        Assert.Equal(20_000, pending.Count);
        Assert.Contains("kolejka 20000, odrzucono ponad limit łącznie 6800", monitor.State);

        for (var id = 1; id <= 9_000; id++) snapshot[id] = "third-name";
        Assert.Equal(100, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(20_000, (await store.ReadPendingProcessChangesAsync()).Count);
        Assert.Contains("kolejka 20000, odrzucono ponad limit łącznie 24700", monitor.State);
        Assert.Equal(24_700L, (await store.ReadProcessMonitorSnapshotAsync()).DroppedChanges);

        var restarted = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(100, await restarted.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Contains("odrzucono ponad limit łącznie 24700", restarted.State);
    }

    [Fact]
    public async Task TruncatedSnapshotsDoNotInventProcessStartsOrStopsAndSurviveRestart()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = Enumerable.Range(1, 10_000).ToDictionary(id => id, _ => "synthetic-process");
        var monitor = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(0, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));

        snapshot.Add(0, "new-low-pid");
        Assert.Equal(1, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(0, Assert.Single(await store.ReadAsync()).ProcessId);
        Assert.True((await store.ReadProcessMonitorSnapshotAsync()).Truncated);

        var restarted = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(0, await restarted.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Single(await store.ReadAsync());

        snapshot.Remove(0);
        Assert.Equal(1, await restarted.CollectAsync(store, paused: false, excludedApplications: ""));
        var events = await store.ReadAsync();
        Assert.Equal(2, events.Count);
        Assert.Contains(events, item => item.ProcessId == 0 && item.Category == "Proces zniknął z migawki");
        Assert.DoesNotContain(events, item => item.ProcessId == 10_000);
        Assert.False((await store.ReadProcessMonitorSnapshotAsync()).Truncated);

        snapshot.Add(0, "new-after-complete-sample");
        Assert.Equal(1, await restarted.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal("new-after-complete-sample", Assert.Single(await store.ReadAsync(),
            item => item.ProcessId == 0 && item.Category == "Proces zaobserwowany" && item.Application == "new-after-complete-sample").Application);
    }

    [Fact]
    public async Task TruncationMetadataAdvancesWhenExcludedProcessesDoNotChangePersistedBaseline()
    {
        var store = new LocalStore(directory); await store.InitializeAsync();
        var snapshot = Enumerable.Range(1, 10_000).ToDictionary(id => id, _ => "synthetic-process");
        var monitor = new ProcessSnapshotMonitor(() => new(snapshot));
        Assert.Equal(0, await monitor.CollectAsync(store, paused: false,
            excludedApplications: "synthetic-process;extra-process"));
        Assert.False((await store.ReadProcessMonitorSnapshotAsync()).Truncated);

        snapshot.Add(10_001, "extra-process");
        Assert.Equal(0, await monitor.CollectAsync(store, paused: false,
            excludedApplications: "synthetic-process;extra-process"));
        Assert.True((await store.ReadProcessMonitorSnapshotAsync()).Truncated);

        snapshot.Remove(10_001);
        Assert.Equal(0, await monitor.CollectAsync(store, paused: false,
            excludedApplications: "synthetic-process;extra-process"));
        Assert.False((await store.ReadProcessMonitorSnapshotAsync()).Truncated);
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
    public async Task InitialProcessSourceFailureDoesNotPreventEngineMonitorStartupOrFloodHistory()
    {
        var available = false;
        var snapshot = new Dictionary<int, string>();
        Dictionary<int, string> ReadSnapshot() => available
            ? new(snapshot)
            : throw new IOException("synthetic startup failure");
        var monitor = new ProcessSnapshotMonitor(ReadSnapshot);
        var store = new LocalStore(directory);
        await store.InitializeAsync();

        Assert.Contains("Snapshot procesów niedostępny: IOException", monitor.State);
        available = true;
        snapshot.Add(41, "already-running-process");
        Assert.Equal(0, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Empty(await store.ReadAsync());

        snapshot.Add(42, "started-after-baseline");
        Assert.Equal(1, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(42, Assert.Single(await store.ReadAsync()).ProcessId);
    }

    [Fact]
    public async Task InitialProcessSourceFailureStillComparesAgainstPersistedBaseline()
    {
        var available = true;
        var snapshot = new Dictionary<int, string> { [41] = "existing-process" };
        Dictionary<int, string> ReadSnapshot() => available
            ? new(snapshot)
            : throw new IOException("synthetic startup failure");
        var store = new LocalStore(directory);
        await store.InitializeAsync();
        var first = new ProcessSnapshotMonitor(ReadSnapshot);
        Assert.Equal(0, await first.CollectAsync(store, paused: false, excludedApplications: ""));

        available = false;
        var restarted = new ProcessSnapshotMonitor(ReadSnapshot);
        available = true;
        snapshot.Add(42, "started-while-engine-stopped");

        Assert.Equal(1, await restarted.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(42, Assert.Single(await store.ReadAsync()).ProcessId);
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
        var fullExplanation = new string('e', 1800);
        var fullRecommendation = new string('r', 1800);
        SecurityEvent Filler() => new(0, DateTimeOffset.UtcNow, RiskLevel.Information, "Proces zaobserwowany", "new-process",
            fullExplanation, fullRecommendation, EventStatus.New,
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

        int? rejectedProcessId = null;
        for (var processId = 42; processId < 10_000; processId++)
        {
            snapshot.Add(processId, "new-process");
            var stored = await monitor.CollectAsync(store, paused: false, excludedApplications: "");
            if (stored == 0)
            {
                rejectedProcessId = processId;
                break;
            }
            Assert.Equal(processId, Assert.Single(await store.ReadAsync(), item => item.ProcessId == processId).ProcessId);
        }

        Assert.NotNull(rejectedProcessId);
        Assert.Contains("pozostają do ponowienia", monitor.State);
        Assert.DoesNotContain(await store.ReadAsync(), item => item.ProcessId == rejectedProcessId);

        await store.DeleteHistoryAsync();
        Assert.Equal(1, await monitor.CollectAsync(store, paused: false, excludedApplications: ""));
        Assert.Equal(rejectedProcessId, Assert.Single(await store.ReadAsync()).ProcessId);
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
