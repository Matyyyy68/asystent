using Sentinel.Core;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Sentinel.Tests;

public sealed class WindowsPersistenceSnapshotMonitorTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "sentinel-persistence-monitor-" + Guid.NewGuid());

    [Fact]
    public async Task BaselineIsSilentAndLaterChangesAreLocalAndRedacted()
    {
        var store = await CreateStore();
        var snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["existing"] = Entry("registry.run", "fingerprint-existing", false)
        };
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);

        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Empty(await store.ReadAsync());

        snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["existing"] = Entry("registry.run", "fingerprint-existing", false),
            ["new"] = Entry("registry.runonce", "secret-command-fingerprint", true)
        };
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));

        var events = await store.ReadAsync();
        var item = Assert.Single(events);
        Assert.Equal("windows-persistence-snapshot", item.Source);
        Assert.Equal(RiskLevel.Low, item.Risk);
        Assert.Contains("persistence.target.user-writable-location", item.EvidenceCodes!);
        Assert.DoesNotContain("secret-command", System.Text.Json.JsonSerializer.Serialize(events), StringComparison.Ordinal);
        Assert.DoesNotContain("new", System.Text.Json.JsonSerializer.Serialize(events), StringComparison.Ordinal);
        Assert.Empty(await store.ReadPendingEnterpriseEventsAsync());
        Assert.Contains("zapisano 1 zmian", monitor.State, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DetectsChangeAndRemovalAndDoesNotDuplicateUnchangedEntries()
    {
        var store = await CreateStore();
        var snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["one"] = Entry("startup.folder", "size:time:1", false)
        };
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);
        await monitor.CollectAsync(store, enabled: true, paused: false);

        snapshot["one"] = Entry("startup.folder", "size:time:2", false);
        snapshot["two"] = Entry("registry.run", "fingerprint-2", false);
        Assert.Equal(2, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        snapshot.Remove("one");
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var events = await store.ReadAsync();
        Assert.Equal(3, events.Count(item => item.Source == "windows-persistence-snapshot"));
        Assert.Contains(events, item => item.Explanation.Contains("zmieniono", StringComparison.Ordinal));
        Assert.Contains(events, item => item.Explanation.Contains("usunięto", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PauseAndDisableClearBaselineWithoutReportingPausedChanges()
    {
        var store = await CreateStore();
        var snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["one"] = Entry("registry.run", "fingerprint-1", false)
        };
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);
        await monitor.CollectAsync(store, enabled: true, paused: false);
        await monitor.CollectAsync(store, enabled: true, paused: true);
        snapshot["one"] = Entry("registry.run", "fingerprint-2", false);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Empty(await store.ReadAsync());
        snapshot["two"] = Entry("registry.run", "fingerprint-3", false);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
    }

    [Fact]
    public async Task CaptureFailureKeepsPreviousBaselineAndReportsOnlyExceptionType()
    {
        var store = await CreateStore();
        var fail = false;
        var snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["one"] = Entry("registry.run", "fingerprint-1", false)
        };
        IReadOnlyDictionary<string, PersistenceSnapshotEntry> Capture()
        {
            if (fail) throw new UnauthorizedAccessException("secret path");
            return snapshot;
        }
        using var monitor = new WindowsPersistenceSnapshotMonitor(Capture, TimeSpan.Zero);
        await monitor.CollectAsync(store, enabled: true, paused: false);
        fail = true;
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Contains(nameof(UnauthorizedAccessException), monitor.State, StringComparison.Ordinal);
        Assert.DoesNotContain("secret path", monitor.State, StringComparison.Ordinal);

        fail = false;
        snapshot["two"] = Entry("registry.run", "fingerprint-2", false);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
    }

    [Fact]
    public async Task OversizedSnapshotIsSkippedWithoutAdvancingBaseline()
    {
        var store = await CreateStore();
        var snapshot = Enumerable.Range(0, 257).ToDictionary(index => index.ToString(),
            index => Entry("registry.run", "fingerprint-" + index, false), StringComparer.Ordinal);
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);

        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Contains("limit 256", monitor.State, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await store.ReadAsync());

        snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["safe"] = Entry("registry.run", "safe-fingerprint", false)
        };
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Empty(await store.ReadAsync());
    }

    [Fact]
    public async Task ChangeQueueIsBoundedAndDrainsOnFollowingSamples()
    {
        var store = await CreateStore();
        var snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal);
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);
        await monitor.CollectAsync(store, enabled: true, paused: false);

        for (var index = 0; index < 40; index++)
            snapshot[index.ToString()] = Entry("registry.run", "fingerprint-" + index, false);
        Assert.Equal(32, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Contains("8 czeka", monitor.State, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(8, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Equal(40, (await store.ReadAsync()).Count(item => item.Source == "windows-persistence-snapshot"));
    }

    [Fact]
    public async Task PersistenceMonitoringSettingSurvivesStoreReopenAndDefaultsOff()
    {
        var data = Path.Combine(root, "settings");
        var store = new LocalStore(data);
        await store.InitializeAsync();
        Assert.False((await store.LoadSettingsAsync()).MonitorPersistenceChanges);
        await store.SaveSettingsAsync(new AppSettings(MonitorPersistenceChanges: true));
        var reopened = new LocalStore(data);
        await reopened.InitializeAsync();
        Assert.True((await reopened.LoadSettingsAsync()).MonitorPersistenceChanges);
    }

    [Fact]
    public async Task PersistedBaselineDetectsChangesAfterMonitorRestartWithoutStoringRawValues()
    {
        var store = await CreateStore();
        var snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["hashed-existing-id"] = Entry("registry.run", "secret-command-before", false)
        };
        using (var first = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero))
            Assert.Equal(0, await first.CollectAsync(store, enabled: true, paused: false));

        var saved = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(saved.Initialized);
        Assert.Contains("registry.run", System.Text.Json.JsonSerializer.Serialize(saved.Entries));
        Assert.DoesNotContain("secret-command-before", System.Text.Json.JsonSerializer.Serialize(saved.Entries), StringComparison.Ordinal);

        snapshot["hashed-existing-id"] = Entry("registry.run", "secret-command-after", false);
        using var restarted = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);
        Assert.Equal(1, await restarted.CollectAsync(store, enabled: true, paused: false));
        Assert.Contains(await store.ReadAsync(), item => item.Source == "windows-persistence-snapshot" && item.Explanation.Contains("zmieniono", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DatabaseRestorePreservesTheActivePersistenceBaseline()
    {
        var source = await CreateStore();
        var target = await CreateStore();
        var sourceEntry = new WindowsPersistenceFingerprint("source-id", "registry.run", Entry("registry.run", "source-command", false).Fingerprint, false);
        var targetEntry = new WindowsPersistenceFingerprint("target-id", "startup.folder", Entry("startup.folder", "target-command", false).Fingerprint, false);
        await source.InitializeWindowsPersistenceMonitorSnapshotAsync([sourceEntry]);
        await target.InitializeWindowsPersistenceMonitorSnapshotAsync([targetEntry]);
        var backup = Path.Combine(root, "state.db");
        await source.BackupAsync(backup);

        Assert.Equal(0, await target.RestoreAsync(backup));
        var restored = await target.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(restored.Initialized);
        Assert.Equal("target-id", Assert.Single(restored.Entries.Keys));
    }

    private static PersistenceSnapshotEntry Entry(string source, string value, bool writable)
        => new(source, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))), writable);

    private async Task<LocalStore> CreateStore()
    {
        var store = new LocalStore(Path.Combine(root, Guid.NewGuid().ToString("N")));
        await store.InitializeAsync();
        return store;
    }

    public void Dispose()
    {
        try { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
        catch { }
    }
}
