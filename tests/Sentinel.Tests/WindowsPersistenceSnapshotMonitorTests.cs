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
            ["existing"] = Entry("registry.user.run", "fingerprint-existing", false)
        };
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);

        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Empty(await store.ReadAsync());

        snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["existing"] = Entry("registry.user.run", "fingerprint-existing", false),
            ["new"] = Entry("registry.user.runonce", "secret-command-fingerprint", true)
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
            ["one"] = Entry("startup.user", "size:time:1", false)
        };
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);
        await monitor.CollectAsync(store, enabled: true, paused: false);

        snapshot["one"] = Entry("startup.user", "size:time:2", false);
        snapshot["two"] = Entry("registry.user.run", "fingerprint-2", false);
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
            ["one"] = Entry("registry.user.run", "fingerprint-1", false)
        };
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);
        await monitor.CollectAsync(store, enabled: true, paused: false);
        await monitor.CollectAsync(store, enabled: true, paused: true);
        snapshot["one"] = Entry("registry.user.run", "fingerprint-2", false);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Empty(await store.ReadAsync());
        snapshot["two"] = Entry("registry.user.run", "fingerprint-3", false);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
    }

    [Fact]
    public async Task CaptureFailureKeepsPreviousBaselineAndReportsOnlyExceptionType()
    {
        var store = await CreateStore();
        var fail = false;
        var snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["one"] = Entry("registry.user.run", "fingerprint-1", false)
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
        snapshot["two"] = Entry("registry.user.run", "fingerprint-2", false);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
    }

    [Fact]
    public async Task OversizedSnapshotIsSkippedWithoutAdvancingBaseline()
    {
        var store = await CreateStore();
        var snapshot = Enumerable.Range(0, 1025).ToDictionary(index => index.ToString(),
            index => Entry("registry.user.run", "fingerprint-" + index, false), StringComparer.Ordinal);
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);

        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Contains("limit 1024", monitor.State, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await store.ReadAsync());

        snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["safe"] = Entry("registry.user.run", "safe-fingerprint", false)
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
            snapshot[index.ToString()] = Entry("registry.user.run", "fingerprint-" + index, false);
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
            ["hashed-existing-id"] = Entry("registry.user.run", "secret-command-before", false)
        };
        using (var first = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero))
            Assert.Equal(0, await first.CollectAsync(store, enabled: true, paused: false));

        var saved = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(saved.Initialized);
        Assert.Contains("registry.user.run", System.Text.Json.JsonSerializer.Serialize(saved.Entries));
        Assert.DoesNotContain("secret-command-before", System.Text.Json.JsonSerializer.Serialize(saved.Entries), StringComparison.Ordinal);

        snapshot["hashed-existing-id"] = Entry("registry.user.run", "secret-command-after", false);
        using var restarted = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);
        Assert.Equal(1, await restarted.CollectAsync(store, enabled: true, paused: false));
        Assert.Contains(await store.ReadAsync(), item => item.Source == "windows-persistence-snapshot" && item.Explanation.Contains("zmieniono", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DatabaseRestorePreservesTheActivePersistenceBaseline()
    {
        var source = await CreateStore();
        var target = await CreateStore();
        var sourceEntry = new WindowsPersistenceFingerprint("source-id", "registry.user.run", Entry("registry.user.run", "source-command", false).Fingerprint, false);
        var targetEntry = new WindowsPersistenceFingerprint("target-id", "registry.machine64.ifeo", Entry("registry.machine64.ifeo", "target-debugger", false).Fingerprint, false);
        var silentExitEntry = new WindowsPersistenceFingerprint("silent-exit-id", "registry.machine64.silent.exit", Entry("registry.machine64.silent.exit", "reporting-mode", false).Fingerprint, false);
        await source.InitializeWindowsPersistenceMonitorSnapshotAsync([sourceEntry]);
        await target.InitializeWindowsPersistenceMonitorSnapshotAsync([targetEntry, silentExitEntry]);
        var backup = Path.Combine(root, "state.db");
        await source.BackupAsync(backup);

        Assert.Equal(0, await target.RestoreAsync(backup));
        var restored = await target.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(restored.Initialized);
        Assert.Contains("target-id", restored.Entries.Keys);
        Assert.Contains("silent-exit-id", restored.Entries.Keys);
    }

    [Fact]
    public async Task MonitorsBothRegistryViewsAndCommonStartupSources()
    {
        var store = await CreateStore();
        var snapshot = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["machine64-run"] = Entry("registry.machine64.run", "64-bit original", false),
            ["machine32-runonce"] = Entry("registry.machine32.runonce", "32-bit original", false),
            ["shared-startup"] = Entry("startup.common", "common original", false)
        };
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => snapshot, TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        snapshot["machine64-run"] = Entry("registry.machine64.run", "64-bit changed", false);
        snapshot["machine32-runonce"] = Entry("registry.machine32.runonce", "32-bit changed", false);
        snapshot["shared-startup"] = Entry("startup.common", "common changed", false);
        Assert.Equal(3, await monitor.CollectAsync(store, enabled: true, paused: false));
        var events = (await store.ReadAsync()).Where(item => item.Source == "windows-persistence-snapshot").ToArray();
        Assert.Equal(3, events.Length);
        Assert.Contains(events, item => item.EvidenceCodes!.Contains("persistence.machine64.run.changed"));
        Assert.Contains(events, item => item.EvidenceCodes!.Contains("persistence.machine32.runonce.changed"));
        Assert.Contains(events, item => item.EvidenceCodes!.Contains("persistence.common.startup.changed"));
    }

    [Fact]
    public async Task ScheduledTaskChangesAreDetectedWithoutPersistingNamesOrCommands()
    {
        var store = await CreateStore();
        var registry = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal);
        var taskXml = ScheduledTaskXml("\\Sentinel\\Updater", @"C:\Program Files\Sentinel\Updater.exe", "--initial");
        var taskEntries = WindowsScheduledTaskSnapshotReader.ParseXml(taskXml);
        Assert.Single(taskEntries);
        Task<ScheduledTaskSnapshotCapture> CaptureTasks(CancellationToken _) => Task.FromResult(new ScheduledTaskSnapshotCapture(true, taskEntries, "odczytano 1 zadanie"));
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => registry, CaptureTasks, TimeSpan.Zero);

        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        var initial = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(initial.ScheduledTasksInitialized, monitor.State);
        Assert.Empty(await store.ReadAsync());

        taskEntries = WindowsScheduledTaskSnapshotReader.ParseXml(ScheduledTaskXml("\\Sentinel\\Updater", @"C:\Users\Mateusz\AppData\Local\Temp\updater.exe", "--credential=secret-value"));
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var events = await store.ReadAsync();
        var item = Assert.Single(events);
        Assert.Equal("Zmiana zaplanowanego zadania Windows", item.Category);
        Assert.Equal(RiskLevel.Low, item.Risk);
        Assert.Contains("persistence.scheduled-task.changed", item.EvidenceCodes!);
        var persisted = System.Text.Json.JsonSerializer.Serialize(new { Events = events, Snapshot = await store.ReadWindowsPersistenceMonitorSnapshotAsync() });
        Assert.DoesNotContain("Sentinel\\Updater", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("C:\\Users\\Mateusz", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("credential=secret-value", persisted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ServiceAndDriverChangesAreDetectedWithRedactedFingerprints()
    {
        var store = await CreateStore();
        var serviceKey = "registry.service:" + new string('0', 62) + "A1";
        var driverKey = "registry.driver:" + new string('0', 62) + "B2";
        var services = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            [serviceKey] = Entry("registry.service", @"C:\Program Files\Vendor\agent.exe", false),
            [driverKey] = Entry("registry.driver", @"\SystemRoot\System32\drivers\vendor.sys", false)
        };
        var tasks = new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        using var monitor = new WindowsPersistenceSnapshotMonitor(
            () => new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal),
            _ => Task.FromResult(tasks),
            _ => Task.FromResult(new PersistenceRegistrySnapshotCapture(true, services, "odczytano 2 komponenty")), TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Empty(await store.ReadAsync());

        services[serviceKey] = Entry("registry.service", @"C:\Users\Mateusz\AppData\Local\Temp\agent.exe", true);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var events = await store.ReadAsync();
        var item = Assert.Single(events);
        Assert.Equal("Zmiana usługi Windows", item.Category);
        Assert.Contains("persistence.service.changed", item.EvidenceCodes!);
        Assert.Contains("persistence.target.user-writable-location", item.EvidenceCodes!);
        var persisted = System.Text.Json.JsonSerializer.Serialize(new { Events = events, Snapshot = await store.ReadWindowsPersistenceMonitorSnapshotAsync() });
        Assert.DoesNotContain("Vendor", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("C:\\Users\\Mateusz", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("agent.exe", persisted, StringComparison.OrdinalIgnoreCase);

        services.Remove(serviceKey);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Contains(await store.ReadAsync(), candidate => candidate.Category == "Zmiana usługi Windows" &&
            candidate.EvidenceCodes!.Contains("persistence.service.removed"));
    }

    [Fact]
    public async Task ScheduledTaskReadFailurePreservesItsBaselineAndStillDetectsOtherSources()
    {
        var store = await CreateStore();
        var registry = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["registry-id"] = Entry("registry.user.run", "registry-before", false)
        };
        var taskEntries = WindowsScheduledTaskSnapshotReader.ParseXml(ScheduledTaskXml("\\Sentinel\\Task", @"C:\Program Files\Sentinel\Task.exe", ""));
        var tasksAvailable = true;
        Task<ScheduledTaskSnapshotCapture> CaptureTasks(CancellationToken _) => Task.FromResult(tasksAvailable
            ? new ScheduledTaskSnapshotCapture(true, taskEntries, "odczytano 1 zadanie")
            : new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "odmowa lub błąd źródła (kod 1)"));
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => registry, CaptureTasks, TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        tasksAvailable = false;
        registry["registry-id"] = Entry("registry.user.run", "registry-after", false);
        var recorded = await monitor.CollectAsync(store, enabled: true, paused: false);
        Assert.True(recorded == 1, monitor.State);
        var events = await store.ReadAsync();
        Assert.Single(events);
        Assert.Contains("persistence.user.run.changed", events[0].EvidenceCodes!);
        Assert.DoesNotContain(events, item => item.EvidenceCodes!.Any(code => code.Contains("scheduled-task.removed", StringComparison.Ordinal)));
        var snapshot = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.Contains(snapshot.Entries.Values, item => item.Source == "scheduled.task");
        Assert.Contains("odmowa lub błąd źródła", monitor.State, StringComparison.OrdinalIgnoreCase);

        tasksAvailable = true;
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Single(await store.ReadAsync());
    }

    [Fact]
    public async Task ServiceRegistryReadFailurePreservesBaselineAndStillDetectsRunChanges()
    {
        var store = await CreateStore();
        var registry = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["run-id"] = Entry("registry.user.run", "run-before", false)
        };
        var serviceEntry = Entry("registry.service", "service-before", false);
        var services = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["registry.service:" + new string('0', 64)] = serviceEntry
        };
        var serviceAvailable = true;
        Task<PersistenceRegistrySnapshotCapture> CaptureServices(CancellationToken _) => Task.FromResult(serviceAvailable
            ? new PersistenceRegistrySnapshotCapture(true, services, "odczytano 1 usługę")
            : new PersistenceRegistrySnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "źródło niedostępne (SecurityException)"));
        var tasks = new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => registry, _ => Task.FromResult(tasks), CaptureServices, TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Empty(await store.ReadAsync());

        registry["run-id"] = Entry("registry.user.run", "run-after", false);
        services.Clear();
        serviceAvailable = false;
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var events = await store.ReadAsync();
        Assert.Single(events);
        Assert.Contains("persistence.user.run.changed", events[0].EvidenceCodes!);
        Assert.DoesNotContain(events, item => item.EvidenceCodes!.Any(code => code.StartsWith("persistence.service.", StringComparison.Ordinal)));
        Assert.Contains("SecurityException", monitor.State, StringComparison.Ordinal);
        var preserved = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.Contains(preserved.Entries.Values, item => item.Source == "registry.service");

        serviceAvailable = true;
        services["registry.service:" + new string('0', 64)] = serviceEntry;
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Single(await store.ReadAsync());
    }

    [Fact]
    public async Task PolicyRunRegistryChangeIsRecordedWithRedactedEvidence()
    {
        var store = await CreateStore();
        var entries = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["policy-entry"] = Entry("registry.user.policy.run", "old command", false)
        };
        var tasks = new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        var services = new PersistenceRegistrySnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => entries,
            _ => Task.FromResult(tasks), _ => Task.FromResult(services), TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        entries["policy-entry"] = Entry("registry.user.policy.run", "C:\\Users\\Alice\\AppData\\Local\\Temp\\payload.exe", true);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var item = Assert.Single(await store.ReadAsync());
        Assert.Equal("Zmiana autostartu Windows", item.Category);
        Assert.Contains("persistence.user.policy-run.changed", item.EvidenceCodes!);
        Assert.Contains("persistence.target.user-writable-location", item.EvidenceCodes!);
        Assert.Contains("Sprawdź ustawienia zasad autostartu Windows", item.Recommendation, StringComparison.OrdinalIgnoreCase);
        var serialized = System.Text.Json.JsonSerializer.Serialize(item);
        Assert.DoesNotContain("payload.exe", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Alice", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("old command", serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WinlogonChangeIsRecordedWithoutShellOrUserinitValue()
    {
        var store = await CreateStore();
        var entries = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["winlogon-shell"] = Entry("registry.machine64.winlogon", "explorer.exe", false)
        };
        var tasks = new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        var services = new PersistenceRegistrySnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => entries,
            _ => Task.FromResult(tasks), _ => Task.FromResult(services), TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        entries["winlogon-shell"] = Entry("registry.machine64.winlogon", "C:\\Users\\Alice\\AppData\\Local\\Temp\\shell.exe", true);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var item = Assert.Single(await store.ReadAsync());
        Assert.Equal("Zmiana konfiguracji logowania Windows", item.Category);
        Assert.Equal("Logowanie Windows · HKLM Winlogon (64-bit)", item.Application);
        Assert.Contains("persistence.machine64.winlogon.changed", item.EvidenceCodes!);
        Assert.Contains("Sprawdź konfigurację logowania Windows", item.Recommendation, StringComparison.OrdinalIgnoreCase);
        var serialized = System.Text.Json.JsonSerializer.Serialize(item);
        Assert.DoesNotContain("shell.exe", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Alice", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("explorer.exe", serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AppInitChangeIsRecordedWithoutPersistingLibraryPath()
    {
        var store = await CreateStore();
        var entries = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["registry.machine64.appinit:" + new string('A', 64)] = Entry("registry.machine64.appinit", "initial-library.dll|load=0", false)
        };
        var tasks = new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        var services = new PersistenceRegistrySnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => entries,
            _ => Task.FromResult(tasks), _ => Task.FromResult(services), TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        entries["registry.machine64.appinit:" + new string('A', 64)] = Entry("registry.machine64.appinit", @"C:\Users\Alice\AppData\Local\Temp\payload.dll|load=1", true);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var item = Assert.Single(await store.ReadAsync());
        Assert.Equal("Zmiana autostartu Windows", item.Category);
        Assert.Equal("Autostart Windows · HKLM AppInit_DLLs (64-bit)", item.Application);
        Assert.Contains("persistence.machine64.appinit.changed", item.EvidenceCodes!);
        Assert.Contains("persistence.target.user-writable-location", item.EvidenceCodes!);
        var persisted = System.Text.Json.JsonSerializer.Serialize(new { Events = await store.ReadAsync(), Snapshot = await store.ReadWindowsPersistenceMonitorSnapshotAsync() });
        Assert.DoesNotContain("payload.dll", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Alice", persisted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ShellServiceObjectDelayLoadChangeIsRecordedWithoutPersistingExtensionDetails()
    {
        var store = await CreateStore();
        const string source = "registry.machine64.shell.delay";
        var key = source + ":" + new string('C', 64);
        var entries = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            [key] = Entry(source, "{00000000-0000-0000-0000-000000000001}", false)
        };
        var tasks = new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        var services = new PersistenceRegistrySnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => entries,
            _ => Task.FromResult(tasks), _ => Task.FromResult(services), TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        entries[key] = Entry(source, @"C:\Users\Alice\AppData\Local\Temp\shell-extension.dll", true);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var item = Assert.Single(await store.ReadAsync());
        Assert.Equal("Zmiana konfiguracji rozszerzenia powłoki Windows", item.Category);
        Assert.Equal("Trwałość Windows · HKLM ShellServiceObjectDelayLoad (64-bit)", item.Application);
        Assert.Contains("persistence.machine64.shell-delay.changed", item.EvidenceCodes!);
        Assert.Contains("Sprawdź konfigurację ShellServiceObjectDelayLoad", item.Recommendation, StringComparison.OrdinalIgnoreCase);
        var persisted = System.Text.Json.JsonSerializer.Serialize(new { Events = await store.ReadAsync(), Snapshot = await store.ReadWindowsPersistenceMonitorSnapshotAsync() });
        Assert.DoesNotContain("shell-extension.dll", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Alice", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("00000000-0000-0000-0000-000000000001", persisted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunOnceExChangeIsRecordedWithoutPersistingSubkeyOrCommand()
    {
        var store = await CreateStore();
        const string source = "registry.machine64.runonceex";
        var key = source + ":" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source + "\0" + "0001|1")));
        var entries = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            [key] = Entry(source, @"C:\Program Files\Vendor\setup.exe /quiet", false)
        };
        var tasks = new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        var services = new PersistenceRegistrySnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => entries,
            _ => Task.FromResult(tasks), _ => Task.FromResult(services), TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        entries[key] = Entry(source, @"C:\Users\Alice\AppData\Local\Temp\payload.exe /silent", true);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var item = Assert.Single(await store.ReadAsync());
        Assert.Equal("Autostart Windows · HKLM RunOnceEx (64-bit)", item.Application);
        Assert.Contains("persistence.machine64.runonceex.changed", item.EvidenceCodes!);
        var persisted = System.Text.Json.JsonSerializer.Serialize(new { Events = await store.ReadAsync(), Snapshot = await store.ReadWindowsPersistenceMonitorSnapshotAsync() });
        Assert.DoesNotContain("payload.exe", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Alice", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("0001|1", persisted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SilentProcessExitChangeIsRecordedWithoutPersistingImageOrMonitorCommand()
    {
        var store = await CreateStore();
        const string source = "registry.machine64.silent.exit";
        var key = source + ":" + new string('2', 64);
        var entries = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            [key] = Entry(source, "mode=4", false)
        };
        var tasks = new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        var services = new PersistenceRegistrySnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => entries,
            _ => Task.FromResult(tasks), _ => Task.FromResult(services), TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        entries[key] = Entry(source, @"MonitorProcess=C:\Users\Alice\AppData\Local\Temp\watcher.exe;LocalDumpFolder=C:\Users\Alice\AppData\Local\Temp\dumps", true);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var item = Assert.Single(await store.ReadAsync());
        Assert.Equal("Zmiana monitorowania zakończenia procesu Windows", item.Category);
        Assert.Equal("Trwałość Windows · HKLM SilentProcessExit (64-bit)", item.Application);
        Assert.Contains("persistence.machine64.silent-exit.changed", item.EvidenceCodes!);
        var persisted = System.Text.Json.JsonSerializer.Serialize(new { Events = await store.ReadAsync(), Snapshot = await store.ReadWindowsPersistenceMonitorSnapshotAsync() });
        Assert.DoesNotContain("watcher.exe", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Alice", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("dumps", persisted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IfeoDebuggerChangeIsRecordedWithoutPersistingExecutableOrDebuggerPath()
    {
        var store = await CreateStore();
        var entries = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal)
        {
            ["registry.machine64.ifeo:" + new string('B', 64)] = Entry("registry.machine64.ifeo", "C:\\Windows\\System32\\WerFault.exe", false)
        };
        var tasks = new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        var services = new PersistenceRegistrySnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        using var monitor = new WindowsPersistenceSnapshotMonitor(() => entries,
            _ => Task.FromResult(tasks), _ => Task.FromResult(services), TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        entries["registry.machine64.ifeo:" + new string('B', 64)] = Entry("registry.machine64.ifeo", @"C:\Users\Alice\AppData\Local\Temp\debugger.exe", true);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        var item = Assert.Single(await store.ReadAsync());
        Assert.Equal("Zmiana konfiguracji uruchamiania procesu Windows", item.Category);
        Assert.Equal("Trwałość Windows · HKLM IFEO Debugger (64-bit)", item.Application);
        Assert.Contains("persistence.machine64.ifeo.changed", item.EvidenceCodes!);
        Assert.Contains("persistence.target.user-writable-location", item.EvidenceCodes!);
        var persisted = System.Text.Json.JsonSerializer.Serialize(new { Events = await store.ReadAsync(), Snapshot = await store.ReadWindowsPersistenceMonitorSnapshotAsync() });
        Assert.DoesNotContain("debugger.exe", persisted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Alice", persisted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task NewlyAvailableServiceSourceGetsSilentBaseline()
    {
        var store = await CreateStore();
        var services = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal);
        var available = false;
        Task<PersistenceRegistrySnapshotCapture> CaptureServices(CancellationToken _) => Task.FromResult(new PersistenceRegistrySnapshotCapture(
            available, services, available ? "odczytano usługę" : "źródło niedostępne"));
        var tasks = new ScheduledTaskSnapshotCapture(false, new Dictionary<string, PersistenceSnapshotEntry>(), "niedostępne");
        using var monitor = new WindowsPersistenceSnapshotMonitor(
            () => new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal),
            _ => Task.FromResult(tasks), CaptureServices, TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));

        services["registry.service:" + new string('1', 64)] = Entry("registry.service", "preexisting service", false);
        available = true;
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Empty(await store.ReadAsync());
        Assert.True((await store.ReadWindowsPersistenceMonitorSnapshotAsync()).ServicesInitialized);

        services["registry.service:" + new string('1', 64)] = Entry("registry.service", "changed service", false);
        Assert.Equal(1, await monitor.CollectAsync(store, enabled: true, paused: false));
        Assert.Contains((await store.ReadAsync()).Single().EvidenceCodes!, code => code == "persistence.service.changed");
    }

    [Fact]
    public async Task ScheduledTaskReaderRejectsExternalEntityXml()
    {
        var xml = "<!DOCTYPE Tasks [<!ENTITY secret SYSTEM 'file:///C:/Windows/win.ini'>]><Task><RegistrationInfo><URI>&secret;</URI></RegistrationInfo></Task>";
        Assert.Throws<System.Xml.XmlException>(() => WindowsScheduledTaskSnapshotReader.ParseXml(xml));
    }

    [Fact]
    public async Task LiveReadOnlyScheduledTaskEnumerationWhenExplicitlyEnabled()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("SENTINEL_LIVE_TASKS"), "1", StringComparison.Ordinal)) return;
        var result = await WindowsScheduledTaskSnapshotReader.CaptureAsync();
        Assert.True(result.Available, result.Status);
        Assert.InRange(result.Entries.Count, 1, 256);
        var store = await CreateStore();
        using var monitor = new WindowsPersistenceSnapshotMonitor(
            () => new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal),
            WindowsScheduledTaskSnapshotReader.CaptureAsync, TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        var baseline = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(baseline.ScheduledTasksInitialized);
        Assert.Equal(result.Entries.Count, baseline.Entries.Values.Count(entry => entry.Source == "scheduled.task"));
        Assert.All(baseline.Entries.Values.Where(entry => entry.Source == "scheduled.task"), entry =>
        {
            Assert.Matches("^scheduled\\.task:[A-F0-9]{64}$", entry.Key);
            Assert.Matches("^[A-F0-9]{64}$", entry.Fingerprint);
        });
    }

    [Fact]
    public async Task SchemaV19BaselineMigratesToExpandedSourceAllowlist()
    {
        var store = await CreateStore();
        var fingerprint = Entry("registry.user.run", "migrated command", false).Fingerprint;
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "DROP TABLE windows_persistence_snapshot; CREATE TABLE windows_persistence_snapshot(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.run','registry.runonce','startup.folder')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot VALUES('legacy-key','registry.run','" + fingerprint + "',0); UPDATE windows_persistence_monitor_metadata SET initialized=1 WHERE id=1; PRAGMA user_version=19;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        var migrated = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(migrated.Initialized);
        var entry = Assert.Single(migrated.Entries.Values);
        Assert.Equal("registry.user.run", entry.Source);
        Assert.Equal(fingerprint, entry.Fingerprint);
    }

    [Fact]
    public async Task SchemaV24BaselineMigratesToServiceAndDriverSources()
    {
        var store = await CreateStore();
        var fingerprint = Entry("registry.user.run", "existing command", false).Fingerprint;
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "DROP TABLE windows_persistence_snapshot; CREATE TABLE windows_persistence_snapshot(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','startup.user','startup.common','scheduled.task')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot VALUES('existing-run','registry.user.run','" + fingerprint + "',0); UPDATE windows_persistence_monitor_metadata SET initialized=1 WHERE id=1; PRAGMA user_version=24;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        var migrated = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(migrated.Initialized);
        Assert.Equal(fingerprint, Assert.Single(migrated.Entries.Values).Fingerprint);

        await store.InitializeWindowsPersistenceMonitorSnapshotAsync([
            new("hashed-service-id", "registry.service", fingerprint, false),
            new("hashed-driver-id", "registry.driver", fingerprint, false)
        ]);
        var expanded = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.Equal(2, expanded.Entries.Count);
        Assert.Contains(expanded.Entries.Values, entry => entry.Source == "registry.service");
        Assert.Contains(expanded.Entries.Values, entry => entry.Source == "registry.driver");
    }

    [Fact]
    public async Task SchemaV26BaselineMigratesToPolicyRunSources()
    {
        var store = await CreateStore();
        var fingerprint = Entry("registry.user.run", "existing command", false).Fingerprint;
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "DROP TABLE windows_persistence_snapshot; CREATE TABLE windows_persistence_snapshot(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot VALUES('existing-run','registry.user.run','" + fingerprint + "',0); UPDATE windows_persistence_monitor_metadata SET initialized=1 WHERE id=1; PRAGMA user_version=26;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        var migrated = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(migrated.Initialized);
        Assert.Equal(fingerprint, Assert.Single(migrated.Entries.Values).Fingerprint);

        await store.InitializeWindowsPersistenceMonitorSnapshotAsync([
            new("policy-user-entry", "registry.user.policy.run", fingerprint, false),
            new("policy-machine-entry", "registry.machine64.policy.run", fingerprint, false)
        ]);
        var expanded = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.Equal(2, expanded.Entries.Count);
        Assert.Contains(expanded.Entries.Values, entry => entry.Source == "registry.user.policy.run");
        Assert.Contains(expanded.Entries.Values, entry => entry.Source == "registry.machine64.policy.run");
    }

    [Fact]
    public async Task SchemaV27BaselineMigratesToWinlogonSources()
    {
        var store = await CreateStore();
        var fingerprint = Entry("registry.user.run", "existing command", false).Fingerprint;
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "DROP TABLE windows_persistence_snapshot; CREATE TABLE windows_persistence_snapshot(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot VALUES('existing-run','registry.user.run','" + fingerprint + "',0); UPDATE windows_persistence_monitor_metadata SET initialized=1 WHERE id=1; PRAGMA user_version=27;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        var migrated = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(migrated.Initialized);
        Assert.Equal(fingerprint, Assert.Single(migrated.Entries.Values).Fingerprint);
        await store.InitializeWindowsPersistenceMonitorSnapshotAsync([
            new("winlogon-user", "registry.user.winlogon", fingerprint, false),
            new("winlogon-machine", "registry.machine64.winlogon", fingerprint, false)
        ]);
        var expanded = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.Equal(2, expanded.Entries.Count);
        Assert.Contains(expanded.Entries.Values, entry => entry.Source == "registry.user.winlogon");
        Assert.Contains(expanded.Entries.Values, entry => entry.Source == "registry.machine64.winlogon");
    }

    [Fact]
    public async Task SchemaV28BaselineMigratesToAppInitIfeoAndShellExtensionSources()
    {
        var store = await CreateStore();
        var fingerprint = Entry("registry.user.run", "existing command", false).Fingerprint;
        await using (var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.DatabasePath};Pooling=False"))
        {
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "DROP TABLE windows_persistence_snapshot; CREATE TABLE windows_persistence_snapshot(entry_key TEXT PRIMARY KEY CHECK(length(entry_key) BETWEEN 1 AND 100), source TEXT NOT NULL CHECK(source IN ('registry.user.run','registry.user.runonce','registry.machine64.run','registry.machine64.runonce','registry.machine32.run','registry.machine32.runonce','registry.user.policy.run','registry.machine64.policy.run','registry.machine32.policy.run','registry.user.winlogon','registry.machine64.winlogon','registry.machine32.winlogon','startup.user','startup.common','scheduled.task','registry.service','registry.driver')), fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64), writable_location INTEGER NOT NULL CHECK(writable_location IN (0,1))); INSERT INTO windows_persistence_snapshot VALUES('existing-run','registry.user.run','" + fingerprint + "',0); UPDATE windows_persistence_monitor_metadata SET initialized=1 WHERE id=1; PRAGMA user_version=28;";
            await command.ExecuteNonQueryAsync();
        }

        await store.InitializeAsync();
        await store.InitializeWindowsPersistenceMonitorSnapshotAsync([
            new("existing-run", "registry.user.run", fingerprint, false),
            new("registry.machine64.appinit:" + new string('A', 64), "registry.machine64.appinit", fingerprint, false),
            new("registry.machine64.ifeo:" + new string('B', 64), "registry.machine64.ifeo", fingerprint, false),
            new("registry.machine64.shell.delay:" + new string('C', 64), "registry.machine64.shell.delay", fingerprint, false),
            new("registry.machine32.shell.delay:" + new string('D', 64), "registry.machine32.shell.delay", fingerprint, false),
            new("registry.user.runonceex:" + new string('E', 64), "registry.user.runonceex", fingerprint, false),
            new("registry.machine64.runonceex:" + new string('F', 64), "registry.machine64.runonceex", fingerprint, false),
            new("registry.machine32.runonceex:" + new string('1', 64), "registry.machine32.runonceex", fingerprint, false),
            new("registry.machine64.silent.exit:" + new string('2', 64), "registry.machine64.silent.exit", fingerprint, false),
            new("registry.machine32.silent.exit:" + new string('3', 64), "registry.machine32.silent.exit", fingerprint, false)
        ]);
        var migrated = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.Contains(migrated.Entries.Values, entry => entry.Source == "registry.user.run");
        Assert.Contains(migrated.Entries.Values, entry => entry.Source == "registry.machine64.appinit");
        Assert.Contains(migrated.Entries.Values, entry => entry.Source == "registry.machine64.ifeo");
        Assert.Contains(migrated.Entries.Values, entry => entry.Source == "registry.machine64.shell.delay");
        Assert.Contains(migrated.Entries.Values, entry => entry.Source == "registry.machine32.shell.delay");
        Assert.Contains(migrated.Entries.Values, entry => entry.Source == "registry.user.runonceex");
        Assert.Contains(migrated.Entries.Values, entry => entry.Source == "registry.machine64.runonceex");
        Assert.Contains(migrated.Entries.Values, entry => entry.Source == "registry.machine32.runonceex");
        Assert.Contains(migrated.Entries.Values, entry => entry.Source == "registry.machine64.silent.exit");
        Assert.Contains(migrated.Entries.Values, entry => entry.Source == "registry.machine32.silent.exit");
    }

    [Fact]
    public async Task LiveReadOnlyServiceRegistryEnumerationWhenExplicitlyEnabled()
    {
        if (!OperatingSystem.IsWindows() || !string.Equals(Environment.GetEnvironmentVariable("SENTINEL_LIVE_SERVICES"), "1", StringComparison.Ordinal)) return;
        var store = await CreateStore();
        using var monitor = new WindowsPersistenceSnapshotMonitor(TimeSpan.Zero);
        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        var snapshot = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(snapshot.Initialized, monitor.State);
        if (!snapshot.ServicesInitialized)
        {
            Assert.Contains("SecurityException", monitor.State, StringComparison.Ordinal);
            return;
        }
        Assert.Contains(snapshot.Entries.Values, entry => entry.Source is "registry.service" or "registry.driver");
        Assert.All(snapshot.Entries.Values.Where(entry => entry.Source is "registry.service" or "registry.driver"), entry =>
        {
            Assert.Matches("^(registry\\.(service|driver)):[A-F0-9]{64}$", entry.Key);
            Assert.Matches("^[A-F0-9]{64}$", entry.Fingerprint);
        });
    }

    [Fact]
    public async Task LiveReadOnlyRunAndWinlogonRegistryEnumerationWhenExplicitlyEnabled()
    {
        if (!OperatingSystem.IsWindows() || !string.Equals(Environment.GetEnvironmentVariable("SENTINEL_LIVE_PERSISTENCE"), "1", StringComparison.Ordinal)) return;
        var store = await CreateStore();
        using var monitor = new WindowsPersistenceSnapshotMonitor(TimeSpan.Zero);

        Assert.Equal(0, await monitor.CollectAsync(store, enabled: true, paused: false));
        var snapshot = await store.ReadWindowsPersistenceMonitorSnapshotAsync();
        Assert.True(snapshot.Initialized, monitor.State);
        Assert.NotEmpty(snapshot.Entries);
        Assert.All(snapshot.Entries, pair =>
        {
            Assert.Matches("^[a-z0-9.]+:[A-F0-9]{64}$", pair.Key);
            Assert.Matches("^[A-F0-9]{64}$", pair.Value.Fingerprint);
            Assert.Contains(pair.Value.Source, new[]
            {
                "registry.user.run", "registry.user.runonce", "registry.user.policy.run", "registry.user.winlogon",
                "registry.machine64.run", "registry.machine64.runonce", "registry.machine64.policy.run", "registry.machine64.winlogon",
                "registry.machine32.run", "registry.machine32.runonce", "registry.machine32.policy.run", "registry.machine32.winlogon",
                "registry.machine64.appinit", "registry.machine32.appinit",
                "registry.machine64.shell.delay", "registry.machine32.shell.delay",
                "registry.user.runonceex", "registry.machine64.runonceex", "registry.machine32.runonceex",
                "registry.machine64.silent.exit", "registry.machine32.silent.exit",
                "startup.user", "startup.common", "scheduled.task", "registry.service", "registry.driver"
            });
        });
        Assert.Contains(snapshot.Entries.Values, entry => entry.Source.EndsWith(".winlogon", StringComparison.Ordinal));
    }

    private static PersistenceSnapshotEntry Entry(string source, string value, bool writable)
        => new(source, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))), writable);

    private static string ScheduledTaskXml(string uri, string command, string arguments)
        => $"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><RegistrationInfo><URI>{System.Security.SecurityElement.Escape(uri)}</URI></RegistrationInfo><Actions><Exec><Command>{System.Security.SecurityElement.Escape(command)}</Command><Arguments>{System.Security.SecurityElement.Escape(arguments)}</Arguments></Exec></Actions></Task>";

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
