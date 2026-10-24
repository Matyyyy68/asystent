using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using Sentinel.Core;
using Sentinel.Core.Analysis;

public sealed record PersistenceSnapshotEntry(string Source, string Fingerprint, bool WritableLocation);
public sealed record PersistenceRegistrySnapshotCapture(bool Available, IReadOnlyDictionary<string, PersistenceSnapshotEntry> Entries, string Status);

/// <summary>Observes selected Windows persistence sources. Raw registry commands and file paths stay in memory and are never persisted.</summary>
public sealed class WindowsPersistenceSnapshotMonitor : IDisposable
{
    private const int MaximumEntries = 1024;
    private const int MaximumEventsPerSample = 32;
    private readonly Func<IReadOnlyDictionary<string, PersistenceSnapshotEntry>> capture;
    private readonly Func<CancellationToken, Task<ScheduledTaskSnapshotCapture>> captureScheduledTasks;
    private readonly Func<CancellationToken, Task<PersistenceRegistrySnapshotCapture>> captureServices;
    private readonly TimeSpan minimumInterval;
    private long? lastAttemptTimestamp;
    private bool? wasEnabled;

    public string State { get; private set; } = "Monitor zmian autostartu jest wyłączony.";

    public WindowsPersistenceSnapshotMonitor(TimeSpan? minimumInterval = null)
        : this(CaptureSupportedPlatform, WindowsScheduledTaskSnapshotReader.CaptureAsync,
            _ => Task.FromResult(CaptureServiceRegistry()), minimumInterval) { }

    public WindowsPersistenceSnapshotMonitor(
        Func<IReadOnlyDictionary<string, PersistenceSnapshotEntry>> capture,
        TimeSpan? minimumInterval = null)
        : this(capture, _ => Task.FromResult(new ScheduledTaskSnapshotCapture(false,
            new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal), "syntetyczne źródło bez zadań")),
            _ => Task.FromResult(new PersistenceRegistrySnapshotCapture(false,
                new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal), "syntetyczne źródło bez usług")), minimumInterval) { }

    public WindowsPersistenceSnapshotMonitor(
        Func<IReadOnlyDictionary<string, PersistenceSnapshotEntry>> capture,
        Func<CancellationToken, Task<ScheduledTaskSnapshotCapture>> captureScheduledTasks,
        TimeSpan? minimumInterval = null)
        : this(capture, captureScheduledTasks,
            _ => Task.FromResult(new PersistenceRegistrySnapshotCapture(false,
                new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal), "syntetyczne źródło bez usług")), minimumInterval) { }

    public WindowsPersistenceSnapshotMonitor(
        Func<IReadOnlyDictionary<string, PersistenceSnapshotEntry>> capture,
        Func<CancellationToken, Task<ScheduledTaskSnapshotCapture>> captureScheduledTasks,
        Func<CancellationToken, Task<PersistenceRegistrySnapshotCapture>> captureServices,
        TimeSpan? minimumInterval = null)
    {
        this.capture = capture ?? throw new ArgumentNullException(nameof(capture));
        this.captureScheduledTasks = captureScheduledTasks ?? throw new ArgumentNullException(nameof(captureScheduledTasks));
        this.captureServices = captureServices ?? throw new ArgumentNullException(nameof(captureServices));
        this.minimumInterval = minimumInterval ?? TimeSpan.FromSeconds(30);
        if (this.minimumInterval < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(minimumInterval));
    }

    public async Task<int> CollectAsync(LocalStore store, bool enabled, bool paused, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (!enabled || paused)
        {
            if (wasEnabled is null or true)
            {
                try { await store.ResetWindowsPersistenceMonitorSnapshotAsync(cancellationToken); }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    State = "Nie można wyczyścić lokalnego baseline'u autostartu: " + exception.GetType().Name;
                    wasEnabled = false;
                    return 0;
                }
            }
            lastAttemptTimestamp = null;
            wasEnabled = false;
            State = paused ? "Monitor zmian autostartu wstrzymany." : "Monitor zmian autostartu jest wyłączony.";
            return 0;
        }

        if (!OperatingSystem.IsWindows())
        {
            State = "Monitor zmian autostartu wymaga Windows.";
            return 0;
        }

        if (wasEnabled == true && lastAttemptTimestamp is { } previous && Stopwatch.GetElapsedTime(previous) < minimumInterval) return 0;
        wasEnabled = true;
        lastAttemptTimestamp = Stopwatch.GetTimestamp();

        IReadOnlyDictionary<string, PersistenceSnapshotEntry> baseSnapshot;
        try { baseSnapshot = capture(); }
        catch (Exception exception)
        {
            State = "Źródła autostartu Windows niedostępne: " + exception.GetType().Name;
            return 0;
        }

        if (baseSnapshot.Count > MaximumEntries)
        {
            State = $"Snapshot autostartu przekracza limit {MaximumEntries}; zmiany pominięto do następnej próbki.";
            return 0;
        }

        WindowsPersistenceMonitorSnapshot stored;
        try { stored = await store.ReadWindowsPersistenceMonitorSnapshotAsync(cancellationToken); }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            State = "Nie można odczytać lokalnego baseline'u autostartu: " + exception.GetType().Name;
            return 0;
        }

        ScheduledTaskSnapshotCapture scheduledTasks;
        try { scheduledTasks = await captureScheduledTasks(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            scheduledTasks = new(false, new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal),
                "źródło niedostępne (" + exception.GetType().Name + ")");
        }
        var currentSnapshot = baseSnapshot.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        var scheduledTaskStatus = scheduledTasks.Status;
        if (scheduledTasks.Available)
        {
            var invalidTaskEntries = scheduledTasks.Entries.Any(pair => pair.Value.Source != "scheduled.task" || !pair.Key.StartsWith("scheduled.task:", StringComparison.Ordinal));
            if (invalidTaskEntries || currentSnapshot.Count + scheduledTasks.Entries.Count > MaximumEntries)
            {
                scheduledTasks = new(false, new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal),
                    invalidTaskEntries ? "snapshot ma nieprawidłowy format" : $"liczba źródeł przekracza limit {MaximumEntries}");
                scheduledTaskStatus = scheduledTasks.Status;
            }
            else if (!stored.ScheduledTasksInitialized && stored.Initialized)
            {
                try
                {
                    await store.InitializeWindowsScheduledTaskSnapshotAsync(scheduledTasks.Entries
                        .Select(pair => new WindowsPersistenceFingerprint(pair.Key, pair.Value.Source, pair.Value.Fingerprint, pair.Value.WritableLocation)).ToArray(), cancellationToken).ConfigureAwait(false);
                    stored = await store.ReadWindowsPersistenceMonitorSnapshotAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    scheduledTasks = new(false, new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal),
                        "nie można ustawić baseline'u (" + exception.GetType().Name + ")");
                    scheduledTaskStatus = scheduledTasks.Status;
                }
            }
        }

        if (scheduledTasks.Available)
        {
            foreach (var pair in scheduledTasks.Entries) currentSnapshot[pair.Key] = pair.Value;
        }
        else
        {
            // A permission or source failure must not look like every scheduled task was removed.
            foreach (var pair in stored.Entries.Where(pair => pair.Value.Source == "scheduled.task"))
                currentSnapshot[pair.Key] = new(pair.Value.Source, pair.Value.Fingerprint, pair.Value.WritableLocation);
        }

        PersistenceRegistrySnapshotCapture services;
        try { services = await captureServices(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            services = new(false, new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal),
                "źródło niedostępne (" + exception.GetType().Name + ")");
        }
        var serviceStatus = services.Status;
        if (services.Available)
        {
            var invalidServiceEntries = services.Entries.Any(pair =>
                pair.Value.Source is not ("registry.service" or "registry.driver") ||
                !pair.Key.StartsWith(pair.Value.Source + ":", StringComparison.Ordinal));
            if (invalidServiceEntries || currentSnapshot.Count + services.Entries.Count > MaximumEntries)
            {
                services = new(false, new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal),
                    invalidServiceEntries ? "snapshot ma nieprawidłowy format" : $"liczba źródeł przekracza limit {MaximumEntries}");
                serviceStatus = services.Status;
            }
            else if (!stored.ServicesInitialized && stored.Initialized)
            {
                try
                {
                    await store.InitializeWindowsServiceSnapshotAsync(services.Entries
                        .Select(pair => new WindowsPersistenceFingerprint(pair.Key, pair.Value.Source, pair.Value.Fingerprint, pair.Value.WritableLocation)).ToArray(), cancellationToken).ConfigureAwait(false);
                    stored = await store.ReadWindowsPersistenceMonitorSnapshotAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    services = new(false, new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal),
                        "nie można ustawić baseline'u (" + exception.GetType().Name + ")");
                    serviceStatus = services.Status;
                }
            }
        }
        if (services.Available)
        {
            foreach (var pair in services.Entries) currentSnapshot[pair.Key] = pair.Value;
        }
        else
        {
            // A registry access failure must not look like every service and driver was removed.
            foreach (var pair in stored.Entries.Where(pair => pair.Value.Source is "registry.service" or "registry.driver"))
                currentSnapshot[pair.Key] = new(pair.Value.Source, pair.Value.Fingerprint, pair.Value.WritableLocation);
        }

        var snapshot = (IReadOnlyDictionary<string, PersistenceSnapshotEntry>)currentSnapshot;
        if (snapshot.Count > MaximumEntries)
        {
            State = $"Snapshot autostartu przekracza limit {MaximumEntries}; zmiany pominięto do następnej próbki.";
            return 0;
        }
        var now = DateTimeOffset.UtcNow;
        var current = snapshot.ToDictionary(pair => pair.Key,
            pair => new WindowsPersistenceFingerprint(pair.Key, pair.Value.Source, pair.Value.Fingerprint, pair.Value.WritableLocation), StringComparer.Ordinal);
        if (!stored.Initialized)
        {
            try { await store.InitializeWindowsPersistenceMonitorSnapshotAsync(current.Values.ToArray(), scheduledTasks.Available, services.Available, cancellationToken); }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                State = "Nie można ustawić lokalnego baseline'u autostartu: " + exception.GetType().Name;
                return 0;
            }
            State = $"Monitor zmian autostartu działa; ustawiono baseline {snapshot.Count} wpisów. Scheduled Tasks: {scheduledTaskStatus}. Usługi/sterowniki: {serviceStatus}.";
            return 0;
        }
        var baseline = stored.Entries.ToDictionary(pair => pair.Key,
            pair => new PersistenceSnapshotEntry(pair.Value.Source, pair.Value.Fingerprint, pair.Value.WritableLocation), StringComparer.Ordinal);

        var changes = GetChanges(baseline, snapshot).Take(MaximumEventsPerSample).ToArray();
        var recorded = 0;
        foreach (var change in changes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var suspicious = change.Current?.WritableLocation == true;
            var verb = change.Kind switch { PersistenceChangeKind.Added => "dodano", PersistenceChangeKind.Changed => "zmieniono", _ => "usunięto" };
            var source = change.Current?.Source ?? change.Previous!.Source;
            var isWinlogon = source is "registry.user.winlogon" or "registry.machine64.winlogon" or "registry.machine32.winlogon";
            var sourceName = source switch
            {
                "registry.user.run" => "HKCU Run",
                "registry.user.runonce" => "HKCU RunOnce",
                "registry.machine64.run" => "HKLM Run (64-bit)",
                "registry.machine64.runonce" => "HKLM RunOnce (64-bit)",
                "registry.machine32.run" => "HKLM Run (32-bit)",
                "registry.machine32.runonce" => "HKLM RunOnce (32-bit)",
                "registry.user.runonceex" => "HKCU RunOnceEx",
                "registry.machine64.runonceex" => "HKLM RunOnceEx (64-bit)",
                "registry.machine32.runonceex" => "HKLM RunOnceEx (32-bit)",
                "registry.user.policy.run" => "HKCU Policies Explorer Run",
                "registry.machine64.policy.run" => "HKLM Policies Explorer Run (64-bit)",
                "registry.machine32.policy.run" => "HKLM Policies Explorer Run (32-bit)",
                "registry.user.winlogon" => "HKCU Winlogon",
                "registry.machine64.winlogon" => "HKLM Winlogon (64-bit)",
                "registry.machine32.winlogon" => "HKLM Winlogon (32-bit)",
                "registry.machine64.appinit" => "HKLM AppInit_DLLs (64-bit)",
                "registry.machine32.appinit" => "HKLM AppInit_DLLs (32-bit)",
                "registry.machine64.ifeo" => "HKLM IFEO Debugger (64-bit)",
                "registry.machine32.ifeo" => "HKLM IFEO Debugger (32-bit)",
                "registry.machine64.silent.exit" => "HKLM SilentProcessExit (64-bit)",
                "registry.machine32.silent.exit" => "HKLM SilentProcessExit (32-bit)",
                "registry.machine64.shell.delay" => "HKLM ShellServiceObjectDelayLoad (64-bit)",
                "registry.machine32.shell.delay" => "HKLM ShellServiceObjectDelayLoad (32-bit)",
                "startup.user" => "folder Startup użytkownika",
                "startup.common" => "wspólny folder Startup",
                "scheduled.task" => "zaplanowane zadanie Windows",
                "registry.service" => "usługa Windows",
                "registry.driver" => "sterownik Windows",
                _ => "autostart Windows"
            };
            var sourceSubject = source switch
            {
                "scheduled.task" => "zaplanowane zadanie Windows",
                "registry.service" => "usługę Windows",
                "registry.driver" => "sterownik Windows",
                "registry.machine64.ifeo" or "registry.machine32.ifeo" => "ustawienie IFEO Debugger Windows",
                "registry.machine64.silent.exit" or "registry.machine32.silent.exit" => "ustawienie SilentProcessExit Windows",
                "registry.machine64.shell.delay" or "registry.machine32.shell.delay" => "ustawienie rozszerzenia powłoki Windows",
                _ => "wpis autostartu"
            };
            var eventApplication = isWinlogon ? "Logowanie Windows · " + sourceName : source is "scheduled.task" or "registry.service" or "registry.driver"
                or "registry.machine64.ifeo" or "registry.machine32.ifeo"
                or "registry.machine64.silent.exit" or "registry.machine32.silent.exit"
                or "registry.machine64.shell.delay" or "registry.machine32.shell.delay"
                ? "Trwałość Windows · " + sourceName : "Autostart Windows · " + sourceName;
            var recommendation = source switch
            {
                "scheduled.task" => "Sprawdź wpis w Harmonogramie zadań Windows. Sentinel nie uruchamia ani nie usuwa zadań.",
                "registry.service" or "registry.driver" => "Sprawdź konfigurację usługi lub sterownika w Windows. Sentinel nie zmienia konfiguracji ani nie zatrzymuje komponentów.",
                "registry.machine64.ifeo" or "registry.machine32.ifeo" => "Sprawdź konfigurację IFEO Debugger dla aplikacji w rejestrze Windows. Sentinel nie zmienia wpisu ani nie uruchamia debuggera.",
                "registry.machine64.silent.exit" or "registry.machine32.silent.exit" => "Sprawdź konfigurację SilentProcessExit Windows. Sentinel nie uruchamia monitor process ani nie tworzy zrzutów pamięci.",
                "registry.machine64.shell.delay" or "registry.machine32.shell.delay" => "Sprawdź konfigurację ShellServiceObjectDelayLoad Windows. Sentinel nie zmienia rejestru ani nie ładuje rozszerzeń powłoki.",
                "registry.user.policy.run" or "registry.machine64.policy.run" or "registry.machine32.policy.run" => "Sprawdź ustawienia zasad autostartu Windows. Sentinel nie zmienia zasad ani nie uruchamia wpisów.",
                "registry.user.winlogon" or "registry.machine64.winlogon" or "registry.machine32.winlogon" => "Sprawdź konfigurację logowania Windows. Sentinel nie zmienia powłoki ani skryptów logowania.",
                "registry.machine64.appinit" or "registry.machine32.appinit" => "Sprawdź konfigurację AppInit_DLLs Windows. Sentinel nie zmienia rejestru ani nie ładuje wskazanych bibliotek.",
                _ => "Sprawdź listę aplikacji uruchamianych podczas logowania w ustawieniach Windows. Sentinel nie uruchamia ani nie usuwa wpisów."
            };
            var evidenceScope = source switch
            {
                "registry.user.run" => "user.run",
                "registry.user.runonce" => "user.runonce",
                "registry.machine64.run" => "machine64.run",
                "registry.machine64.runonce" => "machine64.runonce",
                "registry.machine32.run" => "machine32.run",
                "registry.machine32.runonce" => "machine32.runonce",
                "registry.user.runonceex" => "user.runonceex",
                "registry.machine64.runonceex" => "machine64.runonceex",
                "registry.machine32.runonceex" => "machine32.runonceex",
                "registry.user.policy.run" => "user.policy-run",
                "registry.machine64.policy.run" => "machine64.policy-run",
                "registry.machine32.policy.run" => "machine32.policy-run",
                "registry.user.winlogon" => "user.winlogon",
                "registry.machine64.winlogon" => "machine64.winlogon",
                "registry.machine32.winlogon" => "machine32.winlogon",
                "registry.machine64.appinit" => "machine64.appinit",
                "registry.machine32.appinit" => "machine32.appinit",
                "registry.machine64.ifeo" => "machine64.ifeo",
                "registry.machine32.ifeo" => "machine32.ifeo",
                "registry.machine64.silent.exit" => "machine64.silent-exit",
                "registry.machine32.silent.exit" => "machine32.silent-exit",
                "registry.machine64.shell.delay" => "machine64.shell-delay",
                "registry.machine32.shell.delay" => "machine32.shell-delay",
                "startup.user" => "user.startup",
                "startup.common" => "common.startup",
                "scheduled.task" => "scheduled-task",
                "registry.service" => "service",
                "registry.driver" => "driver",
                _ => "unknown"
            };
            var evidence = new List<string> { "persistence." + evidenceScope + "." + change.Kind.ToString().ToLowerInvariant() };
            if (suspicious) evidence.Add("persistence.target.user-writable-location");
            var item = new SecurityEvent(0, now, suspicious ? RiskLevel.Low : RiskLevel.Information,
                isWinlogon ? "Zmiana konfiguracji logowania Windows" : source switch
                {
                    "scheduled.task" => "Zmiana zaplanowanego zadania Windows",
                    "registry.service" => "Zmiana usługi Windows",
                    "registry.driver" => "Zmiana sterownika Windows",
                    "registry.machine64.ifeo" or "registry.machine32.ifeo" => "Zmiana konfiguracji uruchamiania procesu Windows",
                    "registry.machine64.silent.exit" or "registry.machine32.silent.exit" => "Zmiana monitorowania zakończenia procesu Windows",
                    "registry.machine64.shell.delay" or "registry.machine32.shell.delay" => "Zmiana konfiguracji rozszerzenia powłoki Windows",
                    _ => "Zmiana autostartu Windows"
                }, eventApplication,
                isWinlogon
                    ? $"Wykryto zmianę konfiguracji logowania Windows ({verb}). Surowa nazwa wartości i polecenie nie są zapisywane."
                    : $"Wykryto, że {verb} {sourceSubject}. Surowa nazwa, polecenie i ścieżka nie są zapisywane.",
                recommendation,
                EventStatus.New, EventId: Guid.NewGuid(), Source: "windows-persistence-snapshot",
                RuleVersion: ThreatAnalysisEngine.RulesVersion, EvidenceCodes: evidence);
            try { await store.CommitWindowsPersistenceChangeAsync(change.Key, change.Current is null ? null : current[change.Key], item, cancellationToken); }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                State = "Nie można zapisać zmiany autostartu lokalnie: " + exception.GetType().Name;
                return recorded;
            }

            ApplyChange(baseline, change);
            recorded++;
        }

        // Advance unchanged entries and removed entries only after the corresponding events have been written.
        var changedKeys = changes.Select(change => change.Key).ToHashSet(StringComparer.Ordinal);
        foreach (var key in snapshot.Keys)
            if (!changedKeys.Contains(key) && baseline.TryGetValue(key, out var oldEntry) &&
                string.Equals(oldEntry.Fingerprint, snapshot[key].Fingerprint, StringComparison.Ordinal))
                baseline[key] = snapshot[key];

        var pending = GetChanges(baseline, snapshot).Count;
        State = pending > 0
            ? $"Monitor zmian autostartu działa; zapisano {recorded} zmian, {pending} czeka na kolejną próbkę z powodu limitu. Scheduled Tasks: {scheduledTaskStatus}. Usługi/sterowniki: {serviceStatus}."
            : $"Monitor zmian autostartu działa; {snapshot.Count} wpisów użytkownika i systemu, zapisano {recorded} zmian. Scheduled Tasks: {scheduledTaskStatus}. Usługi/sterowniki: {serviceStatus}.";
        return recorded;
    }

    private static IReadOnlyList<PersistenceChange> GetChanges(
        IReadOnlyDictionary<string, PersistenceSnapshotEntry> previous,
        IReadOnlyDictionary<string, PersistenceSnapshotEntry> current)
    {
        var changes = new List<PersistenceChange>();
        foreach (var (key, entry) in current.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            if (!previous.TryGetValue(key, out var oldEntry)) changes.Add(new(key, PersistenceChangeKind.Added, null, entry));
            else if (!string.Equals(entry.Fingerprint, oldEntry.Fingerprint, StringComparison.Ordinal))
                changes.Add(new(key, PersistenceChangeKind.Changed, oldEntry, entry));
        }
        foreach (var (key, entry) in previous.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            if (!current.ContainsKey(key)) changes.Add(new(key, PersistenceChangeKind.Removed, entry, null));
        return changes;
    }

    private static void ApplyChange(IDictionary<string, PersistenceSnapshotEntry> baseline, PersistenceChange change)
    {
        if (change.Current is null) baseline.Remove(change.Key);
        else baseline[change.Key] = change.Current;
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyDictionary<string, PersistenceSnapshotEntry> CaptureUserPersistence()
    {
        var entries = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal);
        var runPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        var runOncePath = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
        var runOnceExPath = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx";
        var policyRunPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run";
        var winlogonPath = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
        var appInitPath = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
        var shellDelayPath = "Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad";
        CaptureRunKey(RegistryHive.CurrentUser, RegistryView.Default, runPath, "registry.user.run", entries);
        CaptureRunKey(RegistryHive.CurrentUser, RegistryView.Default, runOncePath, "registry.user.runonce", entries);
        CaptureRunOnceEx(RegistryHive.CurrentUser, RegistryView.Default, runOnceExPath, "registry.user.runonceex", entries);
        CaptureRunKey(RegistryHive.CurrentUser, RegistryView.Default, policyRunPath, "registry.user.policy.run", entries);
        CaptureRegistryValues(RegistryHive.CurrentUser, RegistryView.Default, winlogonPath, "registry.user.winlogon", ["Shell", "Userinit"], entries);
        var views = Environment.Is64BitOperatingSystem
            ? new[] { (RegistryView.Registry64, "machine64"), (RegistryView.Registry32, "machine32") }
            : new[] { (RegistryView.Default, "machine32") };
        foreach (var (view, sourcePrefix) in views)
        {
            CaptureRunKey(RegistryHive.LocalMachine, view, runPath, $"registry.{sourcePrefix}.run", entries);
            CaptureRunKey(RegistryHive.LocalMachine, view, runOncePath, $"registry.{sourcePrefix}.runonce", entries);
            CaptureRunOnceEx(RegistryHive.LocalMachine, view, runOnceExPath, $"registry.{sourcePrefix}.runonceex", entries);
            CaptureRunKey(RegistryHive.LocalMachine, view, policyRunPath, $"registry.{sourcePrefix}.policy.run", entries);
            CaptureRegistryValues(RegistryHive.LocalMachine, view, winlogonPath, $"registry.{sourcePrefix}.winlogon", ["Shell", "Userinit"], entries);
            CaptureRegistryValues(RegistryHive.LocalMachine, view, appInitPath, $"registry.{sourcePrefix}.appinit", ["AppInit_DLLs", "LoadAppInit_DLLs", "RequireSignedAppInit_DLLs"], entries);
            CaptureImageFileExecutionOptions(RegistryHive.LocalMachine, view, sourcePrefix, entries);
            CaptureSilentProcessExit(RegistryHive.LocalMachine, view, sourcePrefix, entries);
            CaptureRunKey(RegistryHive.LocalMachine, view, shellDelayPath, $"registry.{sourcePrefix}.shell.delay", entries);
        }
        CaptureStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "startup.user", entries);
        CaptureStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "startup.common", entries);
        return entries;
    }

    private static void CaptureStartupFolder(string startup, string source, IDictionary<string, PersistenceSnapshotEntry> entries)
    {
        if (string.IsNullOrWhiteSpace(startup) || !Directory.Exists(startup)) return;
        var inspected = 0;
        foreach (var path in Directory.EnumerateFileSystemEntries(startup).OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            if (++inspected > MaximumEntries)
            {
                entries["!overflow"] = new("overflow", "", false);
                break;
            }
            var attributes = File.GetAttributes(path);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) continue;
            var info = new FileInfo(path);
            var key = CreateKey(source, Path.GetFileName(path));
            var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{info.Length}:{info.LastWriteTimeUtc.Ticks}")));
            if (!entries.ContainsKey(key) && entries.Count >= MaximumEntries)
            {
                entries["!overflow"] = new("overflow", "", false);
                break;
            }
            entries[key] = new(source, fingerprint, false);
        }
    }

    private static IReadOnlyDictionary<string, PersistenceSnapshotEntry> CaptureSupportedPlatform()
        => OperatingSystem.IsWindows() ? CaptureUserPersistence() : new Dictionary<string, PersistenceSnapshotEntry>();

    private static PersistenceRegistrySnapshotCapture CaptureServiceRegistry()
    {
        if (!OperatingSystem.IsWindows())
            return new(false, new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal), "usługi Windows wymagają Windows");
        try
        {
            var entries = CaptureServiceRegistryEntries();
            return new(true, entries, $"odczytano {entries.Count} usług i sterowników");
        }
        catch (Exception exception)
        {
            return new(false, new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal),
                "źródło niedostępne (" + exception.GetType().Name + ")");
        }
    }

    [SupportedOSPlatform("windows")]
    private static Dictionary<string, PersistenceSnapshotEntry> CaptureServiceRegistryEntries()
    {
        var entries = new Dictionary<string, PersistenceSnapshotEntry>(StringComparer.Ordinal);
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
            Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
        using var services = baseKey.OpenSubKey("SYSTEM\\CurrentControlSet\\Services", writable: false);
        if (services is null) return entries;

        var inspected = 0;
        foreach (var name in services.GetSubKeyNames().OrderBy(value => value, StringComparer.OrdinalIgnoreCase))
        {
            if (++inspected > MaximumEntries) throw new InvalidDataException("Liczba usług i sterowników przekracza limit snapshotu.");
            using var service = services.OpenSubKey(name, writable: false);
            if (service is null) continue;

            var type = ReadDword(service, "Type");
            var isDriver = type is { } serviceType && (serviceType & 0x3) != 0;
            var source = isDriver ? "registry.driver" : "registry.service";
            var imagePath = ReadString(service, "ImagePath");
            var start = ReadDword(service, "Start");
            var errorControl = ReadDword(service, "ErrorControl");
            var objectName = ReadString(service, "ObjectName");
            var delayedAutoStart = ReadDword(service, "DelayedAutoStart");
            string? serviceDll = null;
            using (var parameters = service.OpenSubKey("Parameters", writable: false))
                if (parameters is not null) serviceDll = ReadString(parameters, "ServiceDll");

            var canonical = string.Join("\0", imagePath ?? "", start?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "",
                type?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "",
                errorControl?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "", objectName ?? "",
                delayedAutoStart?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "", serviceDll ?? "");
            var key = CreateKey(source, name);
            if (!entries.ContainsKey(key) && entries.Count >= MaximumEntries)
                throw new InvalidDataException("Łączna liczba źródeł autostartu przekracza limit snapshotu.");
            entries[key] = new(source, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))),
                LooksLikeWritableLocation((imagePath ?? "") + "\0" + (serviceDll ?? "")));
        }
        return entries;
    }

    [SupportedOSPlatform("windows")]
    private static int? ReadDword(RegistryKey key, string name)
        => key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is int value ? value : null;

    [SupportedOSPlatform("windows")]
    private static string? ReadString(RegistryKey key, string name)
        => key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) switch
        {
            string value => value,
            string[] values => string.Join("\0", values),
            _ => null
        };

    [SupportedOSPlatform("windows")]
    private static void CaptureRunKey(RegistryHive hive, RegistryView view, string subKeyPath, string source,
        IDictionary<string, PersistenceSnapshotEntry> entries)
    {
        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var key = baseKey.OpenSubKey(subKeyPath, writable: false);
        if (key is null) return;
        var inspected = 0;
        foreach (var name in key.GetValueNames().OrderBy(valueName => valueName, StringComparer.OrdinalIgnoreCase))
        {
            if (++inspected > MaximumEntries)
            {
                entries["!overflow"] = new("overflow", "", false);
                break;
            }
            var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            var command = value switch
            {
                string text => text,
                string[] values => string.Join("\0", values),
                int number => number.ToString(System.Globalization.CultureInfo.InvariantCulture),
                long number => number.ToString(System.Globalization.CultureInfo.InvariantCulture),
                _ => null
            };
            if (command is null) continue;
            var keyId = CreateKey(source, name);
            var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(command)));
            if (!entries.ContainsKey(keyId) && entries.Count >= MaximumEntries)
            {
                entries["!overflow"] = new("overflow", "", false);
                break;
            }
            entries[keyId] = new(source, fingerprint, LooksLikeWritableLocation(command));
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CaptureRunOnceEx(RegistryHive hive, RegistryView view, string subKeyPath, string source,
        IDictionary<string, PersistenceSnapshotEntry> entries)
    {
        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var root = baseKey.OpenSubKey(subKeyPath, writable: false);
        if (root is null) return;
        var inspected = 0;

        void CaptureKey(RegistryKey key, string relativePath, int depth)
        {
            if (depth > 8 || entries.Count >= MaximumEntries)
            {
                entries["!overflow"] = new("overflow", "", false);
                return;
            }
            foreach (var name in key.GetValueNames().OrderBy(valueName => valueName, StringComparer.OrdinalIgnoreCase))
            {
                if (++inspected > MaximumEntries)
                {
                    entries["!overflow"] = new("overflow", "", false);
                    return;
                }
                var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                var command = value switch
                {
                    string text => text,
                    string[] values => string.Join("\0", values),
                    int number => number.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    long number => number.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    _ => null
                };
                if (command is null) continue;
                var keyId = CreateKey(source, relativePath + "|" + (name.Length == 0 ? "(Default)" : name));
                if (!entries.ContainsKey(keyId) && entries.Count >= MaximumEntries)
                {
                    entries["!overflow"] = new("overflow", "", false);
                    return;
                }
                entries[keyId] = new(source, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(command))),
                    LooksLikeWritableLocation(command));
            }
            foreach (var childName in key.GetSubKeyNames().OrderBy(valueName => valueName, StringComparer.OrdinalIgnoreCase))
            {
                if (++inspected > MaximumEntries)
                {
                    entries["!overflow"] = new("overflow", "", false);
                    return;
                }
                using var child = key.OpenSubKey(childName, writable: false);
                if (child is not null) CaptureKey(child, relativePath.Length == 0 ? childName : relativePath + "\\" + childName, depth + 1);
                if (entries.ContainsKey("!overflow")) return;
            }
        }

        CaptureKey(root, "", 0);
    }

    [SupportedOSPlatform("windows")]
    private static void CaptureRegistryValues(RegistryHive hive, RegistryView view, string subKeyPath, string source,
        IReadOnlyCollection<string> valueNames, IDictionary<string, PersistenceSnapshotEntry> entries)
    {
        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var key = baseKey.OpenSubKey(subKeyPath, writable: false);
        if (key is null) return;
        foreach (var name in valueNames)
        {
            var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            var command = value switch
            {
                string text => text,
                string[] values => string.Join("\0", values),
                _ => null
            };
            if (command is null) continue;
            var keyId = CreateKey(source, name);
            if (!entries.ContainsKey(keyId) && entries.Count >= MaximumEntries)
            {
                entries["!overflow"] = new("overflow", "", false);
                break;
            }
            entries[keyId] = new(source, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(command))),
                LooksLikeWritableLocation(command));
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CaptureImageFileExecutionOptions(RegistryHive hive, RegistryView view, string sourcePrefix,
        IDictionary<string, PersistenceSnapshotEntry> entries)
    {
        const string subKeyPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
        var source = $"registry.{sourcePrefix}.ifeo";
        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var options = baseKey.OpenSubKey(subKeyPath, writable: false);
        if (options is null) return;

        var inspected = 0;
        foreach (var imageName in options.GetSubKeyNames().OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
        {
            if (++inspected > MaximumEntries)
                throw new InvalidDataException("Liczba wpisów IFEO przekracza limit snapshotu.");
            using var imageOptions = options.OpenSubKey(imageName, writable: false);
            if (imageOptions is null) continue;
            var debugger = ReadString(imageOptions, "Debugger");
            if (string.IsNullOrWhiteSpace(debugger)) continue;

            var key = CreateKey(source, imageName);
            if (!entries.ContainsKey(key) && entries.Count >= MaximumEntries)
                throw new InvalidDataException("Łączna liczba źródeł autostartu przekracza limit snapshotu.");
            entries[key] = new(source,
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(debugger))),
                LooksLikeWritableLocation(debugger));
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CaptureSilentProcessExit(RegistryHive hive, RegistryView view, string sourcePrefix,
        IDictionary<string, PersistenceSnapshotEntry> entries)
    {
        const string subKeyPath = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit";
        var source = $"registry.{sourcePrefix}.silent.exit";
        using var baseKey = RegistryKey.OpenBaseKey(hive, view);
        using var root = baseKey.OpenSubKey(subKeyPath, writable: false);
        if (root is null) return;

        var inspected = 0;
        var settingNames = new[] { "MonitorProcess", "ReportingMode", "IgnoreSelfExits", "LocalDumpFolder", "MaxNumberOfDumpFiles", "DumpType", "ModuleIgnoreList" };
        void Capture(RegistryKey key, string imageName)
        {
            var values = new List<string>(settingNames.Length);
            var writableTarget = false;
            foreach (var name in settingNames)
            {
                var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                var canonical = value switch
                {
                    string text => text,
                    string[] strings => string.Join("\0", strings),
                    int number => number.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    long number => number.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    _ => null
                };
                if (canonical is null) continue;
                values.Add(name.ToUpperInvariant() + "=" + canonical);
                if (name is "MonitorProcess" or "LocalDumpFolder")
                    writableTarget |= LooksLikeWritableLocation(canonical);
            }
            if (values.Count == 0) return;
            var keyId = CreateKey(source, imageName);
            if (!entries.ContainsKey(keyId) && entries.Count >= MaximumEntries)
            {
                entries["!overflow"] = new("overflow", "", false);
                return;
            }
            entries[keyId] = new(source, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\0", values)))), writableTarget);
        }

        Capture(root, "(Global)");
        foreach (var imageName in root.GetSubKeyNames().OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
        {
            if (++inspected > MaximumEntries || entries.Count >= MaximumEntries)
            {
                entries["!overflow"] = new("overflow", "", false);
                return;
            }
            using var image = root.OpenSubKey(imageName, writable: false);
            if (image is not null) Capture(image, imageName);
            if (entries.ContainsKey("!overflow")) return;
        }
    }

    private static bool LooksLikeWritableLocation(string command)
    {
        var normalized = command.Replace('/', '\\');
        string[] markers = ["%TEMP%", "%TMP%", "%APPDATA%", "%LOCALAPPDATA%", "\\AppData\\Local\\Temp\\",
            "\\AppData\\Roaming\\", "\\Downloads\\", "\\Users\\Public\\"];
        if (markers.Any(marker => normalized.Contains(marker, StringComparison.OrdinalIgnoreCase))) return true;
        foreach (var specialFolder in new[] { Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolder.ApplicationData,
                     Environment.SpecialFolder.InternetCache, Environment.SpecialFolder.UserProfile })
        {
            var folder = Environment.GetFolderPath(specialFolder);
            if (!string.IsNullOrWhiteSpace(folder) && normalized.Contains(folder + Path.DirectorySeparatorChar + "Temp", StringComparison.OrdinalIgnoreCase)) return true;
        }
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        return !string.IsNullOrWhiteSpace(downloads) && normalized.Contains(downloads, StringComparison.OrdinalIgnoreCase);
    }

    private static string CreateKey(string source, string name)
    {
        var stable = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source + "\0" + name.ToUpperInvariant())));
        return source + ":" + stable;
    }

    public void Dispose() { lastAttemptTimestamp = null; }

    private enum PersistenceChangeKind { Added, Changed, Removed }
    private sealed record PersistenceChange(string Key, PersistenceChangeKind Kind,
        PersistenceSnapshotEntry? Previous, PersistenceSnapshotEntry? Current);
}
