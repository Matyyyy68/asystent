using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using Sentinel.Core;
using Sentinel.Core.Analysis;

public sealed record PersistenceSnapshotEntry(string Source, string Fingerprint, bool WritableLocation);

/// <summary>Observes per-user autorun state. Raw registry commands and file paths stay in memory and are never persisted.</summary>
public sealed class WindowsPersistenceSnapshotMonitor : IDisposable
{
    private const int MaximumEntries = 256;
    private const int MaximumEventsPerSample = 32;
    private readonly Func<IReadOnlyDictionary<string, PersistenceSnapshotEntry>> capture;
    private readonly TimeSpan minimumInterval;
    private DateTimeOffset? lastAttempt;
    private bool? wasEnabled;

    public string State { get; private set; } = "Monitor zmian autostartu jest wyłączony.";

    public WindowsPersistenceSnapshotMonitor(TimeSpan? minimumInterval = null)
        : this(CaptureSupportedPlatform, minimumInterval) { }

    public WindowsPersistenceSnapshotMonitor(
        Func<IReadOnlyDictionary<string, PersistenceSnapshotEntry>> capture,
        TimeSpan? minimumInterval = null)
    {
        this.capture = capture ?? throw new ArgumentNullException(nameof(capture));
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
            lastAttempt = null;
            wasEnabled = false;
            State = paused ? "Monitor zmian autostartu wstrzymany." : "Monitor zmian autostartu jest wyłączony.";
            return 0;
        }

        if (!OperatingSystem.IsWindows())
        {
            State = "Monitor zmian autostartu wymaga Windows.";
            return 0;
        }

        var now = DateTimeOffset.UtcNow;
        if (wasEnabled == true && lastAttempt is { } previous && now - previous < minimumInterval) return 0;
        wasEnabled = true;
        lastAttempt = now;

        IReadOnlyDictionary<string, PersistenceSnapshotEntry> snapshot;
        try { snapshot = capture(); }
        catch (Exception exception)
        {
            State = "Źródła autostartu Windows niedostępne: " + exception.GetType().Name;
            return 0;
        }

        if (snapshot.Count > MaximumEntries)
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
        var current = snapshot.ToDictionary(pair => pair.Key,
            pair => new WindowsPersistenceFingerprint(pair.Key, pair.Value.Source, pair.Value.Fingerprint, pair.Value.WritableLocation), StringComparer.Ordinal);
        if (!stored.Initialized)
        {
            try { await store.InitializeWindowsPersistenceMonitorSnapshotAsync(current.Values.ToArray(), cancellationToken); }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                State = "Nie można ustawić lokalnego baseline'u autostartu: " + exception.GetType().Name;
                return 0;
            }
            State = $"Monitor zmian autostartu działa; ustawiono baseline {snapshot.Count} wpisów.";
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
            var sourceName = source switch
            {
                "registry.user.run" => "HKCU Run",
                "registry.user.runonce" => "HKCU RunOnce",
                "registry.machine64.run" => "HKLM Run (64-bit)",
                "registry.machine64.runonce" => "HKLM RunOnce (64-bit)",
                "registry.machine32.run" => "HKLM Run (32-bit)",
                "registry.machine32.runonce" => "HKLM RunOnce (32-bit)",
                "startup.user" => "folder Startup użytkownika",
                "startup.common" => "wspólny folder Startup",
                _ => "autostart Windows"
            };
            var evidenceScope = source switch
            {
                "registry.user.run" => "user.run",
                "registry.user.runonce" => "user.runonce",
                "registry.machine64.run" => "machine64.run",
                "registry.machine64.runonce" => "machine64.runonce",
                "registry.machine32.run" => "machine32.run",
                "registry.machine32.runonce" => "machine32.runonce",
                "startup.user" => "user.startup",
                "startup.common" => "common.startup",
                _ => "unknown"
            };
            var evidence = new List<string> { "persistence." + evidenceScope + "." + change.Kind.ToString().ToLowerInvariant() };
            if (suspicious) evidence.Add("persistence.target.user-writable-location");
            var item = new SecurityEvent(0, now, suspicious ? RiskLevel.Low : RiskLevel.Information,
                "Zmiana autostartu Windows", "Autostart Windows · " + sourceName,
                $"Wykryto, że {verb} wpis autostartu. Surowa nazwa, polecenie i ścieżka nie są zapisywane.",
                "Sprawdź listę aplikacji uruchamianych podczas logowania w ustawieniach Windows. Sentinel nie uruchamia ani nie usuwa wpisów.",
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
            ? $"Monitor zmian autostartu działa; zapisano {recorded} zmian, {pending} czeka na kolejną próbkę z powodu limitu."
            : $"Monitor zmian autostartu działa; {snapshot.Count} wpisów użytkownika i systemu, zapisano {recorded} zmian.";
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
        CaptureRunKey(RegistryHive.CurrentUser, RegistryView.Default, runPath, "registry.user.run", entries);
        CaptureRunKey(RegistryHive.CurrentUser, RegistryView.Default, runOncePath, "registry.user.runonce", entries);
        var views = Environment.Is64BitOperatingSystem
            ? new[] { (RegistryView.Registry64, "machine64"), (RegistryView.Registry32, "machine32") }
            : new[] { (RegistryView.Default, "machine32") };
        foreach (var (view, sourcePrefix) in views)
        {
            CaptureRunKey(RegistryHive.LocalMachine, view, runPath, $"registry.{sourcePrefix}.run", entries);
            CaptureRunKey(RegistryHive.LocalMachine, view, runOncePath, $"registry.{sourcePrefix}.runonce", entries);
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

    public void Dispose() { lastAttempt = null; }

    private enum PersistenceChangeKind { Added, Changed, Removed }
    private sealed record PersistenceChange(string Key, PersistenceChangeKind Kind,
        PersistenceSnapshotEntry? Previous, PersistenceSnapshotEntry? Current);
}
