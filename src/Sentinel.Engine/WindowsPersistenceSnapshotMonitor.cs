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
    private Dictionary<string, PersistenceSnapshotEntry>? baseline;
    private DateTimeOffset? lastAttempt;
    private bool wasEnabled;

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
            baseline = null;
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
        if (wasEnabled && lastAttempt is { } previous && now - previous < minimumInterval) return 0;
        wasEnabled = true;
        lastAttempt = now;

        IReadOnlyDictionary<string, PersistenceSnapshotEntry> snapshot;
        try { snapshot = capture(); }
        catch (Exception exception)
        {
            State = "Źródła autostartu bieżącego użytkownika niedostępne: " + exception.GetType().Name;
            return 0;
        }

        if (snapshot.Count > MaximumEntries)
        {
            State = $"Snapshot autostartu przekracza limit {MaximumEntries}; zmiany pominięto do następnej próbki.";
            return 0;
        }

        if (baseline is null)
        {
            baseline = snapshot.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
            State = $"Monitor zmian autostartu działa; ustawiono baseline {snapshot.Count} wpisów.";
            return 0;
        }

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
                "registry.run" => "HKCU Run",
                "registry.runonce" => "HKCU RunOnce",
                "startup.folder" => "folder Startup użytkownika",
                _ => "autostart bieżącego użytkownika"
            };
            var evidence = new List<string> { "persistence.user." + source.Split('.')[1] + "." + change.Kind.ToString().ToLowerInvariant() };
            if (suspicious) evidence.Add("persistence.target.user-writable-location");
            var item = new SecurityEvent(0, now, suspicious ? RiskLevel.Low : RiskLevel.Information,
                "Zmiana autostartu Windows", "Autostart bieżącego użytkownika · " + sourceName,
                $"Wykryto, że {verb} wpis autostartu. Surowa nazwa, polecenie i ścieżka nie są zapisywane.",
                "Sprawdź listę aplikacji uruchamianych podczas logowania w ustawieniach Windows. Sentinel nie uruchamia ani nie usuwa wpisów.",
                EventStatus.New, EventId: Guid.NewGuid(), Source: "windows-persistence-snapshot",
                RuleVersion: ThreatAnalysisEngine.RulesVersion, EvidenceCodes: evidence);
            try { await store.AddLocalOnlyAsync(item, cancellationToken); }
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
            : $"Monitor zmian autostartu działa; {snapshot.Count} wpisów bieżącego użytkownika, zapisano {recorded} zmian.";
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
        CaptureRunKey(RegistryHive.CurrentUser, RegistryView.Default, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "registry.run", entries);
        CaptureRunKey(RegistryHive.CurrentUser, RegistryView.Default, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "registry.runonce", entries);

        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (!string.IsNullOrWhiteSpace(startup) && Directory.Exists(startup))
        {
            var inspected = 0;
            foreach (var path in Directory.EnumerateFileSystemEntries(startup).OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
            {
                if (++inspected > MaximumEntries)
                {
                    entries["!overflow"] = new("overflow", "", false);
                    break;
                }
                try
                {
                    var attributes = File.GetAttributes(path);
                    if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) continue;
                    var info = new FileInfo(path);
                    var key = CreateKey("startup.folder", Path.GetFileName(path));
                    var fingerprint = $"{info.Length}:{info.LastWriteTimeUtc.Ticks}";
                    if (!entries.ContainsKey(key) && entries.Count >= MaximumEntries)
                    {
                        entries["!overflow"] = new("overflow", "", false);
                        break;
                    }
                    entries[key] = new("startup.folder", fingerprint, false);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        return entries;
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
            try
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
                var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(command)));
                if (!entries.ContainsKey(keyId) && entries.Count >= MaximumEntries)
                {
                    entries["!overflow"] = new("overflow", "", false);
                    break;
                }
                entries[keyId] = new(source, fingerprint, LooksLikeWritableLocation(command));
            }
            catch (System.Security.SecurityException) { }
            catch (IOException) { }
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

    public void Dispose() { baseline = null; }

    private enum PersistenceChangeKind { Added, Changed, Removed }
    private sealed record PersistenceChange(string Key, PersistenceChangeKind Kind,
        PersistenceSnapshotEntry? Previous, PersistenceSnapshotEntry? Current);
}
