using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using Sentinel.Core.Analysis;

/// <summary>Opt-in, local-only watcher for new files in the user's Downloads tree.</summary>
public sealed class DownloadedFileMonitor : IDisposable
{
    private const int DefaultMaximumBaselineFiles = 100_000;
    private const int MaximumFilesPerSample = 10;
    private const long MaximumFileBytes = 256L * 1024 * 1024;
    private const long MaximumBytesPerSample = 512L * 1024 * 1024;
    private static readonly TimeSpan SettleTime = TimeSpan.FromMilliseconds(750);
    private readonly string directory;
    private readonly int maximumPendingFiles;
    private readonly int maximumBaselineFiles;
    private readonly TimeSpan reconciliationInterval;
    private readonly ConcurrentDictionary<string, DateTimeOffset> pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> processedFingerprints = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, FileFingerprint> baseline = new(StringComparer.OrdinalIgnoreCase);
    private readonly object pendingGate = new();
    private long droppedPendingFiles;
    private long rescanRequestedVersion;
    private long rescanCompletedVersion;
    private DateTimeOffset lastReconciledAtUtc;
    private FileSystemWatcher? watcher;
    private bool enabledRequested;

    private readonly record struct FileFingerprint(long Length, long LastWriteTicks);

    public string State { get; private set; } = "Monitoring pobranych plików wyłączony.";

    public static string GetKnownDownloadsDirectory()
    {
        var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (!OperatingSystem.IsWindows()) return fallback;
        var downloads = new Guid("374DE290-123F-4565-9164-39C4925E467B");
        try
        {
            var result = SHGetKnownFolderPath(ref downloads, 0, IntPtr.Zero, out var pointer);
            if (result != 0) Marshal.ThrowExceptionForHR(result);
            try
            {
                var path = Marshal.PtrToStringUni(pointer);
                return string.IsNullOrWhiteSpace(path) ? fallback : path;
            }
            finally { Marshal.FreeCoTaskMem(pointer); }
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or COMException)
        {
            return fallback;
        }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    private static extern int SHGetKnownFolderPath(ref Guid rfid, uint flags, IntPtr token, out IntPtr path);

    public DownloadedFileMonitor(string directory, int maximumPendingFiles = 1000, int maximumBaselineFiles = DefaultMaximumBaselineFiles,
        TimeSpan? reconciliationInterval = null)
    {
        if (maximumPendingFiles < 1) throw new ArgumentOutOfRangeException(nameof(maximumPendingFiles));
        if (maximumBaselineFiles < 1) throw new ArgumentOutOfRangeException(nameof(maximumBaselineFiles));
        var interval = reconciliationInterval ?? TimeSpan.FromMinutes(5);
        if (interval <= TimeSpan.Zero || interval > TimeSpan.FromHours(1)) throw new ArgumentOutOfRangeException(nameof(reconciliationInterval));
        this.directory = Path.GetFullPath(directory);
        this.maximumPendingFiles = maximumPendingFiles;
        this.maximumBaselineFiles = maximumBaselineFiles;
        this.reconciliationInterval = interval;
    }

    public async Task SetEnabledAsync(LocalStore store, bool enabled, CancellationToken cancellationToken = default)
    {
        enabledRequested = enabled;
        if (!enabled)
        {
            watcher?.Dispose();
            watcher = null;
            pending.Clear();
            baseline.Clear();
            Interlocked.Exchange(ref rescanCompletedVersion, Interlocked.Read(ref rescanRequestedVersion));
            await store.ResetDownloadedFileMonitorSnapshotAsync(cancellationToken);
            State = "Monitoring pobranych plików wyłączony.";
            return;
        }
        if (watcher is not null) return;
        if (!Directory.Exists(directory))
        {
            State = "Monitoring pobranych plików niedostępny: katalog Downloads nie istnieje.";
            return;
        }

        FileSystemWatcher? next = null;
        try
        {
            next = new FileSystemWatcher(directory)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite,
                Filter = "*",
                EnableRaisingEvents = false
            };
            next.Created += OnFileChanged;
            next.Changed += OnFileChanged;
            next.Deleted += OnFileChanged;
            next.Renamed += OnFileRenamed;
            next.Error += (_, _) =>
            {
                RequestRescan();
                State = "Monitoring Downloads odtwarza zmiany po utracie zdarzeń systemu plików.";
            };
            next.EnableRaisingEvents = true;
            watcher = next;
            var saved = await store.ReadDownloadedFileMonitorSnapshotAsync(cancellationToken);
            if (!saved.Initialized)
            {
                if (!CaptureBaseline())
                {
                    next.Dispose(); watcher = null; baseline.Clear();
                    State = $"Monitoring pobranych plików niedostępny: nie można bezpiecznie ustalić stanu początkowego folderu (limit {maximumBaselineFiles} plików lub błąd odczytu).";
                    return;
                }
                await store.InitializeDownloadedFileMonitorSnapshotAsync(baseline.Select(item => ToStoredFingerprint(item.Key, item.Value)).ToArray(), maximumBaselineFiles, cancellationToken);
            }
            else
            {
                foreach (var item in saved.Files) baseline[item.Key] = new(item.Value.Length, item.Value.LastWriteTicks);
                if (!TryEnumerateFilesWithoutFollowingReparsePoints(out var currentPaths))
                {
                    next.Dispose(); watcher = null;
                    State = $"Monitoring pobranych plików niedostępny: nie można wznowić baseline'u (limit {maximumBaselineFiles} ścieżek lub błąd odczytu).";
                    return;
                }
                await store.PruneDownloadedFileMonitorSnapshotAsync(currentPaths, maximumBaselineFiles, cancellationToken);
                var currentSet = new HashSet<string>(currentPaths, StringComparer.OrdinalIgnoreCase);
                foreach (var stalePath in baseline.Keys.Where(path => !currentSet.Contains(path)).ToArray()) baseline.TryRemove(stalePath, out _);
                Interlocked.Increment(ref rescanRequestedVersion);
            }
            State = saved.Initialized
                ? $"Monitoring Downloads wznowiono z lokalnego baseline'u; zmiany od ostatniej sesji są sprawdzane. Utracone powiadomienia kolejki: {Interlocked.Read(ref droppedPendingFiles)}."
                : $"Monitoring Downloads działa; pliki są sprawdzane lokalnie względem listy hashy. Utracone powiadomienia kolejki: {Interlocked.Read(ref droppedPendingFiles)}.";
            lastReconciledAtUtc = DateTimeOffset.UtcNow;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or SqliteException or InvalidDataException)
        {
            next?.Dispose();
            if (ReferenceEquals(watcher, next)) watcher = null;
            pending.Clear();
            baseline.Clear();
            State = "Monitoring pobranych plików niedostępny: " + exception.GetType().Name;
        }
    }

    public async Task<int> CollectAsync(LocalStore store, FileHashReputation reputation, CancellationToken cancellationToken = default)
    {
        if (enabledRequested && watcher is null)
            await SetEnabledAsync(store, true, cancellationToken);
        if (watcher is null) return 0;
        if (DateTimeOffset.UtcNow - lastReconciledAtUtc >= reconciliationInterval) RequestRescan();
        await ReconcileIfNeededAsync(store, cancellationToken);
        if (reputation.Status().HashCount == 0)
        {
            State = $"Monitoring Downloads działa; zaimportuj lokalną listę hashy, aby sprawdzać pliki. Utracone powiadomienia kolejki: {Interlocked.Read(ref droppedPendingFiles)}.";
            return 0;
        }
        var cutoff = DateTimeOffset.UtcNow - SettleTime;
        var ready = pending.Where(item => item.Value <= cutoff).Take(MaximumFilesPerSample).ToArray();
        var detections = 0;
        long bytesScanned = 0;
        foreach (var item in ready)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!pending.TryRemove(item.Key, out _)) continue;
            try
            {
                var info = new FileInfo(item.Key);
                if (!IsInsideDownloadsTreeWithoutReparsePoints(info.FullName))
                {
                    await store.RemoveDownloadedFileMonitorPathAsync(info.FullName, cancellationToken);
                    baseline.TryRemove(info.FullName, out _);
                    continue;
                }
                if (!info.Exists)
                {
                    await store.RemoveDownloadedFileMonitorPathAsync(info.FullName, cancellationToken);
                    baseline.TryRemove(info.FullName, out _);
                    continue;
                }
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    await store.RemoveDownloadedFileMonitorPathAsync(info.FullName, cancellationToken);
                    baseline.TryRemove(info.FullName, out _);
                    continue;
                }
                var fileFingerprint = Fingerprint(info);
                if (baseline.TryGetValue(info.FullName, out var previousFingerprint) && previousFingerprint == fileFingerprint) continue;
                if (!baseline.ContainsKey(info.FullName) && baseline.Count >= maximumBaselineFiles)
                {
                    StopAtBaselineLimit();
                    break;
                }
                if (info.Length > MaximumFileBytes)
                {
                    if (!await CommitBaselineAsync(store, info.FullName, fileFingerprint, cancellationToken)) break;
                    continue;
                }
                if (info.Length > MaximumBytesPerSample - bytesScanned)
                {
                    pending[item.Key] = DateTimeOffset.UtcNow;
                    break;
                }
                var fingerprint = ToProcessedFingerprint(info.FullName, fileFingerprint);
                if (processedFingerprints.ContainsKey(fingerprint)) continue;

                string hash;
                await using (var stream = new FileStream(info.FullName, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (stream.Length > MaximumFileBytes) continue;
                    hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken));
                    bytesScanned += stream.Length;
                }
                var after = new FileInfo(info.FullName);
                if (!after.Exists || after.Length != info.Length || after.LastWriteTimeUtc != info.LastWriteTimeUtc)
                {
                    if (after.Exists) pending[item.Key] = DateTimeOffset.UtcNow;
                    continue;
                }

                var check = reputation.Check(hash);
                if (!check.FeedImported || !check.Match)
                {
                    if (!await CommitBaselineAsync(store, info.FullName, fileFingerprint, cancellationToken)) break;
                    RememberFingerprint(fingerprint);
                    continue;
                }
                var itemEvent = new SecurityEvent(0, DateTimeOffset.UtcNow, RiskLevel.Information,
                    "Pobrany plik pasuje do lokalnej listy hashy", "Monitoring Downloads",
                    "Nowy plik z Downloads pasuje do lokalnej listy SHA-256. Źródło listy nie jest niezależnie zweryfikowane.",
                    "Sprawdź pochodzenie pliku i źródło listy. Dopasowanie nie jest automatycznym werdyktem zagrożenia.",
                    EventStatus.New, EventId: Guid.NewGuid(), Source: "downloads-local-hash",
                    RuleVersion: ThreatAnalysisEngine.RulesVersion,
                    EvidenceCodes: ["file.sha256.matches-local-list", "file.local-list-source-unverified"],
                    SignalHash: hash);
                await store.CommitDownloadedFileMonitorResultAsync(ToStoredFingerprint(info.FullName, fileFingerprint), itemEvent, cancellationToken);
                baseline[info.FullName] = fileFingerprint;
                RememberFingerprint(fingerprint);
                detections++;
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
            {
                if (File.Exists(item.Key)) pending[item.Key] = DateTimeOffset.UtcNow;
                State = "Nie można zapisać wykrycia z Downloads: historia osiągnęła limit lub brakuje miejsca; zdarzenie zostanie ponowione.";
            }
            catch (SqliteException)
            {
                if (File.Exists(item.Key)) pending[item.Key] = DateTimeOffset.UtcNow;
                Interlocked.Increment(ref rescanRequestedVersion);
                State = "Nie można zapisać stanu skanu Downloads; ponowię sprawdzenie.";
            }
            catch (IOException)
            {
                if (File.Exists(item.Key)) pending[item.Key] = DateTimeOffset.UtcNow;
            }
            catch (UnauthorizedAccessException) { }
        }
        return detections;
    }

    private bool IsInsideDownloadsTreeWithoutReparsePoints(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var relativePath = Path.GetRelativePath(directory, fullPath);
        var separator = Path.DirectorySeparatorChar;
        if (relativePath is "." or ".." || Path.IsPathRooted(relativePath) ||
            relativePath.StartsWith(".." + separator, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            return false;

        var parts = relativePath.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return false;
        var parent = directory;
        try
        {
            for (var index = 0; index < parts.Length - 1; index++)
            {
                parent = Path.Combine(parent, parts[index]);
                var attributes = File.GetAttributes(parent);
                if ((attributes & FileAttributes.Directory) == 0 || (attributes & FileAttributes.ReparsePoint) != 0)
                    return false;
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
        return true;
    }

    private bool TryEnumerateFilesWithoutFollowingReparsePoints(out string[] paths)
    {
        var files = new List<string>();
        var directories = new Stack<string>();
        var visitedDirectories = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        directories.Push(directory);
        try
        {
            while (directories.Count > 0)
            {
                var current = Path.GetFullPath(directories.Pop());
                if (!visitedDirectories.Add(current)) continue;
                if (visitedDirectories.Count > maximumBaselineFiles)
                {
                    paths = [];
                    return false;
                }

                foreach (var entryPath in Directory.EnumerateFileSystemEntries(current))
                {
                    var attributes = File.GetAttributes(entryPath);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        directories.Push(entryPath);
                        continue;
                    }

                    if (files.Count >= maximumBaselineFiles)
                    {
                        paths = [];
                        return false;
                    }
                    files.Add(Path.GetFullPath(entryPath));
                }
            }
            paths = files.ToArray();
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            paths = [];
            return false;
        }
    }

    private bool CaptureBaseline()
    {
        baseline.Clear();
        if (!TryEnumerateFilesWithoutFollowingReparsePoints(out var paths)) return false;
        foreach (var path in paths)
        {
            var info = new FileInfo(path);
            if (info.Exists && (info.Attributes & FileAttributes.ReparsePoint) == 0)
                baseline[info.FullName] = Fingerprint(info);
        }
        return true;
    }

    private async Task ReconcileIfNeededAsync(LocalStore store, CancellationToken cancellationToken)
    {
        var requestedVersion = Interlocked.Read(ref rescanRequestedVersion);
        if (requestedVersion == Interlocked.Read(ref rescanCompletedVersion)) return;
        try
        {
            if (!TryEnumerateFilesWithoutFollowingReparsePoints(out var currentPaths))
            {
                State = $"Monitoring Downloads nie może zakończyć odtwarzania: folder przekracza limit {maximumBaselineFiles} plików lub katalogów albo jest niedostępny.";
                return;
            }
            foreach (var path in currentPaths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var info = new FileInfo(path);
                if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0 || info.Length > MaximumFileBytes) continue;
                var fingerprint = Fingerprint(info);
                if (baseline.TryGetValue(info.FullName, out var previous) && previous == fingerprint) continue;
                if (processedFingerprints.ContainsKey(ToProcessedFingerprint(info.FullName, fingerprint))) continue;
                if (pending.ContainsKey(info.FullName)) continue;
                lock (pendingGate)
                {
                    if (!pending.ContainsKey(info.FullName) && pending.Count >= maximumPendingFiles) return;
                    pending[info.FullName] = DateTimeOffset.UtcNow;
                }
            }
            var currentSet = new HashSet<string>(currentPaths, OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
            await store.PruneDownloadedFileMonitorSnapshotAsync(currentPaths, maximumBaselineFiles, cancellationToken);
            foreach (var stalePath in baseline.Keys.Where(path => !currentSet.Contains(path)).ToArray()) baseline.TryRemove(stalePath, out _);
            Interlocked.Exchange(ref rescanCompletedVersion, requestedVersion);
            lastReconciledAtUtc = DateTimeOffset.UtcNow;
            State = $"Monitoring Downloads odtworzył lokalny baseline katalogu. Utracone powiadomienia: {Interlocked.Read(ref droppedPendingFiles)}.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            State = "Monitoring Downloads nie mógł dokończyć odtwarzania zmian; ponowi próbę przy następnym collect.";
        }
        catch (SqliteException)
        {
            State = "Monitoring Downloads nie mógł zapisać odtworzonego baseline'u; ponowi próbę przy następnym collect.";
        }
    }

    private static FileFingerprint Fingerprint(FileInfo info) => new(info.Length, info.LastWriteTimeUtc.Ticks);

    private async Task<bool> CommitBaselineAsync(LocalStore store, string path, FileFingerprint fingerprint, CancellationToken cancellationToken)
    {
        if (!baseline.ContainsKey(path) && baseline.Count >= maximumBaselineFiles)
        {
            StopAtBaselineLimit();
            return false;
        }
        await store.CommitDownloadedFileMonitorResultAsync(ToStoredFingerprint(path, fingerprint), ct: cancellationToken);
        baseline[path] = fingerprint;
        return true;
    }

    private void StopAtBaselineLimit()
    {
        watcher?.Dispose(); watcher = null; pending.Clear();
        State = $"Monitoring Downloads zatrzymano: osiągnięto limit {maximumBaselineFiles} ścieżek stanu; zmniejsz lub wyczyść katalog i włącz monitor ponownie.";
    }

    private static DownloadFileFingerprint ToStoredFingerprint(string path, FileFingerprint fingerprint) =>
        new(Path.GetFullPath(path), fingerprint.Length, fingerprint.LastWriteTicks);

    private static string ToProcessedFingerprint(string path, FileFingerprint fingerprint) =>
        $"{path}\0{fingerprint.Length}\0{fingerprint.LastWriteTicks}";

    private void RememberFingerprint(string fingerprint)
    {
        processedFingerprints.TryAdd(fingerprint, 0);
        if (processedFingerprints.Count <= 5000) return;
        foreach (var key in processedFingerprints.Keys.Take(500)) processedFingerprints.TryRemove(key, out _);
    }

    private void OnFileChanged(object sender, FileSystemEventArgs args)
    {
        if (Directory.Exists(args.FullPath) || (args.ChangeType == WatcherChangeTypes.Deleted && HasTrackedDescendant(args.FullPath)))
        {
            RequestRescan();
            return;
        }
        Queue(args.FullPath);
    }
    private void OnFileRenamed(object sender, RenamedEventArgs args)
    {
        if (Directory.Exists(args.FullPath) || HasTrackedDescendant(args.OldFullPath))
        {
            RequestRescan();
            return;
        }
        Queue(args.OldFullPath);
        Queue(args.FullPath);
    }

    private bool HasTrackedDescendant(string path)
    {
        var fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return baseline.Keys.Concat(pending.Keys).Any(candidate => Path.GetFullPath(candidate).StartsWith(fullPath, comparison));
    }

    private void RequestRescan() => Interlocked.Increment(ref rescanRequestedVersion);

    private void Queue(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (Directory.Exists(fullPath)) { RequestRescan(); return; }
        if (!IsInsideDownloadsTreeWithoutReparsePoints(fullPath))
        {
            var parent = Path.GetDirectoryName(fullPath);
            if (parent is not null && !Directory.Exists(parent) && IsLexicallyInsideDownloadsTree(fullPath)) RequestRescan();
            return;
        }
        lock (pendingGate)
        {
            if (!pending.ContainsKey(fullPath) && pending.Count >= maximumPendingFiles)
            {
                droppedPendingFiles++;
                Interlocked.Increment(ref rescanRequestedVersion);
                State = $"Monitoring Downloads: kolejka jest pełna; pominięto łącznie {droppedPendingFiles} zdarzeń plików.";
                return;
            }
            pending[fullPath] = DateTimeOffset.UtcNow;
        }
    }

    private bool IsLexicallyInsideDownloadsTree(string path)
    {
        var relativePath = Path.GetRelativePath(directory, Path.GetFullPath(path));
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return relativePath is not ("." or "..") && !Path.IsPathRooted(relativePath) &&
            !relativePath.StartsWith(".." + Path.DirectorySeparatorChar, comparison);
    }

    public void Dispose()
    {
        watcher?.Dispose();
        watcher = null;
        pending.Clear();
    }
}
