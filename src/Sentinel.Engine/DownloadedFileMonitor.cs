using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using Sentinel.Core.Analysis;

/// <summary>Opt-in, local-only watcher for new files directly in the user's Downloads folder.</summary>
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
    private readonly ConcurrentDictionary<string, DateTimeOffset> pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> processedFingerprints = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, FileFingerprint> baseline = new(StringComparer.OrdinalIgnoreCase);
    private readonly object pendingGate = new();
    private long droppedPendingFiles;
    private long rescanRequestedVersion;
    private long rescanCompletedVersion;
    private FileSystemWatcher? watcher;

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

    public DownloadedFileMonitor(string directory, int maximumPendingFiles = 1000, int maximumBaselineFiles = DefaultMaximumBaselineFiles)
    {
        if (maximumPendingFiles < 1) throw new ArgumentOutOfRangeException(nameof(maximumPendingFiles));
        if (maximumBaselineFiles < 1) throw new ArgumentOutOfRangeException(nameof(maximumBaselineFiles));
        this.directory = Path.GetFullPath(directory);
        this.maximumPendingFiles = maximumPendingFiles;
        this.maximumBaselineFiles = maximumBaselineFiles;
    }

    public async Task SetEnabledAsync(LocalStore store, bool enabled, CancellationToken cancellationToken = default)
    {
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
                IncludeSubdirectories = false,
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
                Interlocked.Increment(ref rescanRequestedVersion);
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
                if (!CaptureCurrentPaths(out var currentPaths))
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
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or SqliteException or InvalidDataException)
        {
            next?.Dispose();
            State = "Monitoring pobranych plików niedostępny: " + exception.GetType().Name;
        }
    }

    public async Task<int> CollectAsync(LocalStore store, FileHashReputation reputation, CancellationToken cancellationToken = default)
    {
        if (watcher is null) return 0;
        if (reputation.Status().HashCount == 0)
        {
            State = $"Monitoring Downloads działa; zaimportuj lokalną listę hashy, aby sprawdzać pliki. Utracone powiadomienia kolejki: {Interlocked.Read(ref droppedPendingFiles)}.";
            return 0;
        }
        ReconcileIfNeeded(cancellationToken);
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
                if (!IsDirectChild(info.FullName)) continue;
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
                    "Pobrany plik pasuje do lokalnej listy hashy", info.Name,
                    $"Nowy plik w Downloads ma SHA-256 {hash}, który znajduje się na lokalnej liście użytkownika. Źródło listy nie jest niezależnie zweryfikowane.",
                    "Sprawdź pochodzenie pliku i źródło listy. Dopasowanie nie jest automatycznym werdyktem zagrożenia.",
                    EventStatus.New, EventId: Guid.NewGuid(), Source: "downloads-local-hash",
                    RuleVersion: ThreatAnalysisEngine.RulesVersion);
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

    private bool IsDirectChild(string path) => string.Equals(Path.GetDirectoryName(path), directory,
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private bool CaptureBaseline()
    {
        baseline.Clear();
        try
        {
            foreach (var path in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
            {
                var info = new FileInfo(path);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (baseline.Count >= maximumBaselineFiles) return false;
                baseline[info.FullName] = Fingerprint(info);
            }
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private bool CaptureCurrentPaths(out string[] paths)
    {
        var collected = new List<string>();
        try
        {
            foreach (var path in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
            {
                var info = new FileInfo(path);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (collected.Count >= maximumBaselineFiles) { paths = []; return false; }
                collected.Add(info.FullName);
            }
            paths = collected.ToArray(); return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        { paths = []; return false; }
    }

    private void ReconcileIfNeeded(CancellationToken cancellationToken)
    {
        var requestedVersion = Interlocked.Read(ref rescanRequestedVersion);
        if (requestedVersion == Interlocked.Read(ref rescanCompletedVersion)) return;
        try
        {
            var scannedFiles = 0;
            foreach (var path in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++scannedFiles > maximumBaselineFiles)
                {
                    State = $"Monitoring Downloads nie może zakończyć odtwarzania: folder przekracza limit {maximumBaselineFiles} plików.";
                    return;
                }
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
            Interlocked.Exchange(ref rescanCompletedVersion, requestedVersion);
            State = $"Monitoring Downloads działa; ponowne sprawdzenie katalogu odtworzyło zmiany po przepełnieniu kolejki. Utracone powiadomienia: {Interlocked.Read(ref droppedPendingFiles)}.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            State = "Monitoring Downloads nie mógł dokończyć odtwarzania zmian; ponowi próbę przy następnym collect.";
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

    private void OnFileChanged(object sender, FileSystemEventArgs args) => Queue(args.FullPath);
    private void OnFileRenamed(object sender, RenamedEventArgs args)
    {
        Queue(args.OldFullPath);
        Queue(args.FullPath);
    }

    private void Queue(string path)
    {
        if (Directory.Exists(path)) return;
        var fullPath = Path.GetFullPath(path);
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

    public void Dispose()
    {
        watcher?.Dispose();
        watcher = null;
        pending.Clear();
    }
}
