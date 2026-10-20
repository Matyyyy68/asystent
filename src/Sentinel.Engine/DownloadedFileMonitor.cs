using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using Sentinel.Core.Analysis;

/// <summary>Opt-in, local-only watcher for new files directly in the user's Downloads folder.</summary>
public sealed class DownloadedFileMonitor : IDisposable
{
    private const int MaximumPendingFiles = 1000;
    private const int MaximumFilesPerSample = 10;
    private const long MaximumFileBytes = 256L * 1024 * 1024;
    private const long MaximumBytesPerSample = 512L * 1024 * 1024;
    private static readonly TimeSpan SettleTime = TimeSpan.FromMilliseconds(750);
    private readonly string directory;
    private readonly ConcurrentDictionary<string, DateTimeOffset> pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> processedFingerprints = new(StringComparer.OrdinalIgnoreCase);
    private FileSystemWatcher? watcher;

    public string State { get; private set; } = "Monitoring pobranych plików wyłączony.";

    public DownloadedFileMonitor(string directory) => this.directory = Path.GetFullPath(directory);

    public void SetEnabled(bool enabled)
    {
        if (!enabled)
        {
            watcher?.Dispose();
            watcher = null;
            pending.Clear();
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
            next.Renamed += OnFileRenamed;
            next.Error += (_, _) => State = "Monitoring pobranych plików utracił część zdarzeń systemu plików; nowe zdarzenia będą nadal obserwowane.";
            next.EnableRaisingEvents = true;
            watcher = next;
            State = "Monitoring Downloads działa; pliki są sprawdzane lokalnie względem listy hashy.";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
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
            pending.Clear();
            State = "Monitoring Downloads działa; zaimportuj lokalną listę hashy, aby sprawdzać pliki.";
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
                if (!info.Exists || !IsDirectChild(info.FullName)) continue;
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (info.Length > MaximumFileBytes) continue;
                if (info.Length > MaximumBytesPerSample - bytesScanned)
                {
                    pending[item.Key] = DateTimeOffset.UtcNow;
                    break;
                }
                var fingerprint = $"{info.FullName}\0{info.Length}\0{info.LastWriteTimeUtc.Ticks}";
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
                    RememberFingerprint(fingerprint);
                    continue;
                }
                var itemEvent = new SecurityEvent(0, DateTimeOffset.UtcNow, RiskLevel.Information,
                    "Pobrany plik pasuje do lokalnej listy hashy", info.Name,
                    $"Nowy plik w Downloads ma SHA-256 {hash}, który znajduje się na lokalnej liście użytkownika. Źródło listy nie jest niezależnie zweryfikowane.",
                    "Sprawdź pochodzenie pliku i źródło listy. Dopasowanie nie jest automatycznym werdyktem zagrożenia.",
                    EventStatus.New, EventId: Guid.NewGuid(), Source: "downloads-local-hash",
                    RuleVersion: ThreatAnalysisEngine.RulesVersion);
                await store.AddLocalOnlyAsync(itemEvent, cancellationToken);
                RememberFingerprint(fingerprint);
                detections++;
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
            {
                if (File.Exists(item.Key)) pending[item.Key] = DateTimeOffset.UtcNow;
                State = "Nie można zapisać wykrycia z Downloads: historia osiągnęła limit lub brakuje miejsca; zdarzenie zostanie ponowione.";
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

    private void RememberFingerprint(string fingerprint)
    {
        processedFingerprints.TryAdd(fingerprint, 0);
        if (processedFingerprints.Count <= 5000) return;
        foreach (var key in processedFingerprints.Keys.Take(500)) processedFingerprints.TryRemove(key, out _);
    }

    private void OnFileChanged(object sender, FileSystemEventArgs args) => Queue(args.FullPath);
    private void OnFileRenamed(object sender, RenamedEventArgs args) => Queue(args.FullPath);

    private void Queue(string path)
    {
        if (Directory.Exists(path)) return;
        pending[Path.GetFullPath(path)] = DateTimeOffset.UtcNow;
        if (pending.Count > MaximumPendingFiles)
            foreach (var key in pending.Keys.Take(pending.Count - MaximumPendingFiles)) pending.TryRemove(key, out _);
    }

    public void Dispose()
    {
        watcher?.Dispose();
        watcher = null;
        pending.Clear();
    }
}
