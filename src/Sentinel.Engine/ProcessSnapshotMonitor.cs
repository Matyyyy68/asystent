using System.Diagnostics;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using Sentinel.Core.Analysis;

public sealed class ProcessSnapshotMonitor
{
    private const int MaximumProcesses = 10_000;
    private const int MaximumEventsPerSample = 100;
    private Dictionary<int, string> knownProcesses;
    private Dictionary<int, string> persistedProcesses = [];
    private bool storeBaselineLoaded;
    private bool storeBaselineInitialized;
    private long droppedEvents;
    private readonly Dictionary<int, DateTimeOffset> recentlyObservedStarts = [];
    private readonly Func<Dictionary<int, string>> capture;

    public string State { get; private set; } = "Próbkowanie procesów nie zostało uruchomione.";

    public ProcessSnapshotMonitor() : this(Capture) { }

    public ProcessSnapshotMonitor(Func<Dictionary<int, string>> capture)
    {
        this.capture = capture ?? throw new ArgumentNullException(nameof(capture));
        knownProcesses = CaptureSnapshot();
    }

    public bool WasRecentlyObservedStart(int processId, DateTimeOffset timestamp)
    {
        var cutoff = timestamp.AddSeconds(-60);
        foreach (var stale in recentlyObservedStarts.Where(entry => entry.Value < cutoff).Select(entry => entry.Key).ToArray())
            recentlyObservedStarts.Remove(stale);
        return recentlyObservedStarts.TryGetValue(processId, out var startedAt) && startedAt <= timestamp && startedAt >= cutoff;
    }

    public async Task<int> CollectAsync(LocalStore store, bool paused, string excludedApplications, CancellationToken cancellationToken = default)
    {
        Dictionary<int, string> current;
        try { current = CaptureSnapshot(); }
        catch (Exception exception)
        {
            State = "Snapshot procesów niedostępny: " + exception.GetType().Name;
            return 0;
        }

        if (!storeBaselineLoaded)
        {
            var saved = await store.ReadProcessMonitorSnapshotAsync(cancellationToken);
            storeBaselineInitialized = saved.Initialized;
            if (storeBaselineInitialized)
            {
                persistedProcesses = new(saved.Processes);
                knownProcesses = new(saved.Processes);
            }
            storeBaselineLoaded = true;
        }

        var changes = GetChanges(knownProcesses, current, excludedApplications);
        var persistedCurrent = GetPersistableProcesses(current, excludedApplications);
        var (upserts, removed) = GetPersistedDelta(persistedProcesses, persistedCurrent);
        if (paused)
        {
            try
            {
                if (!storeBaselineInitialized || upserts.Length > 0 || removed.Length > 0)
                    await store.CommitProcessMonitorChangesAsync([], upserts, removed, cancellationToken);
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
            {
                State = "Nie można przesunąć baseline'u procesów podczas pauzy: baza osiągnęła limit lub brakuje miejsca. Zmiana zostanie ponowiona.";
                return 0;
            }
            persistedProcesses = persistedCurrent;
            knownProcesses = current;
            storeBaselineInitialized = true;
            State = "Próbkowanie procesów wstrzymane.";
            return 0;
        }

        var toStore = changes.Take(MaximumEventsPerSample).ToArray();
        var newlyDroppedEvents = Math.Max(0, changes.Count - toStore.Length);
        var now = DateTimeOffset.UtcNow;
        foreach (var processId in recentlyObservedStarts.Where(entry => entry.Value < now.AddSeconds(-60)).Select(entry => entry.Key).ToArray())
            recentlyObservedStarts.Remove(processId);
        var events = toStore.Select(change =>
        {
            var explanation = change.Action == "Proces zaobserwowany"
                ? $"Windows pokazał nowy PID {change.ProcessId} o nazwie {change.ProcessName} od poprzedniej próbki. Krótkie procesy mogą zostać pominięte."
                : $"PID {change.ProcessId} ({change.ProcessName}) nie występuje już w migawce procesów.";
            return new SecurityEvent(0, now, RiskLevel.Information,
                change.Action, change.ProcessName, explanation,
                "To obserwacja metadanych, nie werdykt zagrożenia. Zweryfikuj pochodzenie procesu.", EventStatus.New,
                Source: "process-snapshot", RuleVersion: ThreatAnalysisEngine.RulesVersion,
                ProcessId: change.ProcessId, ProcessName: change.ProcessName);
        }).ToArray();
        try
        {
            if (!storeBaselineInitialized || events.Length > 0 || upserts.Length > 0 || removed.Length > 0)
                await store.CommitProcessMonitorChangesAsync(events, upserts, removed, cancellationToken);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
        {
            State = "Historia nie przyjęła zdarzeń: baza osiągnęła limit lub brakuje miejsca. Zmiany procesu pozostają do ponowienia.";
            return 0;
        }

        knownProcesses = current;
        persistedProcesses = persistedCurrent;
        storeBaselineInitialized = true;
        droppedEvents += newlyDroppedEvents;
        foreach (var change in toStore.Where(change => change.Action == "Proces zaobserwowany"))
            recentlyObservedStarts[change.ProcessId] = now;
        var capped = current.Count >= MaximumProcesses ? " Limit snapshotu osiągnięty." : "";
        State = $"Snapshot procesów działa; {current.Count} PID, {toStore.Length} zmian, pominięto łącznie {droppedEvents}.{capped}";
        return toStore.Length;
    }

    private static Dictionary<int, string> Capture()
    {
        var processes = Process.GetProcesses();
        try
        {
            var snapshot = new Dictionary<int, string>(Math.Min(processes.Length, MaximumProcesses));
            foreach (var process in processes.Take(MaximumProcesses))
            {
                string name;
                try { name = process.ProcessName; }
                catch { name = "unknown"; }
                snapshot[process.Id] = string.IsNullOrWhiteSpace(name) ? "unknown" : name[..Math.Min(name.Length, 260)];
            }
            return snapshot;
        }
        finally { foreach (var process in processes) process.Dispose(); }
    }

    private Dictionary<int, string> CaptureSnapshot() => capture().Take(MaximumProcesses)
        .ToDictionary(entry => entry.Key, entry => string.IsNullOrWhiteSpace(entry.Value) ? "unknown" : entry.Value[..Math.Min(entry.Value.Length, 260)]);

    private List<ProcessChange> GetChanges(IReadOnlyDictionary<int, string> previous, IReadOnlyDictionary<int, string> current, string excludedApplications)
    {
        var excluded = new HashSet<string>((excludedApplications ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.OrdinalIgnoreCase)
        { "Sentinel.Engine" };
        var changes = new List<ProcessChange>();
        foreach (var (id, name) in current)
            if ((!previous.TryGetValue(id, out var previousName) || !string.Equals(name, previousName, StringComparison.OrdinalIgnoreCase)) && !excluded.Contains(name))
                changes.Add(new("Proces zaobserwowany", id, name));
        foreach (var (id, name) in previous)
            if ((!current.TryGetValue(id, out var currentName) || !string.Equals(name, currentName, StringComparison.OrdinalIgnoreCase)) && !excluded.Contains(name))
                changes.Add(new("Proces zniknął z migawki", id, name));
        return changes;
    }

    private static Dictionary<int, string> GetPersistableProcesses(IReadOnlyDictionary<int, string> current, string excludedApplications)
    {
        var excluded = new HashSet<string>((excludedApplications ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.OrdinalIgnoreCase)
        { "Sentinel.Engine" };
        return current.Where(entry => !excluded.Contains(entry.Value)).ToDictionary(entry => entry.Key, entry => entry.Value);
    }

    private static (KeyValuePair<int, string>[] Upserts, int[] Removed) GetPersistedDelta(
        IReadOnlyDictionary<int, string> previous, IReadOnlyDictionary<int, string> current)
    {
        var upserts = current.Where(entry => !previous.TryGetValue(entry.Key, out var name) ||
                !string.Equals(name, entry.Value, StringComparison.OrdinalIgnoreCase))
            .Select(entry => new KeyValuePair<int, string>(entry.Key, entry.Value)).ToArray();
        var removed = previous.Where(entry => !current.TryGetValue(entry.Key, out var name) ||
                !string.Equals(name, entry.Value, StringComparison.OrdinalIgnoreCase))
            .Select(entry => entry.Key).ToArray();
        return (upserts, removed);
    }

    private sealed record ProcessChange(string Action, int ProcessId, string ProcessName);
}
