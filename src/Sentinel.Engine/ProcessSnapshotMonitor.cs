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
    private bool storeBaselineTruncated;
    private bool knownSnapshotTruncated;
    private long droppedEvents;
    private readonly Dictionary<int, (DateTimeOffset Timestamp, Guid CorrelationId, string ProcessName)> recentlyObservedStarts = [];
    private readonly Func<Dictionary<int, string>> capture;

    public string State { get; private set; } = "Próbkowanie procesów nie zostało uruchomione.";

    public ProcessSnapshotMonitor() : this(Capture) { }

    public ProcessSnapshotMonitor(Func<Dictionary<int, string>> capture)
    {
        this.capture = capture ?? throw new ArgumentNullException(nameof(capture));
        (knownProcesses, knownSnapshotTruncated) = CaptureSnapshot();
    }

    public Guid? WasRecentlyObservedStart(int processId, DateTimeOffset timestamp)
        => WasRecentlyObservedStart(processId, null, timestamp);

    public Guid? WasRecentlyObservedStart(int processId, string? processName, DateTimeOffset timestamp)
    {
        var cutoff = timestamp.AddSeconds(-60);
        foreach (var stale in recentlyObservedStarts.Where(entry => entry.Value.Timestamp < cutoff).Select(entry => entry.Key).ToArray())
            recentlyObservedStarts.Remove(stale);
        return recentlyObservedStarts.TryGetValue(processId, out var started) && started.Timestamp <= timestamp && started.Timestamp >= cutoff &&
            !string.IsNullOrWhiteSpace(processName) && !string.Equals(processName, "unknown", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(started.ProcessName, processName, StringComparison.OrdinalIgnoreCase)
            ? started.CorrelationId : null;
    }

    public async Task<int> CollectAsync(LocalStore store, bool paused, string excludedApplications, CancellationToken cancellationToken = default)
    {
        Dictionary<int, string> current;
        bool currentTruncated;
        try { (current, currentTruncated) = CaptureSnapshot(); }
        catch (Exception exception)
        {
            State = "Snapshot procesów niedostępny: " + exception.GetType().Name;
            return 0;
        }

        if (!storeBaselineLoaded)
        {
            var saved = await store.ReadProcessMonitorSnapshotAsync(cancellationToken);
            storeBaselineInitialized = saved.Initialized;
            storeBaselineTruncated = saved.Truncated;
            if (storeBaselineInitialized)
            {
                persistedProcesses = new(saved.Processes);
                knownProcesses = new(saved.Processes);
                knownSnapshotTruncated = saved.Truncated;
            }
            storeBaselineLoaded = true;
        }

        var previousSnapshotTruncated = knownSnapshotTruncated;
        var changes = GetChanges(knownProcesses, current, excludedApplications, previousSnapshotTruncated, currentTruncated);
        var persistedCurrent = GetPersistableProcesses(current, excludedApplications);
        var (upserts, removed) = GetPersistedDelta(persistedProcesses, persistedCurrent);
        if (paused)
        {
            recentlyObservedStarts.Clear();
            try
            {
                if (!storeBaselineInitialized || storeBaselineTruncated != currentTruncated || upserts.Length > 0 || removed.Length > 0)
                    await store.CommitProcessMonitorChangesAsync([], upserts, removed, cancellationToken, currentTruncated);
            }
            catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
            {
                State = "Nie można przesunąć baseline'u procesów podczas pauzy: baza osiągnęła limit lub brakuje miejsca. Zmiana zostanie ponowiona.";
                return 0;
            }
            persistedProcesses = persistedCurrent;
            knownProcesses = current;
            knownSnapshotTruncated = currentTruncated;
            storeBaselineInitialized = true;
            storeBaselineTruncated = currentTruncated;
            State = "Próbkowanie procesów wstrzymane.";
            return 0;
        }

        var toStore = changes.Take(MaximumEventsPerSample).ToArray();
        var newlyDroppedEvents = Math.Max(0, changes.Count - toStore.Length);
        var now = DateTimeOffset.UtcNow;
        foreach (var processId in recentlyObservedStarts.Where(entry => entry.Value.Timestamp < now.AddSeconds(-60)).Select(entry => entry.Key).ToArray())
            recentlyObservedStarts.Remove(processId);
        var correlationIds = toStore.Where(change => change.Action == "Proces zaobserwowany")
            .ToDictionary(change => change.ProcessId, _ => Guid.NewGuid());
        var events = toStore.Select(change =>
        {
            var correlationId = correlationIds.TryGetValue(change.ProcessId, out var newCorrelationId)
                ? newCorrelationId : WasRecentlyObservedStart(change.ProcessId, now);
            var explanation = change.Action == "Proces zaobserwowany"
                ? $"Windows pokazał nowy PID {change.ProcessId} o nazwie {change.ProcessName} od poprzedniej próbki. Krótkie procesy mogą zostać pominięte."
                : $"PID {change.ProcessId} ({change.ProcessName}) nie występuje już w migawce procesów.";
            return new SecurityEvent(0, now, RiskLevel.Information,
                change.Action, change.ProcessName, explanation,
                "To obserwacja metadanych, nie werdykt zagrożenia. Zweryfikuj pochodzenie procesu.", EventStatus.New,
                Source: "process-snapshot", RuleVersion: ThreatAnalysisEngine.RulesVersion,
                ProcessId: change.ProcessId, ProcessName: change.ProcessName,
                CorrelationId: correlationId,
                EvidenceCodes: [change.Action == "Proces zaobserwowany" ? "process.snapshot.new-pid" : "process.snapshot.pid-absent"]);
        }).ToArray();
        try
        {
            if (!storeBaselineInitialized || storeBaselineTruncated != currentTruncated || events.Length > 0 || upserts.Length > 0 || removed.Length > 0)
                await store.CommitProcessMonitorChangesAsync(events, upserts, removed, cancellationToken, currentTruncated);
        }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
        {
            State = "Historia nie przyjęła zdarzeń: baza osiągnęła limit lub brakuje miejsca. Zmiany procesu pozostają do ponowienia.";
            return 0;
        }

        knownProcesses = current;
        persistedProcesses = persistedCurrent;
        knownSnapshotTruncated = currentTruncated;
        storeBaselineInitialized = true;
        storeBaselineTruncated = currentTruncated;
        droppedEvents += newlyDroppedEvents;
        foreach (var change in toStore.Where(change => change.Action == "Proces zaobserwowany"))
            recentlyObservedStarts[change.ProcessId] = (now, correlationIds[change.ProcessId], change.ProcessName);
        var capped = currentTruncated ? " Limit snapshotu osiągnięty; zdarzenia zakończenia pominięto dla niepełnej próbki." :
            previousSnapshotTruncated ? " Poprzednia próbka była obcięta; zdarzenia nowych procesów pominięto w tym kroku." : "";
        State = $"Snapshot procesów działa; {current.Count} PID, {toStore.Length} zmian, pominięto łącznie {droppedEvents}.{capped}";
        return toStore.Length;
    }

    private static Dictionary<int, string> Capture()
    {
        var processes = Process.GetProcesses();
        try
        {
            var snapshot = new Dictionary<int, string>(Math.Min(processes.Length, MaximumProcesses));
            foreach (var process in processes.OrderBy(process => process.Id).Take(MaximumProcesses + 1))
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

    private (Dictionary<int, string> Processes, bool Truncated) CaptureSnapshot()
    {
        var captured = capture();
        var truncated = captured.Count > MaximumProcesses;
        var processes = captured.OrderBy(entry => entry.Key).Take(MaximumProcesses)
            .ToDictionary(entry => entry.Key, entry => string.IsNullOrWhiteSpace(entry.Value) ? "unknown" : entry.Value[..Math.Min(entry.Value.Length, 260)]);
        return (processes, truncated);
    }

    private List<ProcessChange> GetChanges(IReadOnlyDictionary<int, string> previous, IReadOnlyDictionary<int, string> current,
        string excludedApplications, bool previousTruncated, bool currentTruncated)
    {
        var excluded = new HashSet<string>((excludedApplications ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.OrdinalIgnoreCase)
        { "Sentinel.Engine" };
        var changes = new List<ProcessChange>();
        foreach (var (id, name) in current)
            if (!previousTruncated && (!previous.TryGetValue(id, out var previousName) || !string.Equals(name, previousName, StringComparison.OrdinalIgnoreCase)) && !excluded.Contains(name))
                changes.Add(new("Proces zaobserwowany", id, name));
        foreach (var (id, name) in previous)
            if (!currentTruncated && (!current.TryGetValue(id, out var currentName) || !string.Equals(name, currentName, StringComparison.OrdinalIgnoreCase)) && !excluded.Contains(name))
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
