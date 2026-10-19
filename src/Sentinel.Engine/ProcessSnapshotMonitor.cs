using System.Diagnostics;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using Sentinel.Core.Analysis;

public sealed class ProcessSnapshotMonitor
{
    private const int MaximumProcesses = 10_000;
    private const int MaximumEventsPerSample = 100;
    private Dictionary<int, string> knownProcesses;
    private long droppedEvents;
    private readonly Func<Dictionary<int, string>> capture;

    public string State { get; private set; } = "Próbkowanie procesów nie zostało uruchomione.";

    public ProcessSnapshotMonitor() : this(Capture) { }

    public ProcessSnapshotMonitor(Func<Dictionary<int, string>> capture)
    {
        this.capture = capture ?? throw new ArgumentNullException(nameof(capture));
        knownProcesses = CaptureSnapshot();
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

        if (paused)
        {
            knownProcesses = current;
            State = "Próbkowanie procesów wstrzymane.";
            return 0;
        }

        var excluded = new HashSet<string>((excludedApplications ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.OrdinalIgnoreCase)
        { "Sentinel.Engine" };
        var changes = new List<ProcessChange>();
        foreach (var (id, name) in current)
            if ((!knownProcesses.TryGetValue(id, out var previousName) || !string.Equals(name, previousName, StringComparison.OrdinalIgnoreCase)) && !excluded.Contains(name))
                changes.Add(new("Proces zaobserwowany", id, name));
        foreach (var (id, name) in knownProcesses)
            if ((!current.TryGetValue(id, out var currentName) || !string.Equals(name, currentName, StringComparison.OrdinalIgnoreCase)) && !excluded.Contains(name))
                changes.Add(new("Proces zniknął z migawki", id, name));

        var toStore = changes.Take(MaximumEventsPerSample).ToArray();
        var newlyDroppedEvents = Math.Max(0, changes.Count - toStore.Length);
        var now = DateTimeOffset.UtcNow;
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
        try { await store.AddLocalOnlyBatchAsync(events, cancellationToken); }
        catch (SqliteException exception) when (exception.SqliteErrorCode == 13)
        {
            State = "Historia nie przyjęła zdarzeń: baza osiągnęła limit lub brakuje miejsca. Zmiany procesu pozostają do ponowienia.";
            return 0;
        }

        knownProcesses = current;
        droppedEvents += newlyDroppedEvents;
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

    private sealed record ProcessChange(string Action, int ProcessId, string ProcessName);
}
