using System.Diagnostics;
using Microsoft.Data.Sqlite;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Engine;

public sealed class ProcessSnapshotMonitor
{
    private const int MaximumProcesses = 10_000;
    private const int MaximumEventsPerSample = 100;
    private const int MaximumPendingChanges = 20_000;
    private Dictionary<int, string> knownProcesses;
    private Dictionary<int, string> persistedProcesses = [];
    private bool storeBaselineLoaded;
    private bool storeBaselineInitialized;
    private bool storeBaselineTruncated;
    private bool knownSnapshotTruncated;
    private bool initialSnapshotCaptured;
    private long droppedEvents;
    private bool recentStartsLoaded;
    private readonly Dictionary<int, (DateTimeOffset Timestamp, Guid CorrelationId, string ProcessName)> recentlyObservedStarts = [];
    private readonly Func<Dictionary<int, string>> capture;
    private readonly Func<int, string, string?>? resolveExecutablePath;
    private readonly Func<Guid, string, bool>? enqueueImageInspection;
    private readonly Func<IReadOnlyCollection<(int ProcessId, string ProcessName)>, IReadOnlyDictionary<int, ProcessParentObservation>>? readParentProcesses;
    public int LastSuspiciousLaunchMatches { get; private set; }

    public string State { get; private set; } = "Próbkowanie procesów nie zostało uruchomione.";

    public ProcessSnapshotMonitor() : this(Capture, null, null, WindowsProcessParentReader.ReadMany) { }

    public ProcessSnapshotMonitor(Func<int, string, string?> resolveExecutablePath,
        Func<Guid, string, bool> enqueueImageInspection) : this(Capture, resolveExecutablePath, enqueueImageInspection, WindowsProcessParentReader.ReadMany) { }

    public ProcessSnapshotMonitor(Func<Dictionary<int, string>> capture) : this(capture, null, null, null) { }

    public ProcessSnapshotMonitor(Func<Dictionary<int, string>> capture,
        Func<int, string, string?>? resolveExecutablePath, Func<Guid, string, bool>? enqueueImageInspection)
        : this(capture, resolveExecutablePath, enqueueImageInspection, null) { }

    public ProcessSnapshotMonitor(Func<Dictionary<int, string>> capture,
        Func<int, string, string?>? resolveExecutablePath, Func<Guid, string, bool>? enqueueImageInspection,
        Func<IReadOnlyCollection<(int ProcessId, string ProcessName)>, IReadOnlyDictionary<int, ProcessParentObservation>>? readParentProcesses)
    {
        this.capture = capture ?? throw new ArgumentNullException(nameof(capture));
        this.resolveExecutablePath = resolveExecutablePath;
        this.enqueueImageInspection = enqueueImageInspection;
        this.readParentProcesses = readParentProcesses;
        try
        {
            (knownProcesses, knownSnapshotTruncated) = CaptureSnapshot();
            initialSnapshotCaptured = true;
        }
        catch (Exception exception)
        {
            // A transient source failure must not prevent the Engine from starting.
            knownProcesses = [];
            knownSnapshotTruncated = false;
            State = "Snapshot procesów niedostępny: " + exception.GetType().Name;
        }
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

    public async Task<int> CollectAsync(LocalStore store, bool paused, string excludedApplications,
        CancellationToken cancellationToken = default, IReadOnlyCollection<WindowsProcessTraceEvent>? traceEvents = null)
    {
        LastSuspiciousLaunchMatches = 0;
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
            droppedEvents = saved.DroppedChanges;
            if (storeBaselineInitialized)
            {
                persistedProcesses = new(saved.Processes);
                knownProcesses = new(saved.Processes);
                knownSnapshotTruncated = saved.Truncated;
            }
            else if (!initialSnapshotCaptured)
            {
                // With no persisted baseline, the first available sample establishes the
                // baseline instead of reporting every already-running process as new.
                knownProcesses = current;
                knownSnapshotTruncated = currentTruncated;
            }
            storeBaselineLoaded = true;
        }

        var pendingChanges = await store.ReadPendingProcessChangesAsync(MaximumPendingChanges, cancellationToken);
        if (!recentStartsLoaded)
        {
            if (!paused)
            {
                foreach (var start in await store.ReadRecentProcessStartsAsync(DateTimeOffset.UtcNow, cancellationToken))
                    if (!recentlyObservedStarts.TryGetValue(start.ProcessId, out var existing) || existing.Timestamp < start.Timestamp)
                        recentlyObservedStarts[start.ProcessId] = (start.Timestamp, start.CorrelationId, start.ProcessName);
                foreach (var start in pendingChanges.Items.Where(item => item.Action == "Proces zaobserwowany" && item.CorrelationId.HasValue))
                    if (!recentlyObservedStarts.TryGetValue(start.ProcessId, out var existing) || existing.Timestamp < start.ObservedAt)
                        recentlyObservedStarts[start.ProcessId] = (start.ObservedAt, start.CorrelationId!.Value, start.ProcessName);
            }
            recentStartsLoaded = true;
        }

        var previousSnapshotTruncated = knownSnapshotTruncated;
        var changes = GetChanges(knownProcesses, current, excludedApplications, previousSnapshotTruncated, currentTruncated);
        var wmiStarts = new HashSet<(int ProcessId, string ProcessName)>();
        var wmiParentProcessIds = new Dictionary<(int ProcessId, string ProcessName), int>();
        if (traceEvents is { Count: > 0 } && !paused)
        {
            var excluded = new HashSet<string>((excludedApplications ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), StringComparer.OrdinalIgnoreCase)
            { "Sentinel.Engine" };
            static bool IsStart(string action) => action == "Proces zaobserwowany";
            var observed = changes.Select(change => (IsStart(change.Action), change.ProcessId, change.ProcessName)).ToHashSet();
            foreach (var trace in traceEvents.OrderBy(item => item.ObservedAt))
            {
                if (excluded.Contains(trace.ProcessName) || trace.ProcessId <= 0) continue;
                var key = (IsStart(trace.Action), trace.ProcessId, trace.ProcessName);
                if (observed.Add(key)) changes.Add(new(trace.Action, trace.ProcessId, trace.ProcessName, trace.ObservedAt));
                if (trace.Action == "Proces zaobserwowany")
                {
                    var processKey = (trace.ProcessId, trace.ProcessName);
                    wmiStarts.Add(processKey);
                    if (trace.ParentProcessId > 0) wmiParentProcessIds[processKey] = trace.ParentProcessId;
                }
            }
        }
        var persistedCurrent = GetPersistableProcesses(current, excludedApplications ?? "");
        var (upserts, removed) = GetPersistedDelta(persistedProcesses, persistedCurrent);
        if (paused)
        {
            recentlyObservedStarts.Clear();
            try
            {
                if (!storeBaselineInitialized || storeBaselineTruncated != currentTruncated || upserts.Length > 0 || removed.Length > 0 || pendingChanges.Count > 0)
                    await store.CommitProcessMonitorChangesAsync([], upserts, removed, cancellationToken, currentTruncated,
                        clearBacklog: true);
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
            State = "Zdarzenia procesów wstrzymane; lokalny baseline PID/nazw jest nadal aktualizowany.";
            return 0;
        }

        var now = DateTimeOffset.UtcNow;
        foreach (var processId in recentlyObservedStarts.Where(entry => entry.Value.Timestamp < now.AddSeconds(-60)).Select(entry => entry.Key).ToArray())
            recentlyObservedStarts.Remove(processId);
        var discovered = changes.Select(change => new ProcessChangeQueueItem(0, Guid.NewGuid(), change.ObservedAt,
            change.Action,
            change.ProcessId, change.ProcessName,
            change.Action == "Proces zaobserwowany" ? Guid.NewGuid() : WasRecentlyObservedStart(change.ProcessId, change.ProcessName, now))).ToArray();
        var changesDrainedThisSample = Math.Min(Math.Min(pendingChanges.Count, pendingChanges.Items.Count), MaximumEventsPerSample);
        var available = Math.Max(0, MaximumPendingChanges - Math.Max(0, pendingChanges.Count - changesDrainedThisSample));
        var backlogToAdd = discovered.Take(available).ToArray();
        var newlyDroppedEvents = Math.Max(0, discovered.Length - backlogToAdd.Length);
        var toStore = pendingChanges.Items.Concat(backlogToAdd).Take(MaximumEventsPerSample).ToArray();
        // Apply lifecycle changes in observation order. Keeping a stopped PID in
        // this cache can attach a later TCP snapshot to an unrelated process if
        // Windows quickly reuses the PID (especially when the image name matches).
        foreach (var change in toStore.OrderBy(item => item.ObservedAt).ThenBy(item => item.QueueId))
        {
            if (change.Action == "Proces zaobserwowany" && change.CorrelationId is { } correlationId)
            {
                if (!recentlyObservedStarts.TryGetValue(change.ProcessId, out var existing) || existing.Timestamp <= change.ObservedAt)
                    recentlyObservedStarts[change.ProcessId] = (change.ObservedAt, correlationId, change.ProcessName);
            }
            else if ((change.Action is "Proces zakończony" or "Proces zniknął z migawki") &&
                recentlyObservedStarts.TryGetValue(change.ProcessId, out var stoppedProcess) &&
                stoppedProcess.Timestamp <= change.ObservedAt)
            {
                recentlyObservedStarts.Remove(change.ProcessId);
            }
        }
        var backlogToRemove = toStore.Select(item => item.EventId).ToArray();
        var imageInspections = new List<(Guid EventId, string Path)>();
        var liveStarts = toStore.Where(change => change.Action == "Proces zaobserwowany" && change.QueueId == 0 &&
                current.TryGetValue(change.ProcessId, out var name) && string.Equals(name, change.ProcessName, StringComparison.OrdinalIgnoreCase))
            .Select(change => (change.ProcessId, change.ProcessName)).Distinct().ToArray();
        IReadOnlyDictionary<int, ProcessParentObservation> parentObservations = new Dictionary<int, ProcessParentObservation>();
        var parentSnapshotFailed = false;
        if (readParentProcesses is not null && liveStarts.Length > 0)
        {
            try { parentObservations = readParentProcesses(liveStarts); }
            catch { parentSnapshotFailed = true; }
        }
        var events = toStore.Select(change =>
        {
            var eventId = change.EventId;
            string? imagePath = null;
            ProcessParentObservation? parent = null;
            ProcessLaunchBehavior? behavior = null;
            if (change.Action == "Proces zaobserwowany" && change.QueueId == 0 && resolveExecutablePath is not null &&
                current.TryGetValue(change.ProcessId, out var currentName) && string.Equals(currentName, change.ProcessName, StringComparison.OrdinalIgnoreCase))
            {
                try { imagePath = resolveExecutablePath(change.ProcessId, change.ProcessName); }
                catch { imagePath = null; }
                if (imagePath is { } candidate && (candidate.Length is 0 or > 4096 || !Path.IsPathFullyQualified(candidate) || candidate.StartsWith(@"\\", StringComparison.Ordinal) || candidate.Any(char.IsControl)))
                    imagePath = null;
                if (imagePath is not null && enqueueImageInspection is not null) imageInspections.Add((eventId, imagePath));
            }
            if (change.Action == "Proces zaobserwowany" && change.QueueId == 0 &&
                parentObservations.TryGetValue(change.ProcessId, out var observedParent) &&
                current.TryGetValue(change.ProcessId, out var observedName) && string.Equals(observedName, change.ProcessName, StringComparison.OrdinalIgnoreCase))
            {
                parent = observedParent;
                behavior = ProcessLaunchBehaviorRules.Evaluate(parent.ProcessName, change.ProcessName);
            }
            else if (change.Action == "Proces zaobserwowany" &&
                wmiStarts.Contains((change.ProcessId, change.ProcessName)) &&
                wmiParentProcessIds.TryGetValue((change.ProcessId, change.ProcessName), out var traceParentId) &&
                traceParentId > 0 && traceParentId != change.ProcessId &&
                current.TryGetValue(traceParentId, out var traceParentName) &&
                !string.Equals(traceParentName, "unknown", StringComparison.OrdinalIgnoreCase))
            {
                // WMI's ParentProcessId remains useful when the child has already exited
                // and cannot be related through a live Toolhelp child snapshot.
                parent = new(traceParentId, traceParentName);
                behavior = ProcessLaunchBehaviorRules.Evaluate(parent.ProcessName, change.ProcessName);
            }
            if (behavior is not null) LastSuspiciousLaunchMatches++;
            var observedFromWmi = change.Action == "Proces zaobserwowany" && wmiStarts.Contains((change.ProcessId, change.ProcessName));
            var wmiParentProcessId = 0;
            var hasWmiParentId = observedFromWmi && wmiParentProcessIds.TryGetValue((change.ProcessId, change.ProcessName), out wmiParentProcessId);
            var delayed = now - change.ObservedAt > TimeSpan.FromSeconds(2);
            var explanation = change.Action == "Proces zaobserwowany"
                ? behavior is not null && parent is not null
                    ? $"{behavior.Summary} Relacja zaobserwowana: {parent.ProcessName} (PID {parent.ProcessId}) → {change.ProcessName} (PID {change.ProcessId}). Taka relacja może mieć legalne przyczyny; krótkie procesy i część rodziców mogą zostać pominięte."
                    : delayed
                    ? $"Windows zaobserwował nowy PID {change.ProcessId} ({change.ProcessName}) wcześniej; zapis zdarzenia opóźniło oczekiwanie w kolejce. Krótkie procesy mogą zostać pominięte."
                    : $"Windows pokazał nowy PID {change.ProcessId} o nazwie {change.ProcessName} od poprzedniej próbki. Krótkie procesy mogą zostać pominięte."
                : delayed
                    ? $"Windows zaobserwował zniknięcie PID {change.ProcessId} ({change.ProcessName}) wcześniej; zapis zdarzenia opóźniło oczekiwanie w kolejce."
                    : $"PID {change.ProcessId} ({change.ProcessName}) nie występuje już w migawce procesów.";
            if (hasWmiParentId && parent is null)
                explanation += $" Zdarzenie WMI podaje Parent PID {wmiParentProcessId}; Sentinel nie ustalił nazwy rodzica.";
            var evidenceCodes = new List<string> { change.Action == "Proces zaobserwowany"
                ? observedFromWmi ? "process.wmi.start-event" : "process.snapshot.new-pid"
                : change.Action == "Proces zakończony" ? "process.wmi.stop-event" : "process.snapshot.pid-absent" };
            if (change.Action == "Proces zaobserwowany") evidenceCodes.Add(imagePath is null ? "process.image.path-unavailable" : "process.image.path-available");
            if (parent is not null) evidenceCodes.Add("process.parent-child.relationship-observed");
            else if (hasWmiParentId) evidenceCodes.Add("process.parent-pid.wmi-observed");
            if (behavior is not null) evidenceCodes.Add(behavior.RuleCode);
            return new SecurityEvent(0, change.ObservedAt, behavior is not null ? RiskLevel.Moderate : RiskLevel.Information,
                behavior is not null ? "Nietypowe uruchomienie procesu" : change.Action, change.ProcessName, explanation,
                behavior is not null
                    ? "Sprawdź, czy użytkownik oczekiwał uruchomienia interpretera przez aplikację Office. Sentinel AI nie zablokował ani nie zatrzymał procesu."
                    : "To obserwacja metadanych, nie werdykt zagrożenia. Zweryfikuj pochodzenie procesu.", EventStatus.New,
                EventId: eventId,
                Source: observedFromWmi || change.Action == "Proces zakończony" ? "process-wmi" : "process-snapshot",
                RuleVersion: ThreatAnalysisEngine.RulesVersion,
                ProcessId: change.ProcessId, ProcessName: change.ProcessName,
                CorrelationId: change.CorrelationId,
                EvidenceCodes: evidenceCodes,
                ProcessImagePath: imagePath,
                ProcessImageSignatureStatus: imagePath is not null ? "Pending" : null,
                RiskScore: RiskEngine.EvaluateEvidenceCodes(evidenceCodes).Score);
        }).ToArray();
        try
        {
            if (!storeBaselineInitialized || storeBaselineTruncated != currentTruncated || events.Length > 0 || upserts.Length > 0 || removed.Length > 0 || backlogToAdd.Length > 0)
                await store.CommitProcessMonitorChangesAsync(events, upserts, removed, cancellationToken, currentTruncated,
                    backlogToAdd, backlogToRemove, droppedChanges: newlyDroppedEvents);
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
        foreach (var inspection in imageInspections)
        {
            if (enqueueImageInspection!(inspection.EventId, inspection.Path)) continue;
            try { await store.UpdateProcessImageInspectionAsync(inspection.EventId, null, "QueueFull", null, cancellationToken); }
            catch { /* The process event remains stored even if diagnostic metadata cannot be updated. */ }
        }
        var capped = currentTruncated ? " Limit snapshotu osiągnięty; zdarzenia zakończenia pominięto dla niepełnej próbki." :
            previousSnapshotTruncated ? " Poprzednia próbka była obcięta; zdarzenia nowych procesów pominięto w tym kroku." : "";
        droppedEvents += newlyDroppedEvents;
        var backlogState = pendingChanges.Count + backlogToAdd.Length - backlogToRemove.Length;
        State = $"Snapshot procesów działa; {current.Count} PID, {toStore.Length} zmian, kolejka {backlogState}, odrzucono ponad limit łącznie {droppedEvents}.{capped}" +
            (parentSnapshotFailed ? " Migawka relacji rodzic–proces potomny była niedostępna; ten cykl nie ocenił tych relacji." : "");
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
                changes.Add(new("Proces zaobserwowany", id, name, DateTimeOffset.UtcNow));
        foreach (var (id, name) in previous)
            if (!currentTruncated && (!current.TryGetValue(id, out var currentName) || !string.Equals(name, currentName, StringComparison.OrdinalIgnoreCase)) && !excluded.Contains(name))
                changes.Add(new("Proces zniknął z migawki", id, name, DateTimeOffset.UtcNow));
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

    private sealed record ProcessChange(string Action, int ProcessId, string ProcessName, DateTimeOffset ObservedAt);
}
