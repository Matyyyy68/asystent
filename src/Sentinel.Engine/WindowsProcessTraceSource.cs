using System.Management;
using System.Runtime.Versioning;

namespace Sentinel.Engine;

public sealed record WindowsProcessTraceEvent(DateTimeOffset ObservedAt, string Action, int ProcessId,
    string ProcessName, int ParentProcessId);

internal interface IProcessTraceSubscription : IDisposable
{
    event Action<WindowsProcessTraceEvent>? EventReceived;
    event Action? Stopped;
    void Start();
    void Stop();
}

/// <summary>
/// Receives process lifecycle events from the Windows Kernel Process provider exposed by WMI.
/// It is advisory and bounded; the periodic process snapshot remains the recovery source.
/// </summary>
public sealed class WindowsProcessTraceSource : IDisposable
{
    private const int Capacity = 4096;
    private readonly object gate = new();
    private readonly object lifecycleGate = new();
    private readonly Queue<WindowsProcessTraceEvent> events = new();
    private readonly Func<string, string, IProcessTraceSubscription> createSubscription;
    private readonly Func<int, TimeSpan> retryDelay;
    private readonly Timer retryTimer;
    private string state = "Nie uruchomiono źródła zdarzeń procesów Windows.";
    private IProcessTraceSubscription? startWatcher;
    private IProcessTraceSubscription? stopWatcher;
    private long dropped;
    private int stopping;
    private int starting;
    private int restartPending;
    private int disposed;
    private int retryAttempt;

    public string State
    {
        get => Volatile.Read(ref state);
        private set => Volatile.Write(ref state, value);
    }
    public long DroppedEvents => Interlocked.Read(ref dropped);

    public WindowsProcessTraceSource()
        : this(CreateWindowsSubscription, RetryDelayForAttempt) { }

    internal WindowsProcessTraceSource(Func<string, string, IProcessTraceSubscription> createSubscription,
        Func<int, TimeSpan>? retryDelay = null)
    {
        this.createSubscription = createSubscription ?? throw new ArgumentNullException(nameof(createSubscription));
        this.retryDelay = retryDelay ?? RetryDelayForAttempt;
        this.retryTimer = new Timer(_ =>
        {
            if (OperatingSystem.IsWindows()) RestartIfNeeded();
        }, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
    }

    public void Start()
    {
        if (!OperatingSystem.IsWindows()) { State = "Zdarzenia WMI procesów są dostępne tylko w Windows."; return; }
        if (Interlocked.Exchange(ref starting, 1) != 0 || Volatile.Read(ref disposed) != 0) return;
        lock (lifecycleGate)
        {
            try
            {
                if (Volatile.Read(ref disposed) != 0) return;
                if (startWatcher is not null && stopWatcher is not null) return;
                Interlocked.Exchange(ref stopping, 0);
                startWatcher = CreateWatcher("Win32_ProcessStartTrace", "Proces zaobserwowany");
                stopWatcher = CreateWatcher("Win32_ProcessStopTrace", "Proces zakończony");
                startWatcher.Start();
                stopWatcher.Start();
                if (Volatile.Read(ref restartPending) != 0)
                {
                    DisposeWatchers();
                    ScheduleRestart();
                    return;
                }
                retryAttempt = 0;
                State = "Odbieranie zdarzeń startu i zakończenia procesów przez WMI; kolejka ograniczona do 4096.";
            }
            catch (Exception exception)
            {
                DisposeWatchers();
                State = "Zdarzenia procesów WMI niedostępne (" + exception.GetType().Name + "); działa awaryjny snapshot PID, ponowienie zostanie wykonane automatycznie.";
                ScheduleRestart();
            }
            finally { Interlocked.Exchange(ref starting, 0); }
        }
    }

    internal static TimeSpan RetryDelayForAttempt(int attempt)
    {
        if (attempt < 0) throw new ArgumentOutOfRangeException(nameof(attempt));
        var exponent = Math.Min(attempt, 6);
        return TimeSpan.FromSeconds(Math.Min(5 * (1 << exponent), 300));
    }

    private static IProcessTraceSubscription CreateWindowsSubscription(string eventClass, string action)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        return new WmiProcessTraceSubscription(eventClass, action);
    }

    private void ScheduleRestart()
    {
        if (Volatile.Read(ref disposed) != 0 || Interlocked.Exchange(ref restartPending, 1) != 0) return;
        var delay = retryDelay(retryAttempt);
        retryAttempt = Math.Min(retryAttempt + 1, 7);
        try { retryTimer.Change(delay, Timeout.InfiniteTimeSpan); }
        catch (ObjectDisposedException) { }
    }

    [SupportedOSPlatform("windows")]
    private void RestartIfNeeded()
    {
        if (Volatile.Read(ref disposed) != 0) return;
        lock (lifecycleGate)
        {
            if (Volatile.Read(ref disposed) != 0) return;
            DisposeWatchers();
            Interlocked.Exchange(ref restartPending, 0);
        }
        Start();
    }

    public IReadOnlyList<WindowsProcessTraceEvent> Drain()
    {
        lock (gate)
        {
            var result = events.ToArray();
            events.Clear();
            return result;
        }
    }

    private IProcessTraceSubscription CreateWatcher(string eventClass, string action)
    {
        var watcher = createSubscription(eventClass, action);
        watcher.EventReceived += OnEvent;
        watcher.Stopped += OnWatcherStopped;
        return watcher;
    }

    private void OnEvent(WindowsProcessTraceEvent item)
    {
        if (item.ProcessId <= 0 || item.ProcessName.Length is 0 or > 260 || item.ProcessName.Any(char.IsControl) ||
            item.ParentProcessId < 0 || item.Action is not ("Proces zaobserwowany" or "Proces zakończony")) return;
        lock (gate)
        {
            if (events.Count == Capacity) { Interlocked.Increment(ref dropped); return; }
            events.Enqueue(item);
        }
    }

    private void OnWatcherStopped()
    {
        if (Volatile.Read(ref stopping) != 0 || Volatile.Read(ref disposed) != 0) return;
        State = "Subskrypcja zdarzeń procesów WMI zatrzymała się nieoczekiwanie; działa snapshot PID i silnik ponowi subskrypcję.";
        ScheduleRestart();
    }

    [SupportedOSPlatform("windows")]
    private void DisposeWatchers()
    {
        Interlocked.Exchange(ref stopping, 1);
        try { startWatcher?.Stop(); } catch { }
        try { stopWatcher?.Stop(); } catch { }
        startWatcher?.Dispose(); stopWatcher?.Dispose();
        startWatcher = null; stopWatcher = null;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        retryTimer.Dispose();
        if (OperatingSystem.IsWindows())
        {
            lock (lifecycleGate) DisposeWatchers();
        }
    }

    [SupportedOSPlatform("windows")]
    private sealed class WmiProcessTraceSubscription : IProcessTraceSubscription
    {
        private readonly ManagementEventWatcher watcher;
        private readonly string action;

        public event Action<WindowsProcessTraceEvent>? EventReceived;
        public event Action? Stopped;

        public WmiProcessTraceSubscription(string eventClass, string action)
        {
            this.action = action;
            watcher = new ManagementEventWatcher(new WqlEventQuery($"SELECT * FROM {eventClass}"));
            watcher.EventArrived += (_, args) => ReadEvent(args.NewEvent);
            watcher.Stopped += (_, _) => Stopped?.Invoke();
        }

        public void Start() => watcher.Start();
        public void Stop() => watcher.Stop();
        public void Dispose() => watcher.Dispose();

        private void ReadEvent(ManagementBaseObject? value)
        {
            if (value is null) return;
            try
            {
                var pid = ReadUInt32(value["ProcessID"]);
                var parentPid = ReadUInt32(value["ParentProcessID"]);
                var rawName = Convert.ToString(value["ProcessName"], System.Globalization.CultureInfo.InvariantCulture);
                var name = string.IsNullOrWhiteSpace(rawName) ? null : Path.GetFileNameWithoutExtension(rawName);
                if (pid is <= 0 or > int.MaxValue || string.IsNullOrWhiteSpace(name) || name.Length > 260 || name.Any(char.IsControl)) return;
                var timestamp = DateTimeOffset.UtcNow;
                var timeCreated = ReadUInt64(value["TIME_CREATED"]);
                if (timeCreated is > 0 and <= long.MaxValue)
                {
                    try { timestamp = DateTimeOffset.FromFileTime((long)timeCreated); } catch (ArgumentOutOfRangeException) { }
                }
                EventReceived?.Invoke(new(timestamp, action, (int)pid, name, parentPid <= int.MaxValue ? (int)parentPid : 0));
            }
            catch { /* Malformed/inaccessible WMI data is dropped; snapshots continue. */ }
        }

        private static ulong ReadUInt64(object? value)
        {
            try { return Convert.ToUInt64(value, System.Globalization.CultureInfo.InvariantCulture); }
            catch { return 0; }
        }

        private static uint ReadUInt32(object? value)
        {
            var converted = ReadUInt64(value);
            return converted <= uint.MaxValue ? (uint)converted : 0;
        }
    }
}
