using System.Management;
using System.Runtime.Versioning;

namespace Sentinel.Engine;

public sealed record WindowsProcessTraceEvent(DateTimeOffset ObservedAt, string Action, int ProcessId,
    string ProcessName, int ParentProcessId);

/// <summary>
/// Receives process lifecycle events from the Windows Kernel Process provider exposed by WMI.
/// It is advisory and bounded; the periodic process snapshot remains the recovery source.
/// </summary>
public sealed class WindowsProcessTraceSource : IDisposable
{
    private const int Capacity = 4096;
    private readonly object gate = new();
    private readonly Queue<WindowsProcessTraceEvent> events = new();
    private ManagementEventWatcher? startWatcher;
    private ManagementEventWatcher? stopWatcher;
    private long dropped;
    private int stopping;

    public string State { get; private set; } = "Nie uruchomiono źródła zdarzeń procesów Windows.";
    public long DroppedEvents => Interlocked.Read(ref dropped);

    public void Start()
    {
        if (!OperatingSystem.IsWindows()) { State = "Zdarzenia WMI procesów są dostępne tylko w Windows."; return; }
        try
        {
            startWatcher = CreateWatcher("Win32_ProcessStartTrace", "Proces zaobserwowany");
            stopWatcher = CreateWatcher("Win32_ProcessStopTrace", "Proces zakończony");
            startWatcher.Start();
            stopWatcher.Start();
            State = "Odbieranie zdarzeń startu i zakończenia procesów przez WMI; kolejka ograniczona do 4096.";
        }
        catch (Exception exception)
        {
            DisposeWatchers();
            State = "Zdarzenia procesów WMI niedostępne (" + exception.GetType().Name + "); działa awaryjny snapshot PID.";
        }
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

    [SupportedOSPlatform("windows")]
    private ManagementEventWatcher CreateWatcher(string eventClass, string action)
    {
        var watcher = new ManagementEventWatcher(new WqlEventQuery($"SELECT * FROM {eventClass}"));
        watcher.EventArrived += (_, args) => OnEvent(args.NewEvent, action);
        watcher.Stopped += (_, _) =>
        {
            if (Volatile.Read(ref stopping) == 0)
                State = "Subskrypcja zdarzeń procesów WMI niedostępna po zatrzymaniu watcher'a; działa awaryjny snapshot PID.";
        };
        return watcher;
    }

    [SupportedOSPlatform("windows")]
    private void OnEvent(ManagementBaseObject? value, string action)
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
            var item = new WindowsProcessTraceEvent(timestamp, action, (int)pid, name, parentPid <= int.MaxValue ? (int)parentPid : 0);
            lock (gate)
            {
                if (events.Count == Capacity) { Interlocked.Increment(ref dropped); return; }
                events.Enqueue(item);
            }
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
        if (OperatingSystem.IsWindows()) DisposeWatchers();
    }
}
