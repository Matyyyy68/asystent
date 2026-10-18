using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Automation;
using Sentinel.Core.Analysis;
using Sentinel.Core.Context;

namespace Sentinel.Desktop.Context;

/// <summary>Foreground-only, opt-in UIA capture. Never reads input values, keystrokes or screenshots.</summary>
public sealed class WindowsContextProvider : IContextProvider, IForegroundEventSource
{
    private const uint ForegroundEvent = 3;
    private readonly WinEventDelegate callback;
    private nint hook;
    private int capturing;
    public event EventHandler? ForegroundChanged;
    public WindowsContextProvider() => callback = OnForeground;
    public void Start()
    {
        if (hook != 0) return;
        hook = SetWinEventHook(ForegroundEvent, ForegroundEvent, 0, callback, 0, 0, 2);
        if (hook == 0) throw new System.ComponentModel.Win32Exception();
    }
    public void Stop() { if (hook != 0) { UnhookWinEvent(hook); hook = 0; } }
    private void OnForeground(nint handle, uint eventType, nint hwnd, int objectId, int childId, uint thread, uint time)
    { if (hwnd != 0) ForegroundChanged?.Invoke(this, EventArgs.Empty); }
    public Task<WindowDescriptor?> GetForegroundAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var hwnd = GetForegroundWindow();
        if (hwnd == 0) return Task.FromResult<WindowDescriptor?>(null);
        GetWindowThreadProcessId(hwnd, out uint id);
        if (id == Environment.ProcessId) return Task.FromResult<WindowDescriptor?>(null);
        try
        {
            using var process = Process.GetProcessById((int)id);
            var title = new StringBuilder(512); GetWindowText(hwnd, title, title.Capacity);
            return Task.FromResult<WindowDescriptor?>(new(hwnd, (int)id, process.ProcessName, title.ToString()));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        { return Task.FromResult<WindowDescriptor?>(null); }
    }
    public async Task<ContextCapture> CaptureAsync(WindowDescriptor window, bool includeStaticText, CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref capturing, 1, 0) != 0) return new(CaptureStatus.Busy, null);
        // A stalled third-party UIA provider can occupy at most one worker. Timeout does not start more workers.
        var work = Task.Run(() =>
        {
            try { return Read(window, includeStaticText, cancellationToken); }
            catch (Exception ex) when (ex is ElementNotAvailableException or InvalidOperationException or COMException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            { return new ContextCapture(CaptureStatus.Unavailable, null); }
            finally { Volatile.Write(ref capturing, 0); }
        }, CancellationToken.None);
        try { return await work.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken); }
        catch (TimeoutException) { return new(CaptureStatus.Unavailable, null); }
    }
    private static ContextCapture Read(WindowDescriptor window, bool includeStaticText, CancellationToken ct)
    {
        bool SameForeground()
        {
            GetWindowThreadProcessId(window.Handle, out uint pid);
            return GetForegroundWindow() == window.Handle && pid == window.ProcessId;
        }
        if (!SameForeground()) return new(CaptureStatus.Unavailable, null);
        var text = new StringBuilder(); bool truncated = false;
        if (includeStaticText)
        {
            var root = AutomationElement.FromHandle(window.Handle);
            if (root is null) return new(CaptureStatus.Unavailable, null);
            var walker = TreeWalker.ControlViewWalker;
            var stack = new Stack<(AutomationElement Element, int Depth)>(); stack.Push((root, 0));
            var watch = Stopwatch.StartNew(); int visited = 0; int queued = 1;
            var unique = new HashSet<string>(StringComparer.Ordinal);
            while (stack.TryPop(out var entry))
            {
                ct.ThrowIfCancellationRequested();
                if (++visited > 250 || watch.Elapsed > TimeSpan.FromSeconds(2) || text.Length >= PrivacyFilter.MaximumTextLength) { truncated = true; break; }
                var current = entry.Element.Current;
                // Skip the ENTIRE subtree of editable/password controls, including their accessible names.
                if (current.IsPassword || current.ControlType == ControlType.Edit || current.ControlType == ControlType.ComboBox || current.IsOffscreen) continue;
                if (current.ControlType == ControlType.Text || current.ControlType == ControlType.Hyperlink || current.ControlType == ControlType.Button)
                {
                    var name = current.Name;
                    if (!string.IsNullOrWhiteSpace(name) && unique.Add(name))
                    {
                        int remaining = PrivacyFilter.MaximumTextLength - text.Length;
                        if (name.Length > remaining) { text.Append(name.AsSpan(0, remaining)); truncated = true; break; }
                        text.AppendLine(name);
                    }
                }
                if (entry.Depth >= 12) { truncated = true; continue; }
                var child = walker.GetFirstChild(entry.Element);
                while (child is not null)
                {
                    if (queued++ >= 250 || watch.Elapsed > TimeSpan.FromSeconds(2)) { truncated = true; break; }
                    stack.Push((child, entry.Depth + 1)); child = walker.GetNextSibling(child);
                }
            }
        }
        ct.ThrowIfCancellationRequested();
        if (!SameForeground()) return new(CaptureStatus.Unavailable, null);
        return new(CaptureStatus.Captured, new AnalysisContext(window.Application, PrivacyFilter.Redact(text.ToString()), DateTimeOffset.UtcNow,
            CorrelationKey: $"window:{window.ProcessId}:{window.Handle}"), truncated);
    }
    public void Dispose() => Stop();
    private delegate void WinEventDelegate(nint hook, uint eventType, nint hwnd, int objectId, int childId, uint eventThread, uint eventTime);
    [DllImport("user32.dll")] private static extern nint GetForegroundWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(nint hwnd, out uint processId);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(nint hwnd, StringBuilder text, int maximum);
    [DllImport("user32.dll")] private static extern nint SetWinEventHook(uint minimum, uint maximum, nint module, WinEventDelegate callback, uint process, uint thread, uint flags);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool UnhookWinEvent(nint hook);
}
