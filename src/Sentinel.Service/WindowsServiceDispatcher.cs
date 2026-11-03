using System.Runtime.InteropServices;

namespace Sentinel.Service;

internal static class WindowsServiceDispatcher
{
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceStopPending = 0x00000003;
    private const uint ServiceRunning = 0x00000004;
    private const uint ServiceAcceptStop = 0x00000001;
    private const uint ServiceAcceptShutdown = 0x00000004;
    private const uint ControlStop = 0x00000001;
    private const uint ControlShutdown = 0x00000005;

    private static readonly ServiceMainCallback ServiceMainRoot = ServiceMain;
    private static readonly HandlerCallback HandlerRoot = HandleControl;
    private static string serviceName = string.Empty;
    private static Func<CancellationToken, Action, Task<int>>? runService;
    private static CancellationTokenSource? stopping;
    private static IntPtr statusHandle;
    private static uint checkpoint;

    public static int Run(string name, Func<CancellationToken, Action, Task<int>> run)
    {
        serviceName = name;
        runService = run;
        var table = new[]
        {
            new ServiceTableEntry { ServiceName = name, ServiceMain = ServiceMainRoot },
            new ServiceTableEntry { ServiceName = null, ServiceMain = null }
        };
        if (!StartServiceCtrlDispatcher(table))
        {
            var error = Marshal.GetLastWin32Error();
            ServiceLog.Write("SCM_DISPATCH_FAILED error=" + error);
            return error;
        }
        return 0;
    }

    private static void ServiceMain(uint argumentCount, IntPtr arguments)
    {
        statusHandle = RegisterServiceCtrlHandlerEx(serviceName, HandlerRoot, IntPtr.Zero);
        if (statusHandle == IntPtr.Zero) return;
        using var cancellation = new CancellationTokenSource();
        stopping = cancellation;
        ReportStatus(ServiceStartPending, 0, 10_000, 1);
        using var pendingTimer = new Timer(_ => ReportStatus(ServiceStartPending, 0, 10_000,
            Interlocked.Increment(ref checkpoint)), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        try
        {
            var run = runService ?? throw new InvalidOperationException("Service entry point was not configured.");
            var exitCode = run(cancellation.Token, () =>
            {
                pendingTimer.Change(Timeout.Infinite, Timeout.Infinite);
                ReportStatus(ServiceRunning, 0, 0, 0);
            }).GetAwaiter().GetResult();
            ReportStatus(ServiceStopped, exitCode < 0 ? 1u : (uint)exitCode, 0, 0);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            ReportStatus(ServiceStopped, 0, 0, 0);
        }
        catch (Exception exception)
        {
            ServiceLog.Write("SERVICE_FAILED type=" + exception.GetType().Name);
            ReportStatus(ServiceStopped, 1, 0, 0);
        }
        finally { stopping = null; }
    }

    private static uint HandleControl(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control is ControlStop or ControlShutdown)
        {
            ReportStatus(ServiceStopPending, 0, 10_000, ++checkpoint);
            stopping?.Cancel();
        }
        return 0;
    }

    private static void ReportStatus(uint state, uint exitCode, uint waitHint, uint checkPoint)
    {
        if (statusHandle == IntPtr.Zero) return;
        var accepted = state == ServiceRunning ? ServiceAcceptStop | ServiceAcceptShutdown : 0;
        var status = new ServiceStatus(ServiceWin32OwnProcess, state, accepted, exitCode, 0, checkPoint, waitHint);
        if (!SetServiceStatus(statusHandle, ref status))
            ServiceLog.Write("SCM_STATUS_UPDATE_FAILED error=" + Marshal.GetLastWin32Error());
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? ServiceName;
        [MarshalAs(UnmanagedType.FunctionPtr)] public ServiceMainCallback? ServiceMain;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus(uint serviceType, uint currentState, uint controlsAccepted,
        uint win32ExitCode, uint serviceSpecificExitCode, uint checkPoint, uint waitHint)
    {
        public uint ServiceType = serviceType;
        public uint CurrentState = currentState;
        public uint ControlsAccepted = controlsAccepted;
        public uint Win32ExitCode = win32ExitCode;
        public uint ServiceSpecificExitCode = serviceSpecificExitCode;
        public uint CheckPoint = checkPoint;
        public uint WaitHint = waitHint;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainCallback(uint argumentCount, IntPtr arguments);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint HandlerCallback(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] serviceTable);

    [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, HandlerCallback handler, IntPtr context);

    [DllImport("advapi32.dll", EntryPoint = "SetServiceStatus", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(IntPtr statusHandle, ref ServiceStatus serviceStatus);
}

internal static class ServiceLog
{
    private static readonly object Gate = new();
    private static readonly string PathName = Path.Combine(SecureServiceDataDirectory.GetPath(), "service.log");

    public static void Write(string message)
    {
        try
        {
            lock (Gate)
            {
                if (File.Exists(PathName) && new FileInfo(PathName).Length > 256 * 1024) File.WriteAllText(PathName, string.Empty);
                File.AppendAllText(PathName, $"{DateTimeOffset.UtcNow:O} {message}{Environment.NewLine}");
            }
        }
        catch { /* Service diagnostics must not prevent monitoring or shutdown. */ }
    }
}
