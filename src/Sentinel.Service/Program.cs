namespace Sentinel.Service;

internal static class Program
{
    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows()) return 2;
        if (args.Length == 1 && args[0].Equals("--self-test", StringComparison.OrdinalIgnoreCase))
            return SecureServiceDataDirectory.ValidateDirectorySecurity() && new ServiceRestartBackoff().SelfTest() ? 0 : 1;
        if (args.Length == 1 && args[0].Equals("--console", StringComparison.OrdinalIgnoreCase))
        {
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; cancellation.Cancel(); };
            return RunServiceAsync(cancellation.Token, static () => { }).GetAwaiter().GetResult();
        }
        return WindowsServiceDispatcher.Run("Sentinel AI Core", RunServiceAsync);
    }

    private static async Task<int> RunServiceAsync(CancellationToken cancellationToken, Action reportStarted)
    {
        using var worker = new SentinelMonitoringWorker();
        await worker.StartAsync(cancellationToken);
        reportStarted();
        await worker.RunAsync(cancellationToken);
        return 0;
    }
}
