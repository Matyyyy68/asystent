namespace Sentinel.Service;

internal static class Program
{
    private const string ServiceName = "Sentinel AI Core";

    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows()) return 2;
        if (args.Length == 1 && args[0].Equals("--self-test", StringComparison.OrdinalIgnoreCase))
        {
            var directorySecurityValid = SecureServiceDataDirectory.ValidateDirectorySecurity();
            var restartBackoffValid = new ServiceRestartBackoff().SelfTest();
            var statusPipeValid = ServiceStatusPipeServer.SelfTest();
            var historyFieldReadersValid = SentinelMonitoringWorker.HistoryFieldReadersSelfTest();
            if (!directorySecurityValid) Console.Error.WriteLine("SELF_TEST_FAILED directory-security");
            if (!restartBackoffValid) Console.Error.WriteLine("SELF_TEST_FAILED restart-backoff");
            if (!statusPipeValid) Console.Error.WriteLine("SELF_TEST_FAILED status-pipe");
            if (!historyFieldReadersValid) Console.Error.WriteLine("SELF_TEST_FAILED history-field-readers");
            return directorySecurityValid && restartBackoffValid && statusPipeValid && historyFieldReadersValid ? 0 : 1;
        }
        if (args.Length == 1 && args[0].Equals("--console", StringComparison.OrdinalIgnoreCase))
        {
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; cancellation.Cancel(); };
            return RunServiceAsync(cancellation.Token, static () => { }).GetAwaiter().GetResult();
        }
        var allowedUserSid = ParseAllowedUserSid(args);
        return WindowsServiceDispatcher.Run(ServiceName,
            (cancellationToken, reportStarted) => RunServiceAsync(cancellationToken, reportStarted, allowedUserSid));
    }

    private static async Task<int> RunServiceAsync(CancellationToken cancellationToken, Action reportStarted, System.Security.Principal.SecurityIdentifier? allowedUserSid = null)
    {
        using var worker = new SentinelMonitoringWorker(allowedUserSid);
        await worker.StartAsync(cancellationToken);
        reportStarted();
        await worker.RunAsync(cancellationToken);
        return 0;
    }

    private static System.Security.Principal.SecurityIdentifier? ParseAllowedUserSid(string[] args)
    {
        const string Prefix = "--allowed-user-sid=";
        var values = args.Where(argument => argument.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (values.Length == 0) return null;
        if (values.Length != 1) throw new ArgumentException("A single allowed user SID is required.");
        var sid = new System.Security.Principal.SecurityIdentifier(values[0][Prefix.Length..]);
        if (!sid.IsAccountSid()) throw new ArgumentException("The configured service client SID is not an account SID.");
        return sid;
    }
}
