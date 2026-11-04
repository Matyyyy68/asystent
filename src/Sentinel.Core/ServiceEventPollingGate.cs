namespace Sentinel.Core;

/// <summary>Rate-limits service event polling and prevents overlapping pipe reads.</summary>
public sealed class ServiceEventPollingGate
{
    private static readonly TimeSpan MinimumInterval = TimeSpan.FromSeconds(30);
    private DateTimeOffset? lastAttemptAtUtc;
    private bool inFlight;

    public bool TryBegin(DateTimeOffset nowUtc, bool notificationsEnabled, bool shutdownRequested)
    {
        if (!notificationsEnabled || shutdownRequested || inFlight ||
            (lastAttemptAtUtc is { } last && nowUtc - last < MinimumInterval))
            return false;

        inFlight = true;
        lastAttemptAtUtc = nowUtc;
        return true;
    }

    public void Complete() => inFlight = false;
}
