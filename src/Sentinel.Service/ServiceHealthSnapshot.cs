using System.Security.Principal;

namespace Sentinel.Service;

internal sealed class ServiceHealthSnapshot
{
    private static readonly TimeSpan StaleAfter = TimeSpan.FromSeconds(30);
    private readonly object gate = new();
    private DateTimeOffset? lastCollectionAtUtc;
    private bool lastCollectionSucceeded;

    public void MarkCollectionSucceeded(DateTimeOffset timestamp)
    {
        lock (gate)
        {
            lastCollectionAtUtc = timestamp.ToUniversalTime();
            lastCollectionSucceeded = true;
        }
    }

    public void MarkCollectionFailed()
    {
        lock (gate) lastCollectionSucceeded = false;
    }

    public ServiceHealthResponse GetResponse(DateTimeOffset now)
    {
        lock (gate)
        {
            var age = lastCollectionAtUtc is null ? (TimeSpan?)null : now.ToUniversalTime() - lastCollectionAtUtc.Value;
            var state = lastCollectionAtUtc is null
                ? "starting"
                : lastCollectionSucceeded && age is { } elapsed && elapsed >= TimeSpan.Zero && elapsed <= StaleAfter
                    ? "running"
                    : "degraded";
            return new ServiceHealthResponse(state, lastCollectionAtUtc);
        }
    }

    public bool SelfTest()
    {
        if (GetResponse(DateTimeOffset.UtcNow).State != "starting") return false;
        MarkCollectionSucceeded(DateTimeOffset.UtcNow);
        if (GetResponse(DateTimeOffset.UtcNow).State != "running") return false;
        if (GetResponse(DateTimeOffset.UtcNow.AddSeconds(31)).State != "degraded") return false;
        MarkCollectionSucceeded(DateTimeOffset.UtcNow.AddMinutes(1));
        if (GetResponse(DateTimeOffset.UtcNow).State != "degraded") return false;
        MarkCollectionFailed();
        return GetResponse(DateTimeOffset.UtcNow).State == "degraded";
    }
}

internal sealed record ServiceHealthResponse(string State, DateTimeOffset? LastCollectionAtUtc);
