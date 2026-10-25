namespace Sentinel.Core.Analysis;

public sealed record DomainFeedRefreshStatus(bool Enabled, string State, DateTimeOffset? LastAttemptAt,
    string? LastErrorCode);

/// <summary>Runs an explicitly opted-in, fixed-source CERT refresh without blocking the Engine request loop.</summary>
public sealed class DomainFeedRefreshScheduler
{
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(24);
    public static readonly TimeSpan RetryInterval = TimeSpan.FromHours(6);

    private readonly object gate = new();
    private bool enabled;
    private bool running;
    private DateTimeOffset? lastAttemptAt;
    private string? lastErrorCode;
    private string state = "Wyłączone";
    private Task? currentRefresh;
    private CancellationTokenSource? refreshCancellation;

    public DomainFeedRefreshScheduler(DomainFeedRefreshCheckpoint? checkpoint = null)
    {
        lastAttemptAt = checkpoint?.LastAttemptAt;
        lastErrorCode = checkpoint?.LastErrorCode;
        if (lastErrorCode is not null) state = "Błąd aktualizacji";
        else if (lastAttemptAt is not null) state = "Ostatnia próba";
    }

    public DomainFeedRefreshStatus Status
    {
        get { lock (gate) return new(enabled, state, lastAttemptAt, lastErrorCode); }
    }

    public void Evaluate(bool isEnabled, ReputationStatus reputation, DateTimeOffset now,
        Func<CancellationToken, Task> update, Action<DateTimeOffset, string?>? saveCheckpoint = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reputation);
        ArgumentNullException.ThrowIfNull(update);
        if (!isEnabled)
        {
            CancellationTokenSource? cancellation;
            lock (gate)
            {
                enabled = false;
                if (!running)
                {
                    state = "Wyłączone";
                    return;
                }
                state = "Anulowanie pobierania";
                cancellation = refreshCancellation;
            }
            try { cancellation?.Cancel(); }
            catch (ObjectDisposedException) { }
            return;
        }

        lock (gate)
        {
            enabled = true;
            if (running) return;

            var due = reputation.FetchedAt is null || now < reputation.FetchedAt.Value ||
                now - reputation.FetchedAt.Value >= RefreshInterval;
            if (!due)
            {
                state = "Aktualna";
                if (lastErrorCode is not null)
                {
                    try
                    {
                        if (lastAttemptAt is { } last) saveCheckpoint?.Invoke(last, null);
                        lastErrorCode = null;
                    }
                    catch (Exception ex) { lastErrorCode = ex.GetType().Name; }
                }
                return;
            }
            if (lastAttemptAt is { } attempted && (now < attempted || now - attempted < RetryInterval))
                return;

            lastAttemptAt = now;
            lastErrorCode = null;
            try { saveCheckpoint?.Invoke(now, null); }
            catch (Exception ex)
            {
                lastErrorCode = ex.GetType().Name;
                state = "Błąd aktualizacji";
                return;
            }
            running = true;
            state = "Pobieranie";
            refreshCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            currentRefresh = RefreshAsync(update, now, saveCheckpoint, refreshCancellation);
        }
    }

    public async Task WaitForIdleAsync()
    {
        Task? refresh;
        lock (gate) refresh = currentRefresh;
        if (refresh is not null) await refresh.ConfigureAwait(false);
    }

    private async Task RefreshAsync(Func<CancellationToken, Task> update, DateTimeOffset attemptedAt,
        Action<DateTimeOffset, string?>? saveCheckpoint, CancellationTokenSource cancellation)
    {
        string? errorCode = null;
        var refreshSucceeded = false;
        try { await update(cancellation.Token).ConfigureAwait(false); refreshSucceeded = true; }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception ex) { errorCode = ex.GetType().Name; }
        try { saveCheckpoint?.Invoke(attemptedAt, errorCode); }
        catch (Exception ex) { errorCode ??= ex.GetType().Name; }
        lock (gate)
        {
            running = false;
            lastErrorCode = errorCode;
            state = !enabled ? "Wyłączone"
                : cancellation.IsCancellationRequested ? "Anulowano"
                : refreshSucceeded ? "Zaktualizowana" : "Błąd aktualizacji";
            if (ReferenceEquals(refreshCancellation, cancellation)) refreshCancellation = null;
        }
        cancellation.Dispose();
    }
}
