using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class DomainFeedRefreshSchedulerTests
{
    [Fact]
    public async Task DisabledSchedulerNeverRefreshesOrMakesNetworkRequest()
    {
        var scheduler = new DomainFeedRefreshScheduler();
        var called = false;

        scheduler.Evaluate(false, new ReputationStatus(0, null, null, true), DateTimeOffset.UtcNow,
            _ => { called = true; return Task.CompletedTask; });

        await scheduler.WaitForIdleAsync();
        Assert.False(called);
        Assert.Equal("Wyłączone", scheduler.Status.State);
    }

    [Fact]
    public async Task EnabledSchedulerFetchesMissingFeedOnceAndDoesNotBlockCaller()
    {
        var scheduler = new DomainFeedRefreshScheduler();
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        Task Update(CancellationToken _) { Interlocked.Increment(ref calls); return completion.Task; }
        var now = DateTimeOffset.UtcNow;

        scheduler.Evaluate(true, new ReputationStatus(0, null, null, true), now, Update);
        Assert.Equal("Pobieranie", scheduler.Status.State);
        scheduler.Evaluate(true, new ReputationStatus(0, null, null, true), now, Update);
        Assert.Equal(1, calls);
        completion.SetResult();
        await scheduler.WaitForIdleAsync();

        Assert.Equal("Zaktualizowana", scheduler.Status.State);
        Assert.Equal(now, scheduler.Status.LastAttemptAt);
    }

    [Fact]
    public async Task DisablingAutoRefreshCancelsAnInFlightRequest()
    {
        var scheduler = new DomainFeedRefreshScheduler();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var now = DateTimeOffset.UtcNow;

        async Task Update(CancellationToken cancellationToken)
        {
            started.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); }
            catch (OperationCanceledException)
            {
                cancelled.SetResult();
                throw;
            }
        }

        scheduler.Evaluate(true, new ReputationStatus(0, null, null, true), now, Update);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));
        scheduler.Evaluate(false, new ReputationStatus(0, null, null, true), now, Update);
        await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await scheduler.WaitForIdleAsync();

        Assert.False(scheduler.Status.Enabled);
        Assert.Equal("Wyłączone", scheduler.Status.State);
        Assert.Null(scheduler.Status.LastErrorCode);
    }

    [Fact]
    public async Task FreshFeedIsNotRefetchedAndExpiredFeedIsDueAtTwentyFourHours()
    {
        var scheduler = new DomainFeedRefreshScheduler();
        var now = DateTimeOffset.UtcNow;
        var calls = 0;
        Task Update(CancellationToken _) { calls++; return Task.CompletedTask; }

        scheduler.Evaluate(true, new ReputationStatus(20, now - TimeSpan.FromHours(23), "A", false), now, Update);
        Assert.Equal("Aktualna", scheduler.Status.State);
        Assert.Equal(0, calls);

        scheduler.Evaluate(true, new ReputationStatus(20, now - DomainFeedRefreshScheduler.RefreshInterval, "A", false), now, Update);
        await scheduler.WaitForIdleAsync();
        Assert.Equal("Zaktualizowana", scheduler.Status.State);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task FailedRefreshIsReportedAndRetriedNoSoonerThanSixHours()
    {
        var scheduler = new DomainFeedRefreshScheduler();
        var now = DateTimeOffset.UtcNow;
        var calls = 0;
        Task Update(CancellationToken _) => Interlocked.Increment(ref calls) == 1
            ? Task.FromException(new HttpRequestException("private request details"))
            : Task.CompletedTask;
        var missing = new ReputationStatus(0, null, null, true);

        scheduler.Evaluate(true, missing, now, Update);
        await scheduler.WaitForIdleAsync();
        Assert.Equal("Błąd aktualizacji", scheduler.Status.State);
        Assert.Equal(nameof(HttpRequestException), scheduler.Status.LastErrorCode);

        scheduler.Evaluate(true, missing, now + TimeSpan.FromHours(5), Update);
        await scheduler.WaitForIdleAsync();
        Assert.Equal(1, calls);

        scheduler.Evaluate(true, missing, now + DomainFeedRefreshScheduler.RetryInterval, Update);
        await scheduler.WaitForIdleAsync();
        Assert.Equal(2, calls);
        Assert.Equal("Zaktualizowana", scheduler.Status.State);
        Assert.Null(scheduler.Status.LastErrorCode);
    }

    [Fact]
    public async Task PersistedCheckpointPreservesRetryThrottleAcrossEngineRestart()
    {
        var now = DateTimeOffset.UtcNow;
        var checkpoint = new DomainFeedRefreshCheckpoint(now, nameof(HttpRequestException));
        var scheduler = new DomainFeedRefreshScheduler(checkpoint);
        var calls = 0;
        Task Update(CancellationToken _) { calls++; return Task.CompletedTask; }
        DomainFeedRefreshCheckpoint? saved = null;
        void Save(DateTimeOffset at, string? error) => saved = new(at, error);
        var missing = new ReputationStatus(0, null, null, true);

        scheduler.Evaluate(true, missing, now + TimeSpan.FromHours(5), Update, Save);
        Assert.Equal(0, calls);
        Assert.Equal(nameof(HttpRequestException), scheduler.Status.LastErrorCode);

        scheduler.Evaluate(true, missing, now + DomainFeedRefreshScheduler.RetryInterval, Update, Save);
        await scheduler.WaitForIdleAsync();
        Assert.Equal(1, calls);
        Assert.Equal(new DomainFeedRefreshCheckpoint(now + DomainFeedRefreshScheduler.RetryInterval, null), saved);

        var restarted = new DomainFeedRefreshScheduler(saved);
        restarted.Evaluate(true, missing, now + TimeSpan.FromHours(11), Update, Save);
        Assert.Equal(1, calls);
    }

    [Fact]
    public void DomainReputationCheckpointSurvivesDatabaseReopen()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sentinel-cert-checkpoint-" + Guid.NewGuid().ToString("N"));
        var attemptedAt = DateTimeOffset.UtcNow;
        try
        {
            var reputation = new DomainReputation(directory);
            Assert.Equal(new DomainFeedRefreshCheckpoint(null, null), reputation.AutoRefreshCheckpoint());
            reputation.SaveAutoRefreshCheckpoint(attemptedAt, nameof(HttpRequestException));

            var reopened = new DomainReputation(directory);
            Assert.Equal(new DomainFeedRefreshCheckpoint(attemptedAt, nameof(HttpRequestException)), reopened.AutoRefreshCheckpoint());
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
    }
}
