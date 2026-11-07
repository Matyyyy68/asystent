using Sentinel.Engine;
using System.Collections.Concurrent;
using Xunit;

namespace Sentinel.Tests;

public sealed class WindowsProcessTraceSourceTests
{
    [Fact]
    public void WmiRetryDelayUsesBoundedExponentialBackoff()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), WindowsProcessTraceSource.RetryDelayForAttempt(0));
        Assert.Equal(TimeSpan.FromSeconds(10), WindowsProcessTraceSource.RetryDelayForAttempt(1));
        Assert.Equal(TimeSpan.FromSeconds(20), WindowsProcessTraceSource.RetryDelayForAttempt(2));
        Assert.Equal(TimeSpan.FromSeconds(160), WindowsProcessTraceSource.RetryDelayForAttempt(5));
        Assert.Equal(TimeSpan.FromSeconds(300), WindowsProcessTraceSource.RetryDelayForAttempt(6));
        Assert.Equal(TimeSpan.FromSeconds(300), WindowsProcessTraceSource.RetryDelayForAttempt(100));
    }

    [Fact]
    public void WmiRetryDelayRejectsNegativeAttempt()
        => Assert.Throws<ArgumentOutOfRangeException>(() => WindowsProcessTraceSource.RetryDelayForAttempt(-1));

    [Fact]
    public void FailedSubscriptionIsRetriedAndRecoversAutomatically()
    {
        if (!OperatingSystem.IsWindows()) return;
        var created = 0;
        var subscriptions = new ConcurrentBag<FakeSubscription>();
        using var source = new WindowsProcessTraceSource((_, _) =>
        {
            var sequence = Interlocked.Increment(ref created);
            var subscription = new FakeSubscription(sequence == 1, sequence);
            subscriptions.Add(subscription);
            return subscription;
        }, _ => TimeSpan.FromMilliseconds(10));

        source.Start();

        Assert.True(SpinWait.SpinUntil(() => source.State.StartsWith("Odbieranie zdarzeń", StringComparison.Ordinal), TimeSpan.FromSeconds(2)), source.State);
        Assert.Equal(4, created);
        Assert.All(subscriptions, item => Assert.Equal(item.Sequence <= 2, item.IsDisposed));
    }

    [Fact]
    public void UnexpectedWmiStopSchedulesSubscriptionRecovery()
    {
        if (!OperatingSystem.IsWindows()) return;
        var created = 0;
        var subscriptions = new ConcurrentBag<FakeSubscription>();
        using var source = new WindowsProcessTraceSource((_, _) =>
        {
            var subscription = new FakeSubscription(false, created + 1);
            subscriptions.Add(subscription);
            Interlocked.Increment(ref created);
            return subscription;
        }, _ => TimeSpan.FromMilliseconds(10));

        source.Start();
        Assert.StartsWith("Odbieranie zdarzeń", source.State, StringComparison.Ordinal);
        Assert.Contains(subscriptions, item => item.IsStarted);
        subscriptions.First().RaiseStopped();

        Assert.True(SpinWait.SpinUntil(() => created >= 4 && source.State.StartsWith("Odbieranie zdarzeń", StringComparison.Ordinal), TimeSpan.FromSeconds(2)), source.State);
        Assert.True(created >= 4);
    }

    [Fact]
    public void SourceBuffersOnlyValidatedEventsFromSubscriptions()
    {
        if (!OperatingSystem.IsWindows()) return;
        var subscriptions = new ConcurrentBag<FakeSubscription>();
        using var source = new WindowsProcessTraceSource((_, _) =>
        {
            var subscription = new FakeSubscription(false, subscriptions.Count + 1);
            subscriptions.Add(subscription);
            return subscription;
        }, _ => TimeSpan.FromHours(1));

        source.Start();
        var startSubscription = Assert.Single(subscriptions, item => item.Sequence == 1);
        startSubscription.RaiseEvent(new(DateTimeOffset.UtcNow, "Proces zaobserwowany", 123, "synthetic-process", 1));
        startSubscription.RaiseEvent(new(DateTimeOffset.UtcNow, "invalid-action", 123, "synthetic-process", 1));
        startSubscription.RaiseEvent(new(DateTimeOffset.UtcNow, "Proces zakończony", -1, "bad", 0));

        var result = Assert.Single(source.Drain());
        Assert.Equal(123, result.ProcessId);
        Assert.Equal("synthetic-process", result.ProcessName);
        Assert.Empty(source.Drain());
    }

    [Fact]
    public void QueueOverflowIsBoundedAndReportedAsDegraded()
    {
        if (!OperatingSystem.IsWindows()) return;
        var subscriptions = new ConcurrentBag<FakeSubscription>();
        using var source = new WindowsProcessTraceSource((_, _) =>
        {
            var subscription = new FakeSubscription(false, subscriptions.Count + 1);
            subscriptions.Add(subscription);
            return subscription;
        });
        source.Start();
        var startSubscription = Assert.Single(subscriptions, item => item.Sequence == 1);
        var item = new WindowsProcessTraceEvent(DateTimeOffset.UtcNow, "Proces zaobserwowany", 123,
            "synthetic-process", 1);

        for (var index = 0; index < 4097; index++) startSubscription.RaiseEvent(item);

        Assert.Equal(1, source.DroppedEvents);
        Assert.Equal(4096, source.Drain().Count);
        Assert.Contains("przepełniono kolejkę", source.State, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class FakeSubscription(bool failOnStart, int sequence) : IProcessTraceSubscription
    {
        public event Action<WindowsProcessTraceEvent>? EventReceived;
        public event Action? Stopped;
        public bool IsStarted { get; private set; }
        public bool IsDisposed { get; private set; }
        public int Sequence { get; } = sequence;

        public void Start()
        {
            if (failOnStart) throw new InvalidOperationException("synthetic WMI subscription failure");
            IsStarted = true;
        }

        public void Stop() => IsStarted = false;
        public void Dispose() => IsDisposed = true;
        public void RaiseEvent(WindowsProcessTraceEvent item) => EventReceived?.Invoke(item);
        public void RaiseStopped() => Stopped?.Invoke();
    }
}
