using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ServiceEventPollingGateTests
{
    [Fact]
    public void EnforcesMinimumIntervalAndPreventsOverlappingReads()
    {
        var gate = new ServiceEventPollingGate();
        var now = DateTimeOffset.Parse("2026-11-04T12:00:00Z");

        Assert.True(gate.TryBegin(now, notificationsEnabled: true, shutdownRequested: false));
        Assert.False(gate.TryBegin(now.AddMinutes(1), notificationsEnabled: true, shutdownRequested: false));

        gate.Complete();
        Assert.False(gate.TryBegin(now.AddSeconds(29), notificationsEnabled: true, shutdownRequested: false));
        Assert.True(gate.TryBegin(now.AddSeconds(30), notificationsEnabled: true, shutdownRequested: false));
    }

    [Fact]
    public void DisabledNotificationsAndShutdownDoNotConsumeAPollAttempt()
    {
        var gate = new ServiceEventPollingGate();
        var now = DateTimeOffset.Parse("2026-11-04T12:00:00Z");

        Assert.False(gate.TryBegin(now, notificationsEnabled: false, shutdownRequested: false));
        Assert.False(gate.TryBegin(now, notificationsEnabled: true, shutdownRequested: true));
        Assert.True(gate.TryBegin(now, notificationsEnabled: true, shutdownRequested: false));
        gate.Complete();
    }
}
