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

        Assert.True(gate.TryBegin(now, preferenceKnown: true, shutdownRequested: false));
        Assert.False(gate.TryBegin(now.AddMinutes(1), preferenceKnown: true, shutdownRequested: false));

        gate.Complete();
        Assert.False(gate.TryBegin(now.AddSeconds(29), preferenceKnown: true, shutdownRequested: false));
        Assert.True(gate.TryBegin(now.AddSeconds(30), preferenceKnown: true, shutdownRequested: false));
    }

    [Fact]
    public void UnknownPreferenceAndShutdownDoNotConsumeAPollAttemptButSavedDisabledStillPolls()
    {
        var gate = new ServiceEventPollingGate();
        var now = DateTimeOffset.Parse("2026-11-04T12:00:00Z");

        Assert.False(gate.TryBegin(now, preferenceKnown: false, shutdownRequested: false));
        Assert.False(gate.TryBegin(now, preferenceKnown: true, shutdownRequested: true));
        Assert.True(gate.TryBegin(now, preferenceKnown: true, shutdownRequested: false));
        gate.Complete();
    }
}

