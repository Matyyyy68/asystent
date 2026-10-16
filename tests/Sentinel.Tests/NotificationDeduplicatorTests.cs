using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class NotificationDeduplicatorTests
{
    [Fact]
    public void SuppressesRepeatedKeyUntilIntervalExpires()
    {
        var deduplicator = new NotificationDeduplicator(TimeSpan.FromMinutes(5));
        var now = DateTimeOffset.UtcNow;
        Assert.True(deduplicator.TryMark("url.brand", now));
        Assert.False(deduplicator.TryMark("url.brand", now.AddMinutes(1)));
        Assert.True(deduplicator.TryMark("url.brand", now.AddMinutes(5)));
    }

    [Fact]
    public void DistinctKeysRemainIndependentAndCapacityIsBounded()
    {
        var deduplicator = new NotificationDeduplicator(TimeSpan.FromHours(1), 2);
        var now = DateTimeOffset.UtcNow;
        Assert.True(deduplicator.TryMark("a", now));
        Assert.True(deduplicator.TryMark("b", now.AddSeconds(1)));
        Assert.True(deduplicator.TryMark("c", now.AddSeconds(2)));
        Assert.True(deduplicator.TryMark("a", now.AddSeconds(3)));
    }
}
