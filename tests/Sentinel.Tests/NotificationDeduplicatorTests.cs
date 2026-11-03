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

    [Fact]
    public void NotificationBatchSummaryGroupsCategoriesAndDeduplicatesThem()
    {
        var summary = NotificationBatchSummary.Compose(["DNS", "plik", "DNS"]);

        Assert.Contains("DNS", summary);
        Assert.Contains("plik", summary);
        Assert.Equal(1, summary.Split("DNS", StringSplitOptions.None).Length - 1);
        Assert.Contains("Otwórz Sentinel AI", summary);
    }

    [Fact]
    public void NotificationBatchSummaryStaysWithinWindowsBalloonLimitAndReportsOmittedCategories()
    {
        var summary = NotificationBatchSummary.Compose(Enumerable.Range(0, 32)
            .Select(index => $"category-{index:D2}-" + new string((char)('a' + index % 26), 40)), 120);

        Assert.True(summary.Length <= 120);
        Assert.Contains("32 sygnałów", summary);
    }

    [Fact]
    public void NotificationBatchSummaryHandlesEmptyInputAndRejectsInvalidLimits()
    {
        Assert.Equal(string.Empty, NotificationBatchSummary.Compose([]));
        Assert.Throws<ArgumentOutOfRangeException>(() => NotificationBatchSummary.Compose(["DNS"], 31));
    }
}
