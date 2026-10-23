using Sentinel.Core.Analysis;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests;

public sealed class ManualUrlReputationMatcherTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-manual-reputation-" + Guid.NewGuid());

    [Fact]
    public void MatchesEmbeddedHttpLinksAgainstFreshLocalFeedWithoutBroadeningDomains()
    {
        var now = DateTimeOffset.UtcNow;
        var reputation = new DomainReputation(directory);
        reputation.Import("listed.test\nother.test", now);

        var matches = ManualUrlReputationMatcher.FindMatches(null,
            "Sprawdź https://LISTED.test/login). oraz https://unlisted.test/", reputation, now);

        Assert.Equal(["listed.test"], matches);
    }

    [Fact]
    public void FreshEmbeddedFeedMatchProducesHighWarningWithoutExposingHost()
    {
        var now = DateTimeOffset.UtcNow;
        var reputation = new DomainReputation(directory);
        reputation.Import("listed.test", now);
        var baseline = new ThreatAssessment(ThreatCategory.None, RiskLevel.Information, [], [], [], "No sygnałów.");

        var result = ManualUrlReputationMatcher.Apply(baseline, null,
            "Otwórz https://listed.test/login", reputation, now, out var matchedHost);

        Assert.Equal("listed.test", matchedHost);
        Assert.Equal(RiskLevel.High, result.Risk);
        Assert.Equal(ThreatCategory.SuspiciousNavigation, result.Category);
        Assert.Contains(result.Indicators, indicator => indicator.Id == "reputation.cert");
        Assert.DoesNotContain("listed.test", result.Explanation);
    }

    [Fact]
    public void ReputationMatchDoesNotDowngradeAnExistingCriticalAssessment()
    {
        var now = DateTimeOffset.UtcNow;
        var reputation = new DomainReputation(directory);
        reputation.Import("listed.test", now);
        var baseline = new ThreatAssessment(ThreatCategory.UnsafeExecution, RiskLevel.Critical, [], [], [], "Existing severe signals.");

        var result = ManualUrlReputationMatcher.Apply(baseline, null,
            "Otwórz https://listed.test/login", reputation, now, out _);

        Assert.Equal(RiskLevel.Critical, result.Risk);
    }

    [Fact]
    public void CombinesExplicitAndEmbeddedUrlsAndUsesTheFreshnessWindow()
    {
        var now = DateTimeOffset.UtcNow;
        var reputation = new DomainReputation(directory);
        reputation.Import("listed.test", now);

        var currentMatches = ManualUrlReputationMatcher.FindMatches("https://listed.test/",
            "Link https://listed.test/path", reputation, now);
        var expiredMatches = ManualUrlReputationMatcher.FindMatches("https://listed.test/",
            "Link https://listed.test/path", reputation, now.AddHours(49));

        Assert.Equal(["listed.test"], currentMatches);
        Assert.Empty(expiredMatches);
    }

    [Fact]
    public void DoesNotMatchLinksBeyondEmbeddedUrlLimit()
    {
        var now = DateTimeOffset.UtcNow;
        var reputation = new DomainReputation(directory);
        reputation.Import("listed.test", now);
        var text = string.Join(' ', Enumerable.Range(1, 10).Select(index => $"https://safe{index}.test/")) +
            " https://listed.test/";

        Assert.Empty(ManualUrlReputationMatcher.FindMatches(null, text, reputation, now));
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
