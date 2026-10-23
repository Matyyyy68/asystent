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
    public void ListedDomainWarnsOnManualSubdomainButNotParentOrLookalike()
    {
        var now = DateTimeOffset.UtcNow;
        var reputation = new DomainReputation(directory);
        reputation.Import("listed.test\nlogin.only.test", now);
        var baseline = new ThreatAssessment(ThreatCategory.None, RiskLevel.Information, [], [], [], "No sygnałów.");

        var subdomain = ManualUrlReputationMatcher.Apply(baseline, null,
            "Otwórz https://shop.listed.test/login", reputation, now, out var matchedHost);
        var parent = ManualUrlReputationMatcher.Apply(baseline, null,
            "Otwórz https://only.test/", reputation, now, out _);
        var lookalike = ManualUrlReputationMatcher.Apply(baseline, null,
            "Otwórz https://notlisted.test/", reputation, now, out _);

        Assert.Equal("shop.listed.test", matchedHost);
        Assert.Equal(RiskLevel.High, subdomain.Risk);
        Assert.Contains(subdomain.Indicators, indicator => indicator.Id == "reputation.cert");
        Assert.Equal(RiskLevel.Information, parent.Risk);
        Assert.Equal(RiskLevel.Information, lookalike.Risk);
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
    public void ExactLocalUrlMatchRaisesRiskAndReturnsOnlyPrivacySafeSignalMaterial()
    {
        var now = DateTimeOffset.UtcNow;
        var domains = new DomainReputation(directory);
        var urls = new UrlReputation(directory);
        const string maliciousUrl = "https://paypal.com@attacker.test/login?campaign=fixture";
        urls.Import(maliciousUrl + "\n", now);
        var baseline = new ThreatAssessment(ThreatCategory.None, RiskLevel.Information, [], [], [], "No sygnałów.");

        var result = ManualUrlReputationMatcher.Apply(baseline, maliciousUrl, "", domains, urls, now,
            out var matchedHost, out var signalHash, out var matchedUrl);

        Assert.Equal("attacker.test", matchedHost);
        Assert.Equal(UrlReputation.CreateSignalHash(maliciousUrl), signalHash);
        Assert.Equal(maliciousUrl, matchedUrl);
        Assert.Equal(RiskLevel.High, result.Risk);
        Assert.Contains(result.Indicators, indicator => indicator.Id == "reputation.url-feed");
        Assert.DoesNotContain(maliciousUrl, result.Explanation, StringComparison.Ordinal);
        Assert.DoesNotContain("attacker.test", result.Explanation, StringComparison.Ordinal);

        var stale = ManualUrlReputationMatcher.Apply(baseline, maliciousUrl, "", domains, urls, now.AddHours(49),
            out _, out var staleHash, out _);
        Assert.Null(staleHash);
        Assert.Empty(stale.Indicators);
    }

    [Fact]
    public void SignalHostComesFromTheUrlThatProducedTheWarning()
    {
        var analyzer = new UrlAnalyzer(new DomainNames());
        const string embedded = "https://paypal.com.evil.test/login";
        var assessment = new ThreatAnalysisEngine(analyzer).Analyze(new AnalysisContext("test",
            $"Link {embedded}", DateTimeOffset.UtcNow, new NavigationSignal("https://example.com/")));

        var selected = ManualUrlReputationMatcher.FindSignalUrlAnalysis("https://example.com/",
            $"Link {embedded}", analyzer, assessment.Indicators);

        Assert.Equal("paypal.com.evil.test", selected?.Host);
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
