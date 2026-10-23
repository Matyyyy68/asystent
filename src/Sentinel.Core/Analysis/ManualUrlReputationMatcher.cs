namespace Sentinel.Core.Analysis;

/// <summary>Matches only explicit URLs and locally extracted HTTP(S) links against the user's fresh local feed.</summary>
public static class ManualUrlReputationMatcher
{
    public static ThreatAssessment Apply(ThreatAssessment assessment, string? explicitUrl, string text,
        DomainReputation reputation, DateTimeOffset observedAt, out string? matchedHost)
    {
        matchedHost = FindMatches(explicitUrl, text, reputation, observedAt).FirstOrDefault();
        if (matchedHost is null) return assessment;
        return assessment with
        {
            Risk = (RiskLevel)Math.Max((int)assessment.Risk, (int)RiskLevel.High),
            Category = ThreatCategory.SuspiciousNavigation,
            Indicators = assessment.Indicators.Append(new ThreatIndicator("reputation.cert",
                "Domena znajduje się na aktualnej liście ostrzeżeń CERT Polska.", 10,
                ThreatCategory.SuspiciousNavigation)).ToArray(),
            Explanation = "Domena znajduje się na aktualnej liście ostrzeżeń CERT Polska. " + assessment.Explanation
        };
    }

    public static IReadOnlyList<string> FindMatches(string? explicitUrl, string text, DomainReputation reputation,
        DateTimeOffset observedAt)
    {
        var hosts = new List<string>();
        AddHost(explicitUrl);
        foreach (var embeddedUrl in ThreatAnalysisEngine.ExtractEmbeddedUrls(text).Urls)
            AddHost(embeddedUrl);
        if (hosts.Count == 0) return [];
        return reputation.FindMatches(hosts, observedAt);

        void AddHost(string? value)
        {
            if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
                hosts.Add(uri.IdnHost);
        }
    }
}
