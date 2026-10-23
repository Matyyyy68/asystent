namespace Sentinel.Core.Analysis;

/// <summary>Matches only explicit URLs and locally extracted HTTP(S) links against the user's fresh local feed.</summary>
public static class ManualUrlReputationMatcher
{
    public static ThreatAssessment Apply(ThreatAssessment assessment, string? explicitUrl, string text,
        DomainReputation reputation, DateTimeOffset observedAt, out string? matchedHost)
    {
        var updated = Apply(assessment, explicitUrl, text, reputation, null, observedAt,
            out matchedHost, out _, out _);
        return updated;
    }

    public static ThreatAssessment Apply(ThreatAssessment assessment, string? explicitUrl, string text,
        DomainReputation reputation, UrlReputation? urlReputation, DateTimeOffset observedAt,
        out string? matchedHost, out string? matchedUrlHash, out string? matchedUrl)
    {
        matchedHost = FindMatches(explicitUrl, text, reputation, observedAt).FirstOrDefault();
        matchedUrlHash = null;
        matchedUrl = null;
        if (matchedHost is null && urlReputation is not null)
        {
            foreach (var candidate in Candidates(explicitUrl, text))
            {
                var check = urlReputation.Check(candidate, observedAt);
                if (!check.Match) continue;
                matchedUrl = candidate;
                matchedUrlHash = check.SignalHash;
                if (Uri.TryCreate(candidate, UriKind.Absolute, out var matchedUri)) matchedHost = matchedUri.IdnHost;
                break;
            }
        }
        if (matchedHost is null) return assessment;
        var matchedCert = reputation.FindMatches([matchedHost], observedAt).Count > 0;
        var indicator = matchedCert
            ? new ThreatIndicator("reputation.cert", "Domena znajduje się na aktualnej liście ostrzeżeń CERT Polska.", 10,
                ThreatCategory.SuspiciousNavigation)
            : new ThreatIndicator("reputation.url-feed", "Dokładny adres znajduje się na lokalnej liście URL użytkownika.", 10,
                ThreatCategory.SuspiciousNavigation);
        return assessment with
        {
            Risk = (RiskLevel)Math.Max((int)assessment.Risk, (int)RiskLevel.High),
            Category = ThreatCategory.SuspiciousNavigation,
            Indicators = assessment.Indicators.Append(indicator).ToArray(),
            Explanation = indicator.Description + " " + assessment.Explanation
        };
    }

    private static IEnumerable<string> Candidates(string? explicitUrl, string text)
    {
        if (!string.IsNullOrWhiteSpace(explicitUrl)) yield return explicitUrl;
        foreach (var embeddedUrl in ThreatAnalysisEngine.ExtractEmbeddedUrls(text).Urls) yield return embeddedUrl;
    }

    public static IReadOnlyList<string> FindMatches(string? explicitUrl, string text, DomainReputation reputation,
        DateTimeOffset observedAt)
    {
        var hosts = Candidates(explicitUrl, text).Select(value =>
        {
            return Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https"
                ? uri.IdnHost : null;
        }).ToList();
        if (hosts.Count == 0) return [];
        return reputation.FindMatches(hosts.OfType<string>(), observedAt);
    }

    public static UrlAnalysis? FindSignalUrlAnalysis(string? explicitUrl, string text, UrlAnalyzer urlAnalyzer,
        IReadOnlyList<ThreatIndicator> indicators, string? reputationMatchHost = null, string? reputationMatchUrl = null)
    {
        if (reputationMatchUrl is not null) return urlAnalyzer.Analyze(reputationMatchUrl);
        if (reputationMatchHost is not null) return urlAnalyzer.Analyze("https://" + reputationMatchHost);

        var urlIndicators = indicators.Where(indicator => indicator.Id.StartsWith("url.", StringComparison.Ordinal))
            .GroupBy(indicator => indicator.Id, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Max(indicator => indicator.Weight), StringComparer.Ordinal);
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(explicitUrl)) candidates.Add(explicitUrl);
        candidates.AddRange(ThreatAnalysisEngine.ExtractEmbeddedUrls(text).Urls);

        UrlAnalysis? fallback = null;
        UrlAnalysis? best = null;
        var bestWeight = 0;
        foreach (var candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var analysis = urlAnalyzer.Analyze(candidate);
            if (!analysis.IsValid) continue;
            fallback ??= analysis;
            var weight = analysis.Indicators.Sum(indicator => urlIndicators.GetValueOrDefault(indicator.Id));
            if (weight > bestWeight)
            {
                best = analysis;
                bestWeight = weight;
            }
        }

        return best ?? fallback;
    }
}
