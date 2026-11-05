namespace Sentinel.Core.Analysis;

/// <summary>
/// Deterministic evidence aggregation. The numeric score is a rule-derived severity
/// indicator, not a probability or a statistically calibrated likelihood.
/// </summary>
public static class RiskEngine
{
    public sealed record Result(int Score, RiskLevel Level);

    // Only evidence identifiers with a defined meaning contribute to scores for
    // system-monitor events. Unknown identifiers remain visible in the event but
    // cannot silently inflate its risk.
    private static readonly IReadOnlyDictionary<string, (int Weight, ThreatCategory Category)> EventEvidence =
        new Dictionary<string, (int, ThreatCategory)>(StringComparer.Ordinal)
        {
            ["process.behavior.office-spawned-script-host"] = (3, ThreatCategory.UnsafeExecution),
            ["reputation.ip-feed.match"] = (4, ThreatCategory.SuspiciousNavigation),
            ["reputation.cert.current-feed-match"] = (4, ThreatCategory.SuspiciousNavigation),
            ["file.sha256.matches-local-list"] = (3, ThreatCategory.UnsafeExecution),
            ["persistence.target.user-writable-location"] = (2, ThreatCategory.UnsafeExecution),
            ["correlation.process-network.office-spawned-script-host"] = (3, ThreatCategory.UnsafeExecution)
        };

    public static Result EvaluateEvidenceCodes(IEnumerable<string> evidenceCodes)
    {
        ArgumentNullException.ThrowIfNull(evidenceCodes);
        var allCodes = evidenceCodes.Where(code => code is not null).Distinct(StringComparer.Ordinal).ToArray();
        var codes = allCodes
            .Where(code => code is not null && EventEvidence.ContainsKey(code))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        // A local file hash list with unverified provenance is not sufficient
        // evidence to assign a numeric risk score.
        if (allCodes.Contains("file.local-list-source-unverified", StringComparer.Ordinal))
            codes = codes.Where(code => code != "file.sha256.matches-local-list").ToArray();
        var indicators = codes.Select(code =>
            {
                var evidence = EventEvidence[code];
                return new ThreatIndicator(code, code, evidence.Weight, evidence.Category);
            }).ToList();
        // Reputation contributes a second signal only when Windows also supplied
        // the matching event (DNS query or TCP connection) represented by the
        // reputation evidence code.
        if (codes.Contains("reputation.ip-feed.match", StringComparer.Ordinal) ||
            codes.Contains("reputation.cert.current-feed-match", StringComparer.Ordinal))
            indicators.Add(new ThreatIndicator("reputation.observed-system-event", "matching Windows observation", 4,
                ThreatCategory.SuspiciousNavigation));
        return Evaluate(indicators);
    }

    public static Result Evaluate(IEnumerable<ThreatIndicator> indicators)
    {
        ArgumentNullException.ThrowIfNull(indicators);
        var evidence = indicators
            .Where(indicator => indicator is not null)
            .DistinctBy(indicator => indicator.Id, StringComparer.Ordinal)
            .ToArray();

        if (evidence.Length == 0) return new(0, RiskLevel.Information);

        // Preserve the established evidence/count policy while representing its
        // bands on the requested 0–100 severity scale. This keeps one weak signal
        // from becoming a high alert and requires multiple signals for escalation.
        var totalWeight = evidence.Sum(indicator => Math.Clamp(indicator.Weight, 0, 4));
        if (totalWeight == 0) return new(0, RiskLevel.Information);
        int score;
        if (totalWeight <= 2) score = 20 + totalWeight * 5;
        else if (totalWeight < 7 || evidence.Length < 2)
            score = 40 + Math.Min(19, Math.Max(0, totalWeight - 3) * 4);
        else if (totalWeight < 12 || evidence.Length < 3)
            score = 60 + Math.Min(19, Math.Max(0, totalWeight - 7) * 3);
        else score = 80 + Math.Min(20, (totalWeight - 12) * 3);
        return new(score, LevelForScore(score));
    }

    public static RiskLevel LevelForScore(int score) => Math.Clamp(score, 0, 100) switch
    {
        < 20 => RiskLevel.Information,
        < 40 => RiskLevel.Low,
        < 60 => RiskLevel.Moderate,
        < 80 => RiskLevel.High,
        _ => RiskLevel.Critical
    };

    public static int MinimumScoreForLevel(RiskLevel level) => level switch
    {
        RiskLevel.Information => 0,
        RiskLevel.Low => 20,
        RiskLevel.Moderate => 40,
        RiskLevel.High => 60,
        RiskLevel.Critical => 80,
        _ => throw new ArgumentOutOfRangeException(nameof(level))
    };
}
