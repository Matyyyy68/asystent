namespace Sentinel.Core.Analysis;

/// <summary>
/// Deterministic evidence aggregation. The numeric score is a rule-derived severity
/// indicator, not a probability or a statistically calibrated likelihood.
/// </summary>
public static class RiskEngine
{
    public sealed record Result(int Score, RiskLevel Level);

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
        var level = score switch
        {
            < 20 => RiskLevel.Information,
            < 40 => RiskLevel.Low,
            < 60 => RiskLevel.Moderate,
            < 80 => RiskLevel.High,
            _ => RiskLevel.Critical
        };
        return new(score, level);
    }
}
