namespace Sentinel.Core.Analysis;

/// <summary>Combines local and Enterprise evidence without accepting a remote risk level unsupported by indicators.</summary>
public static class EnterpriseAssessmentCombiner
{
    public static ThreatAssessment Combine(ThreatAssessment local, ThreatAssessment remote, string? additionalUncertainty = null)
    {
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(remote);
        var indicators = local.Indicators.Concat(remote.Indicators)
            .DistinctBy(indicator => indicator.Id, StringComparer.Ordinal)
            .Take(128).ToArray();
        var result = RiskEngine.Evaluate(indicators);
        var category = indicators.OrderByDescending(indicator => indicator.Weight)
            .Select(indicator => indicator.Category).FirstOrDefault();
        var uncertainties = local.Uncertainties.Concat(remote.Uncertainties)
            .Append(additionalUncertainty)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .OfType<string>()
            .Distinct(StringComparer.Ordinal).Take(64).ToArray();
        var recommendations = local.Recommendations.Concat(remote.Recommendations)
            .Distinct(StringComparer.Ordinal).Take(32).ToArray();
        return new ThreatAssessment(category, result.Level, indicators, uncertainties, recommendations,
            $"Ocena lokalna: {local.Explanation}\n\nOcena Enterprise: {remote.Explanation}", result.Score);
    }
}
