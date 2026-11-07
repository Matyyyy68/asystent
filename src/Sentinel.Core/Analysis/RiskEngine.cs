namespace Sentinel.Core.Analysis;

/// <summary>
/// Deterministic evidence aggregation. The numeric score is a rule-derived severity
/// indicator, not a probability or a statistically calibrated likelihood.
/// </summary>
public static class RiskEngine
{
    private const int MaximumRawEvidenceItems = 1024;
    private const int MaximumDistinctEvidenceIndicators = 256;

    public sealed record Result(int Score, RiskLevel Level);

    public enum ResponseAction
    {
        RecordOnly,
        ReviewInHistory,
        NotifyForReview,
        UrgentReview
    }

    public sealed record ResponseDecision(
        ResponseAction Action,
        string Code,
        string Guidance,
        bool AutomaticProtectionPerformed);

    /// <summary>
    /// Chooses a proportionate, auditable response from the evidence-derived risk.
    /// Current response capabilities are notification and user-directed review;
    /// this policy never claims that a process or connection was blocked.
    /// </summary>
    public static ResponseDecision DecideResponse(RiskLevel risk)
    {
        if (!Enum.IsDefined(risk)) throw new ArgumentOutOfRangeException(nameof(risk));
        return risk switch
        {
            RiskLevel.Information => new(ResponseAction.RecordOnly, "response.record-only",
                "Zapisz zdarzenie w historii; powiadomienia zależą od ustawień i typu źródła.", false),
            RiskLevel.Low => new(ResponseAction.ReviewInHistory, "response.review-in-history",
                "Pozostaw w historii do weryfikacji użytkownika.", false),
            RiskLevel.Moderate => new(ResponseAction.NotifyForReview, "response.notify-review",
                "Zalecany alert i sprawdzenie zdarzenia przez użytkownika.", false),
            RiskLevel.High => new(ResponseAction.UrgentReview, "response.high-review",
                "Zalecany pilny alert i sprawdzenie szczegółów; proces lub ruch nie zostały zablokowane.", false),
            RiskLevel.Critical => new(ResponseAction.UrgentReview, "response.critical-review",
                "Zalecany natychmiastowy alert i ręczna ocena dostępnych działań; automatyczna blokada nie została wykonana.", false),
            _ => throw new ArgumentOutOfRangeException(nameof(risk))
        };
    }

    /// <summary>Attaches the deterministic response recommendation once before an event is persisted.</summary>
    public static SecurityEvent ApplyResponseDecision(SecurityEvent item)
    {
        ArgumentNullException.ThrowIfNull(item);
        var decision = DecideResponse(item.Risk);
        var marker = $"({decision.Code})";
        if ((item.Recommendation ?? string.Empty).Contains(marker, StringComparison.Ordinal))
            return item;

        var suffix = $" Zalecenie Sentinel {marker}: {decision.Guidance}";
        const int maximumRecommendationCharacters = 1000;
        var recommendation = item.Recommendation ?? string.Empty;
        if (recommendation.Length + suffix.Length > maximumRecommendationCharacters)
            recommendation = recommendation[..Math.Max(0, maximumRecommendationCharacters - suffix.Length)].TrimEnd();
        return item with { Recommendation = recommendation + suffix };
    }

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
        var allCodeSet = new HashSet<string>(StringComparer.Ordinal);
        var rawCodeCount = 0;
        foreach (var code in evidenceCodes)
        {
            if (++rawCodeCount > MaximumRawEvidenceItems)
                throw new ArgumentException($"Evidence exceeded the maximum of {MaximumRawEvidenceItems} items.", nameof(evidenceCodes));
            if (code is not null) allCodeSet.Add(code);
        }
        var allCodes = allCodeSet.ToArray();
        var codes = allCodes.Where(EventEvidence.ContainsKey).ToArray();
        // A local file hash list with unverified provenance is not sufficient
        // evidence to assign a numeric risk score.
        if (allCodes.Contains("file.local-list-source-unverified", StringComparer.Ordinal))
            codes = codes.Where(code => code != "file.sha256.matches-local-list").ToArray();
        // A user-imported IP list has no trusted provenance/signature contract.
        // Preserve the match as event context, but do not let it raise numeric risk.
        if (allCodes.Contains("reputation.local-ip-feed-source-unverified", StringComparer.Ordinal))
            codes = codes.Where(code => code != "reputation.ip-feed.match").ToArray();
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
        var uniqueEvidence = new List<ThreatIndicator>(MaximumDistinctEvidenceIndicators);
        var evidenceIds = new HashSet<string>(StringComparer.Ordinal);
        var rawEvidenceCount = 0;
        foreach (var indicator in indicators)
        {
            if (++rawEvidenceCount > MaximumRawEvidenceItems)
                throw new ArgumentException($"Evidence exceeded the maximum of {MaximumRawEvidenceItems} items.", nameof(indicators));
            if (indicator is null || string.IsNullOrWhiteSpace(indicator.Id) || !evidenceIds.Add(indicator.Id)) continue;
            if (uniqueEvidence.Count == MaximumDistinctEvidenceIndicators)
                throw new ArgumentException($"Evidence exceeded the maximum of {MaximumDistinctEvidenceIndicators} distinct indicators.", nameof(indicators));
            uniqueEvidence.Add(indicator);
        }
        var evidence = uniqueEvidence.ToArray();

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
