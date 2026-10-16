namespace Sentinel.Core.Analysis;

public enum ThreatCategory { None, SuspiciousNavigation, CredentialPhishing, PaymentFraud, UnsafeExecution, SecurityTampering, SocialEngineering }
public sealed record ThreatIndicator(string Id, string Description, int Weight, ThreatCategory Category);
public sealed record ThreatAssessment(ThreatCategory Category, RiskLevel Risk,
    IReadOnlyList<ThreatIndicator> Indicators, IReadOnlyList<string> Uncertainties,
    IReadOnlyList<string> Recommendations, string Explanation);
// A destination must come from an explicit user input or a future trusted navigation provider.
// Text of an arbitrary UI Automation label is NOT evidence of an actual link target.
public sealed record NavigationSignal(string Target, string? DisplayedUrl = null, string? VerifiedRedirectTarget = null);
public sealed record AnalysisContext(string Application, string Text, DateTimeOffset Timestamp,
    NavigationSignal? Navigation = null, string? CorrelationKey = null);
public sealed record UrlAnalysis(bool IsValid, string? Origin, string? Host, string? RegistrableDomain,
    IReadOnlyList<ThreatIndicator> Indicators);
