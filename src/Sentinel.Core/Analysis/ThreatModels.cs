namespace Sentinel.Core.Analysis;

public enum ThreatCategory { None, SuspiciousNavigation, CredentialPhishing, PaymentFraud, UnsafeExecution, SecurityTampering, SocialEngineering }
public sealed record KnowledgeCitation(string SourceName, int ChunkNumber, string Excerpt);
public sealed record ThreatIndicator(string Id, string Description, int Weight, ThreatCategory Category,
    IReadOnlyList<KnowledgeCitation>? KnowledgeCitations = null);
public sealed record ThreatAssessment(ThreatCategory Category, RiskLevel Risk,
    IReadOnlyList<ThreatIndicator> Indicators, IReadOnlyList<string> Uncertainties,
    IReadOnlyList<string> Recommendations, string Explanation);
public static class AnalysisLimitationCodes
{
    private static readonly (string TextPrefix, string Code)[] Known =
    [
        ("Reguły nie potwierdzają intencji", "analysis.sender-intent-unverified"),
        ("Adresy HTTP/HTTPS zapisane w treści", "analysis.embedded-link-target-unverified"),
        ("Przeanalizowano najwyżej", "analysis.embedded-url-limit"),
        ("Nie ustalono wiarygodnego adresu", "analysis.navigation-target-unverified"),
        ("Podany adres nie jest poprawnym", "analysis.navigation-target-invalid"),
        ("Widoczny tekst linku nie jest", "analysis.displayed-url-invalid"),
        ("Podany cel przekierowania nie jest", "analysis.redirect-target-invalid"),
        ("Treść została ograniczona", "analysis.input-truncated"),
        ("Wynik lokalnego modelu nie jest skalibrowanym", "analysis.ai-not-calibrated"),
        ("Semantyczne porządkowanie lokalnych źródeł było niedostępne", "analysis.semantic-ranking-unavailable"),
        ("Lokalny model AI jest niedostępny lub zwrócił", "analysis.ai-unavailable-rule-only"),
        ("Nieprawidłowy limit czasu modelu", "analysis.ai-timeout-invalid-rule-only")
    ];

    public static IReadOnlyList<string> FromUncertainties(IEnumerable<string> uncertainties)
    {
        ArgumentNullException.ThrowIfNull(uncertainties);
        var codes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var uncertainty in uncertainties)
            foreach (var (prefix, code) in Known)
                if (uncertainty.StartsWith(prefix, StringComparison.Ordinal)) codes.Add(code);
        return codes.Order(StringComparer.Ordinal).ToArray();
    }
}
// A destination must come from an explicit user input or a future trusted navigation provider.
// Text of an arbitrary UI Automation label is NOT evidence of an actual link target.
public sealed record NavigationSignal(string Target, string? DisplayedUrl = null, string? VerifiedRedirectTarget = null);
public sealed record AnalysisContext(string Application, string Text, DateTimeOffset Timestamp,
    NavigationSignal? Navigation = null, string? CorrelationKey = null);
public sealed record UrlAnalysis(bool IsValid, string? Origin, string? Host, string? RegistrableDomain,
    IReadOnlyList<ThreatIndicator> Indicators);
