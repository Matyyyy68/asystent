using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Text;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Context;

namespace Sentinel.UrlHost;

public sealed record BrowserRequest([property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("url")] string? Url = null,
    [property: JsonPropertyName("browser")] string Browser = "unknown",
    [property: JsonPropertyName("enabled")] bool Enabled = true);

public sealed record BrowserIndicator([property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("description")] string Description);

public sealed record BrowserResponse([property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("available")] bool Available,
    [property: JsonPropertyName("rulesVersion")] string RulesVersion,
    [property: JsonPropertyName("risk")] string Risk,
    [property: JsonPropertyName("category")] string Category,
    [property: JsonPropertyName("shouldWarn")] bool ShouldWarn,
    [property: JsonPropertyName("indicators")] IReadOnlyList<BrowserIndicator> Indicators,
    [property: JsonPropertyName("uncertainty")] string Uncertainty,
    [property: JsonIgnore] string? HistoryKey = null,
    [property: JsonIgnore] string? Explanation = null,
    [property: JsonIgnore] string? CorrelationDomain = null);

public sealed class UrlRequestProcessor
{
    private readonly UrlAnalyzer urls;
    private readonly ThreatAnalysisEngine engine;
    private readonly DomainReputation? reputation;
    public UrlRequestProcessor(DomainReputation? reputation = null)
    {
        this.reputation = reputation;
        urls = new UrlAnalyzer(new DomainNames());
        engine = new ThreatAnalysisEngine(urls);
    }

    public BrowserResponse Process(BrowserRequest request)
    {
        if (request.Browser is not ("unknown" or "chrome" or "edge")) throw new InvalidDataException("Nieznana przeglądarka.");
        if (string.IsNullOrWhiteSpace(request.Id) || request.Id.Length > 100 || request.Id.Any(char.IsControl))
            throw new InvalidDataException("Nieprawidłowy identyfikator żądania.");
        if (request.Type == "status") return new(request.Id, true, ThreatAnalysisEngine.RulesVersion,
            "Information", "None", false, [], "Lokalny silnik reguł jest dostępny.");
        if (request.Type != "analyze" || request.Url is null || request.Url.Length > 4096)
            throw new InvalidDataException("Nieprawidłowe żądanie analizy adresu.");

        var context = new AnalysisContext("Browser extension", "", DateTimeOffset.UtcNow, new NavigationSignal(request.Url));
        var result = engine.Analyze(context);
        var analysis = urls.Analyze(request.Url);
        if (analysis.Host is { } host && reputation?.Contains(host, DateTimeOffset.UtcNow) == true)
            result = result with { Risk = RiskLevel.High, Category = ThreatCategory.SuspiciousNavigation,
                Indicators = result.Indicators.Append(new ThreatIndicator("reputation.cert", "Domena znajduje się na aktualnej liście CERT Polska.", 10, ThreatCategory.SuspiciousNavigation)).ToArray() };
        var historyKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{analysis.Origin}|{string.Join(',', result.Indicators.Select(x => x.Id).Order(StringComparer.Ordinal))}")));
        return new(request.Id, true, ThreatAnalysisEngine.RulesVersion, result.Risk.ToString(), result.Category.ToString(),
            result.Risk >= RiskLevel.Moderate && result.Indicators.Count != 0,
            result.Indicators.Select(i => new BrowserIndicator(i.Id, i.Description)).ToArray(),
            result.Uncertainties.FirstOrDefault() ?? "Wynik nie potwierdza bezpieczeństwa adresu.", historyKey, result.Explanation,
            analysis.RegistrableDomain ?? analysis.Host);
    }
}
