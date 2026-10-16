using System.Net;
using System.Text;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Knowledge;
using Xunit;

namespace Sentinel.Tests;

[Collection("NetworkAudit")]
public sealed class AIProviderTests
{
    private static readonly string ValidResponse = """
        {"message":{"content":"{\"category\":\"CredentialPhishing\",\"risk\":\"High\",\"indicators\":[\"Prośba o pilne logowanie\"],\"uncertainties\":[\"Nadawca niezweryfikowany\"],\"recommendations\":[\"Zweryfikuj przez oficjalny kanał\"],\"explanation\":\"Treść łączy presję czasu z prośbą o dane.\"}"}}
        """;

    [Fact]
    public async Task OllamaRequestIsLoopbackOnlyAndTreatsContentAsUntrusted()
    {
        HttpRequestMessage? captured = null;
        using var client = new HttpClient(new DelegateHandler(async request =>
        {
            captured = request;
            return Json(ValidResponse);
        }));
        var provider = new OllamaLocalProvider(client);
        var context = new AnalysisContext("Manual", "Pilnie zaloguj się; email alice@example.test password: dont-send-me", DateTimeOffset.UtcNow,
            new NavigationSignal("https://example.test/login?token=private"));
        var result = await provider.AnalyzeAsync("http://127.0.0.1:11434", "synthetic-model", context, []);
        Assert.Equal(RiskLevel.High, result.Risk);
        Assert.NotNull(captured);
        var requestBody = await captured.Content!.ReadAsStringAsync();
        Assert.Contains("niezaufane DANE", requestBody, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"role\":\"system\"", requestBody);
        Assert.DoesNotContain("alice@example.test", requestBody);
        Assert.DoesNotContain("dont-send-me", requestBody);
        Assert.DoesNotContain("token=private", requestBody);
        Assert.DoesNotContain("tools", requestBody, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ListsOnlyModelsActuallyReturnedByLocalOllama()
    {
        var json = """{"models":[{"name":"synthetic:latest","size":1073741824,"details":{"family":"synthetic","parameter_size":"3B","quantization_level":"Q4_K_M"}},{"name":"","size":99}]}""";
        using var client = new HttpClient(new DelegateHandler(_ => Task.FromResult(Json(json))));
        var provider = new OllamaLocalProvider(client);
        var model = Assert.Single(await provider.ListModelsAsync("http://[::1]:11434"));
        Assert.Equal("synthetic:latest", model.Name);
        Assert.Equal(1_073_741_824, model.SizeBytes);
        Assert.Contains("1.0 GB plik", model.DisplayName);
        Assert.Contains("Q4_K_M", model.DisplayName);
    }

    [Theory]
    [InlineData("https://model.example")]
    [InlineData("http://192.0.2.10:11434")]
    [InlineData("http://user:pass@127.0.0.1:11434")]
    [InlineData("http://127.0.0.1:11434/api")]
    public async Task RejectsRemoteOrCredentialBearingModelEndpoints(string endpoint)
    {
        using var client = new HttpClient(new DelegateHandler(_ => throw new Xunit.Sdk.XunitException("HTTP must not be called.")));
        var provider = new OllamaLocalProvider(client);
        await Assert.ThrowsAsync<ArgumentException>(() => provider.ListModelsAsync(endpoint));
    }

    [Fact]
    public async Task RejectsUnstructuredOrUnjustifiedHighRiskModelOutput()
    {
        var response = """{"message":{"content":"{\"category\":\"None\",\"risk\":\"Critical\",\"indicators\":[],\"uncertainties\":[],\"recommendations\":[],\"explanation\":\"Threat detected\"}"}}""";
        using var client = new HttpClient(new DelegateHandler(_ => Task.FromResult(Json(response))));
        var provider = new OllamaLocalProvider(client);
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.AnalyzeAsync("http://localhost:11434", "synthetic-model",
            new AnalysisContext("Synthetic", "Synthetic test input", DateTimeOffset.UtcNow), []));
    }

    [Fact]
    public async Task ModelFailureFallsBackToRulesWithoutLosingTheRuleAssessment()
    {
        var root = Path.Combine(Path.GetTempPath(), "sentinel-ai-fallback-" + Guid.NewGuid().ToString("N"));
        try
        {
            var knowledge = new LocalKnowledgeBase(root);
            await knowledge.InitializeAsync();
            using var client = new HttpClient(new DelegateHandler(_ => Task.FromException<HttpResponseMessage>(new HttpRequestException("Synthetic unavailable"))));
            var service = new AnalysisOrchestrator(new ThreatAnalysisEngine(new UrlAnalyzer(new DomainNames())), new OllamaLocalProvider(client), knowledge);
            var result = await service.AnalyzeAsync(new AnalysisContext("Synthetic", "Pilnie: blokada konta. Zaloguj się.", DateTimeOffset.UtcNow), true,
                "http://127.0.0.1:11434", "missing-local-model");
            Assert.Equal(RiskLevel.Moderate, result.Risk);
            Assert.Contains(result.Indicators, item => item.Id == "text.urgency");
            Assert.Contains(result.Uncertainties, item => item.Contains("użyto wyłącznie reguł", StringComparison.OrdinalIgnoreCase));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private static HttpResponseMessage Json(string content) => new(HttpStatusCode.OK) { Content = new StringContent(content, Encoding.UTF8, "application/json") };

    private sealed class DelegateHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> execute) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => execute(request);
    }
}
