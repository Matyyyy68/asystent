using System.Net;
using System.Text;
using System.Text.Json;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.Core.Knowledge;
using Xunit;

namespace Sentinel.Tests;

[Collection("NetworkAudit")]
public sealed class AIProviderTests
{
    private static readonly string ValidResponse = """
        {"message":{"content":"{\"category\":\"CredentialPhishing\",\"risk\":\"High\",\"indicators\":[{\"description\":\"Prośba o pilne logowanie\",\"sourceReferences\":[]}],\"uncertainties\":[\"Nadawca niezweryfikowany\"],\"recommendations\":[\"Zweryfikuj przez oficjalny kanał\"],\"explanation\":\"Treść łączy presję czasu z prośbą o dane.\"}"}}
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
        Assert.Contains($"{1d:0.0} GB plik", model.DisplayName);
        Assert.Contains("Q4_K_M", model.DisplayName);
    }

    [Fact]
    public async Task EmbeddingsUseOnlyLoopbackAndValidateBatchShape()
    {
        HttpRequestMessage? captured = null;
        using var client = new HttpClient(new DelegateHandler(async request =>
        {
            captured = request;
            return Json("""{"embeddings":[[1,0],[0,1]]}""");
        }));
        var provider = new OllamaLocalProvider(client);
        var vectors = await provider.EmbedAsync("http://127.0.0.1:11434", "synthetic-embed", ["query", "document"]);
        Assert.Equal("/api/embed", captured!.RequestUri!.AbsolutePath);
        Assert.Equal(2, vectors.Count);
        Assert.Equal(new[] { 1f, 0f }, vectors[0]);

        using var invalidClient = new HttpClient(new DelegateHandler(_ => Task.FromResult(Json("""{"embeddings":[[1,0],[0,1,2]]}"""))));
        var invalidProvider = new OllamaLocalProvider(invalidClient);
        await Assert.ThrowsAsync<InvalidDataException>(() => invalidProvider.EmbedAsync("http://localhost:11434", "synthetic-embed", ["query", "document"]));
    }

    [Fact]
    public async Task EmbeddingRerankingMovesTheMostSimilarLexicalCandidateIntoAIContext()
    {
        string? chatRequest = null;
        string? embeddingRequest = null;
        using var client = new HttpClient(new DelegateHandler(async request =>
        {
            if (request.RequestUri!.AbsolutePath == "/api/embed")
            {
                embeddingRequest = await request.Content!.ReadAsStringAsync();
                return Json("""{"embeddings":[[1,0],[0,1],[1,0]]}""");
            }
            chatRequest = await request.Content!.ReadAsStringAsync();
            return Json("""{"message":{"content":"{\"category\":\"CredentialPhishing\",\"risk\":\"High\",\"indicators\":[{\"description\":\"Zweryfikuj zasady\",\"sourceReferences\":[1]}],\"uncertainties\":[],\"recommendations\":[],\"explanation\":\"Źródło opisuje weryfikację zgłoszenia.\"}"}}""");
        }));
        var provider = new OllamaLocalProvider(client);
        var candidates = new TestKnowledgeProvider(
        [
            new KnowledgeHit("doc-a", "lexical-first.txt", 0, "payment transfer details password: kb-secret-value", -2.0),
            new KnowledgeHit("doc-b", "semantic-match.txt", 0, "verify identity through the official support channel", -1.0)
        ]);
        var orchestrator = new AnalysisOrchestrator(new ThreatAnalysisEngine(new UrlAnalyzer(new DomainNames())), provider, candidates);
        var result = await orchestrator.AnalyzeAsync(new AnalysisContext("Synthetic", "Review this payment transfer request.", DateTimeOffset.UtcNow),
            true, "http://127.0.0.1:11434", "synthetic-chat", "synthetic-embed");

        Assert.Equal(RiskLevel.High, result.Risk);
        Assert.NotNull(embeddingRequest);
        Assert.DoesNotContain("kb-secret-value", embeddingRequest, StringComparison.Ordinal);
        Assert.Contains("[dane poufne]", embeddingRequest, StringComparison.Ordinal);
        Assert.NotNull(chatRequest);
        using var sent = JsonDocument.Parse(chatRequest);
        var context = sent.RootElement.GetProperty("messages")[1].GetProperty("content").GetString();
        Assert.Contains("Źródło 1: semantic-match.txt", context, StringComparison.Ordinal);
        Assert.Contains(result.Uncertainties, text => text.Contains("semantic-match.txt", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task LongAnalysisTextUsesBoundedKnowledgeQueryAndStillReachesLocalModel()
    {
        using var client = new HttpClient(new DelegateHandler(_ => Task.FromResult(Json(ValidResponse))));
        var knowledge = new TestKnowledgeProvider([]);
        var orchestrator = new AnalysisOrchestrator(new ThreatAnalysisEngine(new UrlAnalyzer(new DomainNames())),
            new OllamaLocalProvider(client), knowledge);
        await orchestrator.AnalyzeAsync(new AnalysisContext("Synthetic", string.Concat(Enumerable.Repeat("ordinary words ", 400)), DateTimeOffset.UtcNow),
            true, "http://127.0.0.1:11434", "synthetic-chat");
        Assert.Equal(4000, knowledge.LastQuery?.Length);
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

    [Fact]
    public async Task LocalKnowledgeHitsAreRetrievedAndIncludedInTheOllamaAnalysisContext()
    {
        var root = Path.Combine(Path.GetTempPath(), "sentinel-ai-knowledge-context-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root);
            var document = Path.Combine(root, "credential-policy.txt");
            await File.WriteAllTextAsync(document,
                "Credential transfer requests must be paused and verified through the official support channel.", Encoding.UTF8);
            var knowledge = new LocalKnowledgeBase(Path.Combine(root, "index"));
            await knowledge.InitializeAsync();
            await knowledge.ImportAsync(document);
            Assert.NotEmpty(await knowledge.SearchAsync("Review this credential transfer request."));

            string? requestBody = null;
            using var client = new HttpClient(new DelegateHandler(async request =>
            {
                requestBody = await request.Content!.ReadAsStringAsync();
                return Json("""{"message":{"content":"{\"category\":\"CredentialPhishing\",\"risk\":\"High\",\"indicators\":[{\"description\":\"Zweryfikuj kanał obsługi\",\"sourceReferences\":[1]}],\"uncertainties\":[\"Nadawca niezweryfikowany\"],\"recommendations\":[\"Zweryfikuj przez oficjalny kanał\"],\"explanation\":\"Treść prosi o weryfikację przelewu.\"}"}}""");
            }));
            var service = new AnalysisOrchestrator(new ThreatAnalysisEngine(new UrlAnalyzer(new DomainNames())),
                new OllamaLocalProvider(client), knowledge);
            var result = await service.AnalyzeAsync(new AnalysisContext("Synthetic", "Review this credential transfer request.", DateTimeOffset.UtcNow), true,
                "http://127.0.0.1:11434", "synthetic-model");

            Assert.Equal(RiskLevel.High, result.Risk);
            Assert.NotNull(requestBody);
            using var sent = JsonDocument.Parse(requestBody);
            var userContent = sent.RootElement.GetProperty("messages")[1].GetProperty("content").GetString();
            Assert.Contains("verified through the official support channel", userContent, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Lokalne źródła wiedzy", userContent, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(result.Uncertainties, value => value.Contains("credential-policy.txt", StringComparison.OrdinalIgnoreCase));
            var citedIndicator = Assert.Single(result.Indicators, item => item.Id == "ai.context.0");
            var citation = Assert.Single(citedIndicator.KnowledgeCitations!);
            Assert.Equal("credential-policy.txt", citation.SourceName);
            Assert.Contains("official support channel", citation.Excerpt, StringComparison.OrdinalIgnoreCase);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public async Task RejectsModelCitationsOutsideRetrievedKnowledgeSources()
    {
        var response = """{"message":{"content":"{\"category\":\"CredentialPhishing\",\"risk\":\"High\",\"indicators\":[{\"description\":\"Prośba o dane\",\"sourceReferences\":[2]}],\"uncertainties\":[],\"recommendations\":[],\"explanation\":\"Wiadomość prosi o dane.\"}"}}""";
        using var client = new HttpClient(new DelegateHandler(_ => Task.FromResult(Json(response))));
        var provider = new OllamaLocalProvider(client);
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.AnalyzeAsync("http://localhost:11434", "synthetic-model",
            new AnalysisContext("Synthetic", "Synthetic test input", DateTimeOffset.UtcNow), []));
    }

    [Fact]
    public async Task RejectsNullModelIndicatorInsteadOfFailingAnalysisUnexpectedly()
    {
        var response = """{"message":{"content":"{\"category\":\"None\",\"risk\":\"Low\",\"indicators\":[null],\"uncertainties\":[],\"recommendations\":[],\"explanation\":\"Brak dodatkowych sygnałów.\"}"}}""";
        using var client = new HttpClient(new DelegateHandler(_ => Task.FromResult(Json(response))));
        var provider = new OllamaLocalProvider(client);
        await Assert.ThrowsAsync<InvalidDataException>(() => provider.AnalyzeAsync("http://localhost:11434", "synthetic-model",
            new AnalysisContext("Synthetic", "Synthetic test input", DateTimeOffset.UtcNow), []));
    }

    private static HttpResponseMessage Json(string content) => new(HttpStatusCode.OK) { Content = new StringContent(content, Encoding.UTF8, "application/json") };

    private sealed class TestKnowledgeProvider(IReadOnlyList<KnowledgeHit> hits) : IKnowledgeBaseProvider
    {
        public string? LastQuery { get; private set; }
        public Task<IReadOnlyList<KnowledgeDocument>> ListAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<KnowledgeDocument>>([]);
        public Task<KnowledgeDocument> ImportAsync(string filePath, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<KnowledgeHit>> SearchAsync(string query, int limit = 5, CancellationToken cancellationToken = default)
        {
            LastQuery = query;
            return Task.FromResult<IReadOnlyList<KnowledgeHit>>(hits.Take(limit).ToArray());
        }
        public Task<bool> DeleteAsync(string documentId, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task BackupAsync(string destination, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<int> RestoreAsync(string backupPath, CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class DelegateHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> execute) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => execute(request);
    }
}
