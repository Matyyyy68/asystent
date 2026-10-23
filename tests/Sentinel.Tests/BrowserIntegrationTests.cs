using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Sentinel.Core;
using Sentinel.Core.Analysis;
using Sentinel.UrlHost;
using Xunit;

namespace Sentinel.Tests;

public sealed class BrowserIntegrationTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "sentinel-browser-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task NativeMessagingUsesLittleEndianLengthPrefixAndRoundTrips()
    {
        var input = new MemoryStream();
        var payload = Encoding.UTF8.GetBytes("{\"id\":\"test\",\"type\":\"status\"}");
        await NativeMessagingProtocol.WriteAsync(input, payload);
        input.Position = 0;
        var header = new byte[4];
        await input.ReadExactlyAsync(header);
        Assert.Equal((uint)payload.Length, BinaryPrimitives.ReadUInt32LittleEndian(header));
        input.Position = 0;
        Assert.Equal(payload, await NativeMessagingProtocol.ReadAsync(input));
        Assert.Null(await NativeMessagingProtocol.ReadAsync(input));
    }

    [Fact]
    public async Task NativeMessagingRejectsOversizedAndIncompleteFrames()
    {
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(header, NativeMessagingProtocol.MaximumMessageBytes + 1u);
        await Assert.ThrowsAsync<InvalidDataException>(() => NativeMessagingProtocol.ReadAsync(new MemoryStream(header)));
        await Assert.ThrowsAsync<EndOfStreamException>(() => NativeMessagingProtocol.ReadAsync(new MemoryStream([1, 0])));
    }

    [Fact]
    public async Task NativeHostEndToEndAnalyzesNavigationAndReturnsLocalWarning()
    {
        var url = "https://example.test/account/verify-and-confirm-password?continue=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var request = JsonSerializer.SerializeToUtf8Bytes(new BrowserRequest("navigation-1", "analyze", url, "chrome"));
        var input = new MemoryStream();
        await NativeMessagingProtocol.WriteAsync(input, request);
        input.Position = 0;
        var output = new MemoryStream();

        await Program.ServeAsync(input, output, enableHostSideEffects: false);
        output.Position = 0;
        var response = JsonSerializer.Deserialize<BrowserResponse>(await NativeMessagingProtocol.ReadAsync(output)!);
        Assert.NotNull(response);
        Assert.True(response.Available);
        Assert.True(response.ShouldWarn);
        Assert.Equal("2026.10.8", response.RulesVersion);
        Assert.Equal("Moderate", response.Risk);
        Assert.Contains(response.Indicators, item => item.Id == "url.auth_structure");
        var serialized = JsonSerializer.Serialize(response);
        Assert.DoesNotContain(url, serialized);
        Assert.DoesNotContain("example.test", serialized);
    }

    [Fact]
    public void BrowserWarningCatchesUserInfoThatHidesTheDestinationHost()
    {
        var requestUrl = "https://paypal.com@attacker.test/login";
        var response = new UrlRequestProcessor().Process(new BrowserRequest("userinfo-1", "analyze", requestUrl));

        Assert.True(response.ShouldWarn);
        Assert.Equal("Moderate", response.Risk);
        Assert.Contains(response.Indicators, item => item.Id == "url.userinfo");
        Assert.Equal(LocalStore.CreateUrlEvidenceSignalHash("attacker.test", response.Indicators.Select(item => item.Id)), response.SignalHash);
        Assert.DoesNotContain("attacker.test", JsonSerializer.Serialize(response));
    }

    [Fact]
    public void BrowserWarningMatchesExactLocalUrlFeedWithoutReturningUrlOrHost()
    {
        var url = "https://bad.example.test/login?campaign=synthetic";
        var reputation = new UrlReputation(directory);
        reputation.Import(url + "\n", DateTimeOffset.UtcNow);
        var response = new UrlRequestProcessor(urlReputation: reputation)
            .Process(new BrowserRequest("url-feed-1", "analyze", url, "chrome"));

        Assert.True(response.ShouldWarn);
        Assert.Equal("High", response.Risk);
        Assert.Contains(response.Indicators, item => item.Id == "reputation.url-feed");
        Assert.Equal(UrlReputation.CreateSignalHash(url), response.SignalHash);
        var serialized = JsonSerializer.Serialize(response);
        Assert.DoesNotContain(url, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("bad.example.test", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(response.SignalHash!, serialized, StringComparison.Ordinal);
    }

    [Fact]
    public void BrowserWarningMatchesListedDomainSubdomainWithoutReturningHost()
    {
        var reputation = new DomainReputation(directory);
        reputation.Import("listed.test", DateTimeOffset.UtcNow);
        const string url = "https://shop.listed.test/login";

        var response = new UrlRequestProcessor(reputation)
            .Process(new BrowserRequest("cert-subdomain-1", "analyze", url, "chrome"));

        Assert.True(response.ShouldWarn);
        Assert.Equal("High", response.Risk);
        Assert.Contains(response.Indicators, item => item.Id == "reputation.cert");
        Assert.DoesNotContain(url, JsonSerializer.Serialize(response), StringComparison.Ordinal);
        Assert.DoesNotContain("listed.test", JsonSerializer.Serialize(response), StringComparison.Ordinal);
    }

    [Fact]
    public void ProcessorWarnsOnDeceptiveBrandAndDoesNotReturnSubmittedUrl()
    {
        var url = "https://paypal.com.evil.test/login?email=private@example.test";
        var result = new UrlRequestProcessor().Process(new BrowserRequest("tab-1", "analyze", url));
        Assert.True(result.Available);
        Assert.True(result.ShouldWarn);
        Assert.NotEmpty(result.Indicators);
        var serialized = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("evil.test", serialized);
        Assert.DoesNotContain("private@example.test", serialized);
        Assert.DoesNotContain("CorrelationDomain", serialized);
    }

    [Fact]
    public void InvalidSchemesAndUnrelatedTrustedBrandsDoNotCreateWarnings()
    {
        var processor = new UrlRequestProcessor();
        Assert.False(processor.Process(new BrowserRequest("1", "analyze", "file:///etc/passwd")).ShouldWarn);
        Assert.False(processor.Process(new BrowserRequest("2", "analyze", "https://news.paypal.com/")).ShouldWarn);
    }

    [Fact]
    public async Task BrowserEventsAreLocalAndNeverEnterEnterpriseQueue()
    {
        Directory.CreateDirectory(directory);
        var store = new LocalStore(directory);
        await store.InitializeAsync();
        var pointer = Path.Combine(directory, "data-path.txt");
        await File.WriteAllTextAsync(pointer, directory);
        var result = new BrowserResponse("1", true, ThreatAnalysisEngine.RulesVersion, "Moderate", "SuspiciousNavigation", true,
            [new BrowserIndicator("url.brand", "Domena przypomina znaną markę.")], "Niepewny adres.", new string('a', 64), "Sygnał lokalny.", "login.example.test",
            new string('b', 64));
        var recorder = new BrowserHistoryRecorder(pointer);

        Assert.True(await recorder.RecordAsync(result));
        var restartedRecorder = new BrowserHistoryRecorder(pointer);
        Assert.False(await restartedRecorder.RecordAsync(result with { Id = "2" }));
        Assert.True(await restartedRecorder.RecordAsync(result with { Id = "3", HistoryKey = new string('c', 64), SignalHash = new string('d', 64) }));
        var events = await store.ReadAsync();
        Assert.Equal(2, events.Count);
        var eventRow = Assert.Single(events, item => item.SignalHash == new string('B', 64));
        Assert.Equal("Przeglądarka · SuspiciousNavigation", eventRow.Category);
        Assert.Equal("browser-extension", eventRow.Source);
        Assert.Equal(ThreatAnalysisEngine.RulesVersion, eventRow.RuleVersion);
        Assert.Equal(1, eventRow.SchemaVersion);
        Assert.NotEqual(Guid.Empty, eventRow.EventId);
        Assert.NotNull(eventRow.CorrelationId);
        Assert.Contains("url.brand", eventRow.EvidenceCodes!);
        Assert.Equal(new[] { AnalysisLimitationCodes.BrowserRedirectChainUnverified }, eventRow.AnalysisLimitations);
        Assert.DoesNotContain("paypal", eventRow.Explanation, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await store.ReadPendingEnterpriseEventsAsync());
    }

    [Fact]
    public async Task CorruptDataDirectoryPointerDisablesBrowserHistoryWithoutCreatingFallbackData()
    {
        Directory.CreateDirectory(directory);
        var pointer = Path.Combine(directory, "data-path.txt");
        await File.WriteAllTextAsync(pointer, new string('x', DataDirectoryPointer.MaximumPointerBytes + 1));
        var fallback = Path.Combine(directory, "data");
        var result = new BrowserResponse("1", true, ThreatAnalysisEngine.RulesVersion, "Moderate", "SuspiciousNavigation", true,
            [new BrowserIndicator("url.brand", "Domena przypomina markę.")], "Niepewny adres.", new string('a', 64), "Sygnał lokalny.", "login.example.test",
            new string('b', 64));

        Assert.False(await new BrowserHistoryRecorder(pointer).RecordAsync(result));
        Assert.False(Directory.Exists(fallback));
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
