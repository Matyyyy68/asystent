using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Sentinel.Core;
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
        var request = JsonSerializer.SerializeToUtf8Bytes(new BrowserRequest("navigation-1", "analyze", "https://paypal.com.evil.test/login"));
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
        Assert.Contains(response.Indicators, item => item.Id == "url.brand");
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
        var result = new BrowserResponse("1", true, "2026.10.1", "Moderate", "SuspiciousNavigation", true,
            [new BrowserIndicator("url.brand", "Domena przypomina znaną markę.")], "Niepewny adres.", new string('a', 64), "Sygnał lokalny.");
        var recorder = new BrowserHistoryRecorder(pointer);

        Assert.True(await recorder.RecordAsync(result));
        Assert.False(await recorder.RecordAsync(result with { Id = "2" }));
        var eventRow = Assert.Single(await store.ReadAsync());
        Assert.Equal("Przeglądarka · SuspiciousNavigation", eventRow.Category);
        Assert.Equal("browser-extension", eventRow.Source);
        Assert.Equal("2026.10.1", eventRow.RuleVersion);
        Assert.Equal(1, eventRow.SchemaVersion);
        Assert.NotEqual(Guid.Empty, eventRow.EventId);
        Assert.DoesNotContain("paypal", eventRow.Explanation, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(await store.ReadPendingEnterpriseEventsAsync());
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
