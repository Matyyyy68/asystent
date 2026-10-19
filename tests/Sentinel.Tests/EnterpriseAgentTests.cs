using System.Net;
using System.Text;
using Sentinel.Core.Enterprise;
using Xunit;

namespace Sentinel.Tests;

[Collection("NetworkAudit")]
public sealed class EnterpriseAgentTests
{
    [Fact]
    public void EnterprisePolicyParsesValidatedEffectiveSettings()
    {
        using var json = System.Text.Json.JsonDocument.Parse("""{"globalVersion":4,"effective":{"analysisMode":"local","analysisIntervalSeconds":45,"aiProvider":"disabled","notificationLevel":"important","excludedApplications":["browser.exe"],"syncIntervalSeconds":600}}""");
        var policy = EnterprisePolicy.Parse(json);
        Assert.Equal(4, policy.Version);
        Assert.Equal(45, policy.AnalysisIntervalSeconds);
        Assert.Equal(600, policy.SyncIntervalSeconds);
        Assert.Equal("browser.exe", Assert.Single(policy.ExcludedApplications));
    }

    [Theory]
    [InlineData("""{"globalVersion":1,"effective":{"analysisMode":"local","analysisIntervalSeconds":1,"aiProvider":"disabled","notificationLevel":"important","excludedApplications":[],"syncIntervalSeconds":300}}""")]
    [InlineData("""{"globalVersion":1,"effective":{"analysisMode":"hybrid","analysisIntervalSeconds":5,"aiProvider":"disabled","notificationLevel":"important","excludedApplications":["bad;name"],"syncIntervalSeconds":300}}""")]
    public void EnterprisePolicyRejectsUnsafeOrOutOfRangeValues(string source)
    {
        using var json = System.Text.Json.JsonDocument.Parse(source);
        Assert.Throws<InvalidDataException>(() => EnterprisePolicy.Parse(json));
    }

    [Theory]
    [InlineData("http://sentinel.example")]
    [InlineData("https://user:secret@sentinel.example")]
    [InlineData("https://sentinel.example/api/v1")]
    [InlineData("https://sentinel.example/?token=secret")]
    public void ServerAddressRejectsUnsafeForms(string value) => Assert.Throws<ArgumentException>(() => EnterpriseAgentClient.ValidateServer(value));

    [Fact]
    public async Task EnrollmentUsesHttpsAndSendsOnlyOneTimeCodeAndDeviceMetadata()
    {
        HttpRequestMessage? observed = null;
        var handler = new DelegateHandler(async request =>
        {
            observed = request;
            Assert.Equal("https", request.RequestUri!.Scheme);
            return Json(HttpStatusCode.Created, """{"deviceId":"device-1","deviceToken":"012345678901234567890123456789012345678901234567890123456789","group":"Test","registeredAt":"2026-01-01T00:00:00Z"}""");
        });
        using var http = new HttpClient(handler);
        var client = new EnterpriseAgentClient(http);
        var version = typeof(EnterpriseAgentClient).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        var result = await client.EnrollAsync(EnterpriseAgentClient.ValidateServer("https://sentinel.example"), "invite-code", "PC-01", version);
        Assert.Equal("device-1", result.DeviceId);
        Assert.Equal(HttpMethod.Post, observed!.Method);
        Assert.Contains("invite-code", await observed.Content!.ReadAsStringAsync());
    }

    [Fact]
    public async Task EventSynchronizationSendsOnlyMetadataAndBearerCredential()
    {
        string? body = null;
        var handler = new DelegateHandler(async request =>
        {
            Assert.Equal("Bearer 012345678901234567890123456789012345678901234567890123456789", request.Headers.Authorization!.ToString());
            Assert.Equal("https://sentinel.example/api/v1/agents/events", request.RequestUri!.AbsoluteUri);
            body = await request.Content!.ReadAsStringAsync();
            return Json(HttpStatusCode.OK, """{"accepted":1,"duplicates":0}""");
        });
        using var http = new HttpClient(handler);
        var client = new EnterpriseAgentClient(http);
        var input = new PendingEnterpriseEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "url", 3, "local.url");
        var result = await client.SendEventsAsync(EnterpriseAgentClient.ValidateServer("https://sentinel.example"),
            "012345678901234567890123456789012345678901234567890123456789", [input]);
        Assert.Equal(1, result.Accepted);
        Assert.Contains(input.EventId.ToString("D"), body);
        Assert.DoesNotContain("explanation", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EventSynchronizationRejectsIncompleteServerAcknowledgement()
    {
        var handler = new DelegateHandler(_ => Task.FromResult(Json(HttpStatusCode.OK, """{"accepted":0,"duplicates":0}""")));
        using var http = new HttpClient(handler);
        var client = new EnterpriseAgentClient(http);
        var item = new PendingEnterpriseEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, "url", 3, "local.url");
        await Assert.ThrowsAsync<InvalidDataException>(() => client.SendEventsAsync(EnterpriseAgentClient.ValidateServer("https://sentinel.example"),
            "012345678901234567890123456789012345678901234567890123456789", [item]));
    }

    [Fact]
    public async Task CredentialRotationStagesClientGeneratedTokenOverAuthenticatedHttps()
    {
        var handler = new DelegateHandler(async request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://sentinel.example/api/v1/agents/credentials/rotate", request.RequestUri!.AbsoluteUri);
            Assert.Equal("Bearer 012345678901234567890123456789012345678901234567890123456789", request.Headers.Authorization!.ToString());
            Assert.Contains("replacement-device-token-12345678901234567890", await request.Content!.ReadAsStringAsync());
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });
        using var http = new HttpClient(handler);
        var client = new EnterpriseAgentClient(http);
        await client.RotateCredentialAsync(EnterpriseAgentClient.ValidateServer("https://sentinel.example"),
            "012345678901234567890123456789012345678901234567890123456789", "replacement-device-token-12345678901234567890");
    }

    [Fact]
    public async Task WindowsCredentialStoreProtectsTokenAtRestAndSupportsDelete()
    {
        if (!OperatingSystem.IsWindows()) return;
        var directory = Path.Combine(Path.GetTempPath(), "sentinel-dpapi-" + Guid.NewGuid().ToString("N"));
        const string token = "device-token-01234567890123456789012345678901234567890123456789";
        try
        {
            var credentials = new WindowsDpapiCredentialStore(directory);
            Assert.Null(await credentials.ReadAsync());
            try { await credentials.WriteAsync(token); }
            catch (System.Security.Cryptography.CryptographicException ex) when (ex.Message.Contains("error 2", StringComparison.Ordinal))
            { return; } // Restricted runners without a loaded Windows user profile cannot exercise DPAPI; verified separately in the interactive context.
            var path = Path.Combine(directory, "enterprise-credential.bin");
            Assert.DoesNotContain(token, Encoding.UTF8.GetString(await File.ReadAllBytesAsync(path)), StringComparison.Ordinal);
            Assert.Equal(token, await credentials.ReadAsync());
            await credentials.DeleteAsync();
            Assert.Null(await credentials.ReadAsync());
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string content) => new(status)
    { Content = new StringContent(content, Encoding.UTF8, "application/json") };

    private sealed class DelegateHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => callback(request);
    }
}
