using System.Net;
using System.Text;
using Sentinel.Core.Enterprise;
using Xunit;

namespace Sentinel.Tests;

[Collection("NetworkAudit")]
public sealed class EnterpriseAgentTests
{
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

    private static HttpResponseMessage Json(HttpStatusCode status, string content) => new(status)
    { Content = new StringContent(content, Encoding.UTF8, "application/json") };

    private sealed class DelegateHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => callback(request);
    }
}
