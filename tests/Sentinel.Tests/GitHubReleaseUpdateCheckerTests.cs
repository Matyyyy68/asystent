using System.Net;
using System.Text;
using Sentinel.Core.Analysis;
using Xunit;

namespace Sentinel.Tests;

public sealed class GitHubReleaseUpdateCheckerTests
{
    [Fact]
    public async Task ReportsNewStableVersionAndBuildsOnlyTheFixedReleaseUrl()
    {
        var handler = new StubHandler(_ => Json("""
            {"tag_name":"v0.15.40","draft":false,"prerelease":false}
            """));
        using var client = new HttpClient(handler);

        var result = await GitHubReleaseUpdateChecker.CheckAsync(client, new Version(0, 15, 39, 0));

        Assert.True(result.UpdateAvailable);
        Assert.Equal(new Version(0, 15, 39), result.InstalledVersion);
        Assert.Equal(new Version(0, 15, 40), result.LatestVersion);
        Assert.Equal("https://github.com/Matyyyy68/asystent/releases/tag/v0.15.40", result.ReleaseUrl);
        Assert.Equal(GitHubReleaseUpdateChecker.LatestReleaseApi, handler.LastRequestUri?.ToString());
        Assert.Equal("SentinelAI-UpdateCheck", handler.LastUserAgent);
    }

    [Fact]
    public async Task ReportsCurrentWhenLatestTagIsNotNewer()
    {
        using var client = new HttpClient(new StubHandler(_ => Json(
            "{\"tag_name\":\"0.15.39\",\"draft\":false,\"prerelease\":false}")));

        var result = await GitHubReleaseUpdateChecker.CheckAsync(client, new Version(0, 15, 39));

        Assert.False(result.UpdateAvailable);
        Assert.Equal("0.15.39", result.Tag);
    }

    [Theory]
    [InlineData("{\"tag_name\":\"v0.15.40-beta.1\"}")]
    [InlineData("{\"tag_name\":\"https://evil.test/installer.exe\"}")]
    [InlineData("{\"tag_name\":\"v0.15.40\",\"draft\":true}")]
    [InlineData("[]")]
    public async Task RejectsMalformedOrUnstableReleaseMetadata(string json)
    {
        using var client = new HttpClient(new StubHandler(_ => Json(json)));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            GitHubReleaseUpdateChecker.CheckAsync(client, new Version(0, 15, 39)));
    }

    [Fact]
    public async Task RejectsRedirectInsteadOfFollowingAnUntrustedReleaseEndpoint()
    {
        using var client = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Redirect)
        {
            Headers = { Location = new Uri("https://evil.test/releases") }
        }));

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            GitHubReleaseUpdateChecker.CheckAsync(client, new Version(0, 15, 39)));
    }

    private static HttpResponseMessage Json(string value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(value, Encoding.UTF8, "application/json")
    };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        public Uri? LastRequestUri { get; private set; }
        public string? LastUserAgent { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri;
            LastUserAgent = request.Headers.UserAgent.FirstOrDefault()?.Product?.Name;
            return Task.FromResult(response(request));
        }
    }
}
