using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentinel.Core.Analysis;

public sealed record ReleaseUpdateCheck(Version InstalledVersion, Version LatestVersion, string Tag, bool UpdateAvailable)
{
    public string ReleaseUrl => $"https://github.com/Matyyyy68/asystent/releases/tag/{Tag}";
}

/// <summary>Checks GitHub's public latest-release endpoint without downloading or executing assets.</summary>
public static partial class GitHubReleaseUpdateChecker
{
    public const string LatestReleaseApi = "https://api.github.com/repos/Matyyyy68/asystent/releases/latest";
    private const int MaximumResponseBytes = 64 * 1024;

    [GeneratedRegex("^v?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex ReleaseTagPattern();

    public static async Task<ReleaseUpdateCheck> CheckAsync(HttpClient client, Version installedVersion,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(installedVersion);
        if (installedVersion.Build < 0 || installedVersion.Revision > 0)
            throw new ArgumentException("Installed version must use major.minor.patch form.", nameof(installedVersion));
        installedVersion = new Version(installedVersion.Major, installedVersion.Minor, installedVersion.Build);

        using var request = new HttpRequestMessage(HttpMethod.Get, LatestReleaseApi);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        request.Headers.UserAgent.ParseAdd("SentinelAI-UpdateCheck/1.0");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode is not HttpStatusCode.OK)
            throw new HttpRequestException($"GitHub update check returned HTTP {(int)response.StatusCode}.");
        if (response.Content.Headers.ContentLength is > MaximumResponseBytes)
            throw new InvalidDataException("GitHub release metadata exceeded the response limit.");

        var payload = await ReadBoundedAsync(response.Content, cancellationToken);
        using var document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("tag_name", out var tagElement) || tagElement.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("GitHub response does not describe a release.");
        if (root.TryGetProperty("draft", out var draft) && draft.ValueKind is JsonValueKind.True ||
            root.TryGetProperty("prerelease", out var prerelease) && prerelease.ValueKind is JsonValueKind.True)
            throw new InvalidDataException("GitHub returned a draft or prerelease where a stable release was expected.");

        var tag = tagElement.GetString() ?? string.Empty;
        var match = ReleaseTagPattern().Match(tag);
        if (!match.Success || !Version.TryParse($"{match.Groups[1].Value}.{match.Groups[2].Value}.{match.Groups[3].Value}", out var latestVersion))
            throw new InvalidDataException("GitHub release tag is not a stable three-part version.");

        return new(installedVersion, latestVersion, tag, latestVersion > installedVersion);
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken);
            if (read == 0) break;
            if (buffer.Length + read > MaximumResponseBytes)
                throw new InvalidDataException("GitHub release metadata exceeded the response limit.");
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }
}
