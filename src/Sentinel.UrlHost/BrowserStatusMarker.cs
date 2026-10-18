using System.Text.Json;

namespace Sentinel.UrlHost;

internal static class BrowserStatusMarker
{
    public static async Task TouchAsync(string browser, bool enabled, CancellationToken cancellationToken)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelAI");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, $"browser-{browser}.json");
        var temporary = path + "." + Environment.ProcessId + ".new";
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(new Status(DateTimeOffset.UtcNow, enabled)), cancellationToken);
        File.Move(temporary, path, overwrite: true);
    }

    private sealed record Status(DateTimeOffset LastContactUtc, bool Enabled);
}
