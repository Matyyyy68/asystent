using System.Text.Json;

namespace Sentinel.UrlHost;

internal static class BrowserStatusMarker
{
    public static async Task TouchAsync(CancellationToken cancellationToken)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelAI");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "browser-integration.json");
        var temporary = path + "." + Environment.ProcessId + ".new";
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(new Status(DateTimeOffset.UtcNow)), cancellationToken);
        File.Move(temporary, path, overwrite: true);
    }

    private sealed record Status(DateTimeOffset LastContactUtc);
}
