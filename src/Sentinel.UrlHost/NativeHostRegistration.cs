using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace Sentinel.UrlHost;

internal static class NativeHostRegistration
{
    private const string HostName = "com.sentinelai.urlcheck";
    private const string ExtensionId = "nakmencmekkefmcddpihiiohjgabfemg";
    private const string ManifestFile = "com.sentinelai.urlcheck.json";
    private static readonly string[] RegistryKeys =
    [
        $@"Software\Google\Chrome\NativeMessagingHosts\{HostName}",
        $@"Software\Microsoft\Edge\NativeMessagingHosts\{HostName}"
    ];

    [SupportedOSPlatform("windows")]
    public static void Register()
    {
        var executable = Path.Combine(AppContext.BaseDirectory, "Sentinel.UrlHost.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException("Brak hosta integracji przeglądarki.", executable);
        var manifestPath = Path.Combine(AppContext.BaseDirectory, ManifestFile);
        var manifest = new HostManifest(HostName, "Sentinel AI local URL analysis", executable, "stdio",
            [$"chrome-extension://{ExtensionId}/"]);
        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        var temporary = manifestPath + ".new";
        File.WriteAllText(temporary, json);
        File.Move(temporary, manifestPath, overwrite: true);
        foreach (var path in RegistryKeys)
        {
            using var key = Registry.CurrentUser.CreateSubKey(path, writable: true)
                ?? throw new UnauthorizedAccessException("Nie można zarejestrować hosta Native Messaging dla bieżącego użytkownika.");
            key.SetValue(null, manifestPath, RegistryValueKind.String);
        }
    }

    [SupportedOSPlatform("windows")]
    public static void Unregister()
    {
        foreach (var path in RegistryKeys)
        {
            using var key = Registry.CurrentUser.OpenSubKey(path, writable: true);
            key?.DeleteValue("", throwOnMissingValue: false);
            if (key is not null && key.ValueCount == 0 && key.SubKeyCount == 0)
                Registry.CurrentUser.DeleteSubKey(path, throwOnMissingSubKey: false);
        }
        var manifest = Path.Combine(AppContext.BaseDirectory, ManifestFile);
        if (File.Exists(manifest)) File.Delete(manifest);
        var temporary = manifest + ".new";
        if (File.Exists(temporary)) File.Delete(temporary);
    }

    private sealed record HostManifest(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("description")] string Description,
        [property: JsonPropertyName("path")] string Path,
        [property: JsonPropertyName("type")] string Type,
        [property: JsonPropertyName("allowed_origins")] string[] AllowedOrigins);
}
