using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentinel.Core.Enterprise;

public sealed record EnterprisePolicy(long Version, string AnalysisMode, int AnalysisIntervalSeconds,
    string AiProvider, string NotificationLevel, IReadOnlyList<string> ExcludedApplications, int SyncIntervalSeconds)
{
    public static EnterprisePolicy Parse(JsonDocument document)
    {
        var root = document.RootElement;
        if (!root.TryGetProperty("effective", out var effective) || effective.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("globalVersion", out var globalVersion) || !globalVersion.TryGetInt64(out var version) || version < 0)
            throw new InvalidDataException("Konfiguracja Enterprise nie zawiera poprawnej polityki ani wersji.");
        var mode = RequiredString(effective, "analysisMode");
        var provider = RequiredString(effective, "aiProvider");
        var notifications = RequiredString(effective, "notificationLevel");
        var interval = RequiredInt(effective, "analysisIntervalSeconds", 3, 3600);
        var sync = RequiredInt(effective, "syncIntervalSeconds", 30, 86400);
        if (mode is not ("local" or "server" or "hybrid") || provider is not ("disabled" or "ollama") ||
            notifications is not ("history" or "important" or "all"))
            throw new InvalidDataException("Polityka Enterprise zawiera nieobsługiwaną wartość.");
        if (!effective.TryGetProperty("excludedApplications", out var excluded) || excluded.ValueKind != JsonValueKind.Array || excluded.GetArrayLength() > 200)
            throw new InvalidDataException("Polityka Enterprise zawiera nieprawidłową listę wykluczeń.");
        var apps = excluded.EnumerateArray().Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : null).ToArray();
        if (apps.Any(app => app is null || app.Length is < 1 or > 64 || !Regex.IsMatch(app, "^[a-zA-Z0-9._-]+$", RegexOptions.CultureInvariant)))
            throw new InvalidDataException("Polityka Enterprise zawiera nieprawidłową nazwę aplikacji.");
        return new(version, mode, interval, provider, notifications, apps.Select(x => x!).ToArray(), sync);
    }

    private static string RequiredString(JsonElement source, string name) =>
        source.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()! : throw new InvalidDataException($"Brak pola polityki {name}.");

    private static int RequiredInt(JsonElement source, string name, int min, int max) =>
        source.TryGetProperty(name, out var value) && value.TryGetInt32(out var number) && number >= min && number <= max
            ? number : throw new InvalidDataException($"Nieprawidłowe pole polityki {name}.");
}
