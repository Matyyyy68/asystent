namespace Sentinel.Server.Core;

public sealed record SecurityEventInput(string EventId, DateTimeOffset OccurredAt, string Category, int RiskLevel, string RuleCode,
    string Source = "unknown", string? RuleVersion = null, int SchemaVersion = 1);
public sealed record SecurityEvent(string EventId, string DeviceId, DateTimeOffset OccurredAt, DateTimeOffset ReceivedAt,
    string Category, int RiskLevel, string RuleCode, string Status, string Source, string? RuleVersion, int SchemaVersion);
public sealed record EventBatchResult(int Accepted, int Duplicates);
public static class SecurityEventRules
{
    private static readonly string[] Categories = ["url", "message", "document", "attachment", "sender", "login"];
    private static readonly HashSet<string> Sources = new(StringComparer.Ordinal)
    {
        "browser-extension", "dns-cache", "downloads-local-hash", "manual-analysis",
        "process-snapshot", "tcp-connection-snapshot", "udp-endpoint-snapshot", "unknown"
    };
    public static string? Validate(SecurityEventInput item, DateTimeOffset now)
    {
        if (item is null) return "Brak danych zdarzenia.";
        if (!Guid.TryParse(item.EventId, out _)) return "eventId musi być identyfikatorem GUID.";
        if (item.OccurredAt > now.AddMinutes(5) || item.OccurredAt < now.AddDays(-30)) return "occurredAt może być najwyżej 5 minut w przyszłości i 30 dni wstecz.";
        if (!Categories.Contains(item.Category, StringComparer.Ordinal)) return "Nieobsługiwana kategoria zdarzenia.";
        if (item.RiskLevel is < 0 or > 4) return "riskLevel musi mieć wartość 0–4.";
        if (item.RuleCode is null || item.RuleCode.Length is < 1 or > 80 || item.RuleCode.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-')))
            return "ruleCode może zawierać wyłącznie litery ASCII, cyfry, kropkę, podkreślenie i myślnik (1–80 znaków).";
        if (item.Source is null || !Sources.Contains(item.Source)) return "Nieobsługiwane źródło zdarzenia.";
        if (item.RuleVersion is { } version && (version.Length is < 1 or > 80 || version.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-'))))
            return "ruleVersion może zawierać wyłącznie litery ASCII, cyfry, kropkę, podkreślenie i myślnik (1–80 znaków).";
        if (item.SchemaVersion != 1) return "Nieobsługiwana wersja schematu zdarzenia.";
        return null;
    }
}
