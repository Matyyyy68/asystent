namespace Sentinel.Contracts;

/// <summary>Privacy-minimal event contract shared by the Windows client and Enterprise API.</summary>
public sealed record EnterpriseEventV1(
    Guid EventId,
    DateTimeOffset OccurredAt,
    string Category,
    int RiskLevel,
    string RuleCode,
    string Source = "unknown",
    string? RuleVersion = null,
    int SchemaVersion = 1);

public sealed record EnterpriseEventBatchV1(IReadOnlyList<EnterpriseEventV1>? Events);

public sealed record EnterpriseEventBatchResultV1(int Accepted, int Duplicates);

public static class EnterpriseEventV1Rules
{
    private static readonly HashSet<string> Categories = new(StringComparer.Ordinal)
        { "url", "message", "document", "attachment", "sender", "login" };
    private static readonly HashSet<string> Sources = new(StringComparer.Ordinal)
    {
        "browser-extension", "dns-cache", "downloads-local-hash", "manual-analysis",
        "process-snapshot", "tcp-connection-snapshot", "udp-endpoint-snapshot", "unknown"
    };

    public static string NormalizeSource(string? source) => source is not null && Sources.Contains(source) ? source : "unknown";

    public static string? NormalizeRuleVersion(string? version) => version is { Length: > 0 and <= 80 } &&
        version.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-') ? version : null;

    public static string? Validate(EnterpriseEventV1? item, DateTimeOffset now)
    {
        if (item is null) return "Brak danych zdarzenia.";
        if (item.EventId == Guid.Empty) return "eventId musi być niepustym identyfikatorem GUID.";
        if (item.OccurredAt > now.AddMinutes(5) || item.OccurredAt < now.AddDays(-30)) return "occurredAt może być najwyżej 5 minut w przyszłości i 30 dni wstecz.";
        if (!Categories.Contains(item.Category)) return "Nieobsługiwana kategoria zdarzenia.";
        if (item.RiskLevel is < 0 or > 4) return "riskLevel musi mieć wartość 0–4.";
        if (!IsSafeCode(item.RuleCode, 80)) return "ruleCode może zawierać wyłącznie litery ASCII, cyfry, kropkę, podkreślenie i myślnik (1–80 znaków).";
        if (item.Source is null || !Sources.Contains(item.Source)) return "Nieobsługiwane źródło zdarzenia.";
        if (item.RuleVersion is { } version && !IsSafeCode(version, 80))
            return "ruleVersion może zawierać wyłącznie litery ASCII, cyfry, kropkę, podkreślenie i myślnik (1–80 znaków).";
        if (item.SchemaVersion != 1) return "Nieobsługiwana wersja schematu zdarzenia.";
        return null;
    }

    private static bool IsSafeCode(string? value, int maximum) => value is { Length: >= 1 } && value.Length <= maximum &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');
}
