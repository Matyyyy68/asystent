namespace Sentinel.Server.Core;

public sealed record SecurityEventInput(string EventId, DateTimeOffset OccurredAt, string Category, int RiskLevel, string RuleCode);
public sealed record SecurityEvent(string EventId, string DeviceId, DateTimeOffset OccurredAt, DateTimeOffset ReceivedAt,
    string Category, int RiskLevel, string RuleCode, string Status);
public sealed record EventBatchResult(int Accepted, int Duplicates);
public static class SecurityEventRules
{
    private static readonly string[] Categories = ["url", "message", "document", "attachment", "sender", "login"];
    public static string? Validate(SecurityEventInput item, DateTimeOffset now)
    {
        if (!Guid.TryParse(item.EventId, out _)) return "eventId musi być identyfikatorem GUID.";
        if (item.OccurredAt > now.AddMinutes(5) || item.OccurredAt < now.AddDays(-30)) return "occurredAt może być najwyżej 5 minut w przyszłości i 30 dni wstecz.";
        if (!Categories.Contains(item.Category, StringComparer.Ordinal)) return "Nieobsługiwana kategoria zdarzenia.";
        if (item.RiskLevel is < 0 or > 4) return "riskLevel musi mieć wartość 0–4.";
        if (item.RuleCode.Length is < 1 or > 80 || item.RuleCode.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-')))
            return "ruleCode może zawierać wyłącznie litery ASCII, cyfry, kropkę, podkreślenie i myślnik (1–80 znaków).";
        return null;
    }
}
