using Sentinel.Core;
using Sentinel.Core.Analysis;

namespace Sentinel.UrlHost;

public sealed class BrowserHistoryRecorder
{
    private readonly NotificationDeduplicator deduplicator = new(TimeSpan.FromMinutes(10), 512);
    private readonly string pointer;

    public BrowserHistoryRecorder(string? pointerPath = null) => pointer = pointerPath ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelAI", "data-path.txt");

    public async Task<bool> RecordAsync(BrowserResponse result, CancellationToken cancellationToken = default)
    {
        if (!result.ShouldWarn || result.HistoryKey is not { Length: 64 } key) return false;

        if (!File.Exists(pointer)) return false;
        var directory = (await File.ReadAllTextAsync(pointer, cancellationToken)).Trim();
        if (directory.Length is 0 or > 4096 || directory.StartsWith('\\') || !Path.IsPathFullyQualified(directory)) return false;
        var database = Path.Combine(directory, "sentinel.db");
        if (!File.Exists(database)) return false;
        if (!deduplicator.TryMark(key, DateTimeOffset.UtcNow)) return false;

        var store = new LocalStore(directory);
        var risk = Enum.Parse<RiskLevel>(result.Risk, ignoreCase: false);
        var explanation = string.Join(" ", result.Indicators.Select(i => i.Description).Distinct());
        if (explanation.Length == 0) return false;
        var item = new SecurityEvent(0, DateTimeOffset.UtcNow, risk, $"Przeglądarka · {result.Category}", "Rozszerzenie Sentinel AI",
            explanation[..Math.Min(explanation.Length, 2000)],
            "Nie podawaj danych i zweryfikuj adres przez niezależny, znany kanał.", EventStatus.New,
            Source: "browser-extension", RuleVersion: ThreatAnalysisEngine.RulesVersion);
        await store.AddLocalOnlyAsync(item, cancellationToken);
        try
        {
            var settings = await store.LoadSettingsAsync(cancellationToken);
            await store.ApplyRetentionAsync(settings.RetentionDays, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or Microsoft.Data.Sqlite.SqliteException)
        { /* History event was recorded; retention will run in the desktop app. */ }
        return true;
    }
}
