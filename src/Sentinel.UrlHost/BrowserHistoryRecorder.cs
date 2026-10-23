using Sentinel.Core;
using Sentinel.Core.Analysis;

namespace Sentinel.UrlHost;

public sealed class BrowserHistoryRecorder
{
    private readonly string pointer;

    public BrowserHistoryRecorder(string? pointerPath = null) => pointer = pointerPath ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelAI", "data-path.txt");

    public async Task<bool> RecordAsync(BrowserResponse result, CancellationToken cancellationToken = default)
    {
        if (!result.ShouldWarn || result.HistoryKey is not { Length: 64 }) return false;

        if (!File.Exists(pointer)) return false;
        var directory = (await File.ReadAllTextAsync(pointer, cancellationToken)).Trim();
        if (directory.Length is 0 or > 4096 || directory.StartsWith('\\') || !Path.IsPathFullyQualified(directory)) return false;
        var database = Path.Combine(directory, "sentinel.db");
        if (!File.Exists(database)) return false;
        var store = new LocalStore(directory);
        await store.InitializeAsync(cancellationToken);
        var observedAt = DateTimeOffset.UtcNow;
        Guid? correlationId = result.CorrelationDomain is { } domain
            ? await store.GetDomainCorrelationIdAsync(domain, observedAt, ct: cancellationToken)
            : null;
        var risk = Enum.Parse<RiskLevel>(result.Risk, ignoreCase: false);
        var explanation = string.Join(" ", result.Indicators.Select(i => i.Description).Distinct());
        if (explanation.Length == 0) return false;
        var item = new SecurityEvent(0, observedAt, risk, $"Przeglądarka · {result.Category}", "Rozszerzenie Sentinel AI",
            explanation[..Math.Min(explanation.Length, 2000)],
            "Nie podawaj danych i zweryfikuj adres przez niezależny, znany kanał.", EventStatus.New,
            Source: "browser-extension", RuleVersion: ThreatAnalysisEngine.RulesVersion, CorrelationId: correlationId,
            EvidenceCodes: result.Indicators.Select(i => i.Id).Distinct(StringComparer.Ordinal).Take(32).ToArray(),
            SignalHash: result.SignalHash);
        if (!await store.AddLocalOnlyDeduplicatedAsync(item, TimeSpan.FromMinutes(10), cancellationToken)) return false;
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
