using Sentinel.Core;
using Sentinel.Core.Analysis;

namespace Sentinel.Engine;

public interface IWindowsDefenderOperationalLogSource
{
    Task<bool> IsEnabledAsync(CancellationToken cancellationToken = default);
    Task<long?> ReadLatestRecordIdAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<WindowsDefenderOperationalEvent>> ReadAfterAsync(long recordId,
        CancellationToken cancellationToken = default);
}

public sealed record WindowsDefenderOperationalCollectionResult(int EventsRead,
    IReadOnlyList<Guid> AlertEventIds, string Status);

/// <summary>Persists normalized Defender events locally and advances a restart-safe Event Log cursor.</summary>
public sealed class WindowsDefenderOperationalCollector(LocalStore store, IWindowsDefenderOperationalLogSource source)
{
    public async Task<WindowsDefenderOperationalCollectionResult> CollectAsync(CancellationToken cancellationToken = default)
    {
        if (!await source.IsEnabledAsync(cancellationToken))
            return new(0, [], "Dziennik Microsoft Defender Operational jest wyłączony; nie zmieniono konfiguracji systemu");

        var cursor = await store.GetWindowsDefenderOperationalRecordCursorAsync(cancellationToken);
        var latestRecordId = await source.ReadLatestRecordIdAsync(cancellationToken);
        if (cursor is null)
        {
            await store.SetWindowsDefenderOperationalRecordCursorAsync(latestRecordId ?? 0, cancellationToken);
            return new(0, [], "Dziennik Defender aktywny; ustawiono początkowy punkt odczytu");
        }
        if (latestRecordId is null)
        {
            await store.SetWindowsDefenderOperationalRecordCursorAsync(0, cancellationToken);
            return new(0, [], "Dziennik Defender pusty lub wyczyszczony; ustawiono nowy punkt odczytu");
        }

        var logWasReset = latestRecordId.Value < cursor.Value;
        cursor = WindowsDefenderOperationalEventParser.ResolveCursorAfterLogReset(cursor.Value, latestRecordId.Value);
        var records = await source.ReadAfterAsync(cursor.Value, cancellationToken);
        var alertEventIds = new List<Guid>();
        foreach (var record in records)
        {
            var (risk, score, category, explanation, recommendation, evidence) = Describe(record);
            var eventId = WindowsDefenderOperationalEventParser.CreateEventId(record);
            await store.AddLocalOnlyAsync(new SecurityEvent(0, record.Timestamp, risk, category,
                "Microsoft Defender Antivirus", explanation, recommendation, EventStatus.New,
                EventId: eventId, Source: "windows-defender-operational", RuleVersion: ThreatAnalysisEngine.RulesVersion,
                Confidence: 100, EvidenceCodes: [evidence], RiskScore: score), cancellationToken);
            if (ServiceEventNotificationPolicy.ShouldNotify(risk.ToString()))
                alertEventIds.Add(eventId);
        }

        if (records.Count > 0)
            await store.SetWindowsDefenderOperationalRecordCursorAsync(records[^1].RecordId, cancellationToken);
        var state = $"Dziennik Defender działa; odczytano {records.Count} nowych zdarzeń" +
            (logWasReset ? " po wykryciu resetu dziennika" : "");
        return new(records.Count, alertEventIds, state);
    }

    private static (RiskLevel Risk, int Score, string Category, string Explanation, string Recommendation, string Evidence)
        Describe(WindowsDefenderOperationalEvent item)
    {
        if (item.EventId == 1116)
        {
            var (risk, score) = item.SeverityName?.ToLowerInvariant() switch
            {
                "severe" => (RiskLevel.Critical, 95), "high" => (RiskLevel.High, 80),
                "moderate" => (RiskLevel.Moderate, 60), "low" => (RiskLevel.Low, 35),
                _ => (RiskLevel.Moderate, 55)
            };
            var threat = item.ThreatName ?? "nazwa niedostępna";
            return (risk, score, "Wykrycie Microsoft Defender",
                $"Microsoft Defender zgłosił wykrycie: {threat} (poziom: {item.SeverityName ?? "nieznany"}). Ścieżka pliku i konto użytkownika nie są zapisywane.",
                "Sprawdź stan ochrony i historię zagrożeń w aplikacji Zabezpieczenia Windows. Sentinel nie wykonuje działania na pliku.",
                "windows.defender.detection");
        }
        if (item.EventId == 1117)
            return (RiskLevel.Information, 15, "Działanie Microsoft Defender",
                $"Microsoft Defender zgłosił podjęcie działania ({item.ActionName ?? "szczegóły niedostępne"}). Sentinel nie wykonuje ani nie potwierdza tej akcji.",
                "Sprawdź wynik w historii ochrony Microsoft Defender.", "windows.defender.action-reported");
        if (item.EventId is 1118 or 1119)
            return (RiskLevel.High, 75, "Błąd działania Microsoft Defender",
                $"Microsoft Defender zgłosił błąd podczas działania ({item.ActionStatus ?? "szczegóły niedostępne"}). Ścieżka pliku i konto użytkownika nie są zapisywane.",
                "Sprawdź historię ochrony i stan Microsoft Defender w Zabezpieczeniach Windows.", "windows.defender.action-failed");
        if (item.EventId == 5007)
            return (RiskLevel.Information, 10, "Zmiana konfiguracji Microsoft Defender",
                "Microsoft Defender zgłosił zmianę konfiguracji. Poprzednia i nowa wartość nie są zapisywane.",
                "Jeśli zmiana jest nieoczekiwana, sprawdź historię ochrony i ustawienia Zabezpieczeń Windows.",
                "windows.defender.configuration-changed");
        return (RiskLevel.High, 75, "Błąd silnika Microsoft Defender",
            "Microsoft Defender zgłosił błąd silnika ochrony.", "Sprawdź stan Microsoft Defender w Zabezpieczeniach Windows.",
            "windows.defender.engine-failed");
    }
}
