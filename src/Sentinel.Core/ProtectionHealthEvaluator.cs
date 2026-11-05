namespace Sentinel.Core;

public sealed record ProtectionHealthSnapshot(string State, string Title, string Description,
    DateTimeOffset CheckedAtUtc, IReadOnlyList<string> Limitations);

/// <summary>Builds the truthful top-level engine status from current component health.</summary>
public static class ProtectionHealthEvaluator
{
    private static readonly string[] UnavailableMarkers = ["niedostęp", "nie działa", "wstrzyman", "błąd", "error", "unavailable", "not started"];

    public static ProtectionHealthSnapshot Evaluate(AppSettings settings, DateTimeOffset? lastCollectionAtUtc,
        DateTimeOffset now, IReadOnlyDictionary<string, string?> sourceStates, string? antivirus, string? firewall)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(sourceStates);
        var checkedAt = now.ToUniversalTime();
        if (settings.Paused)
            return new("DISABLED", "Ochrona wstrzymana", "Monitorowanie zostało wstrzymane. Bieżąca ochrona nie jest potwierdzona.", checkedAt, ["monitoring-paused"]);
        if (lastCollectionAtUtc is null)
            return new("INITIALIZING", "Inicjalizacja ochrony", "Silnik nie zakończył jeszcze poprawnego cyklu monitorowania.", checkedAt, ["collection-not-completed"]);

        var staleAfter = TimeSpan.FromSeconds(Math.Clamp(settings.MinimumIntervalSeconds * 3, 30, 900));
        if (lastCollectionAtUtc.Value > checkedAt || checkedAt - lastCollectionAtUtc.Value > staleAfter)
            return new("ATTENTION_REQUIRED", "Wymagana uwaga", "Ostatni poprawny cykl monitorowania jest nieaktualny.", checkedAt, ["collection-stale"]);

        var limitations = new List<string>();
        Check("processes", "Procesy", enabled: true);
        Check("processEvents", "Zdarzenia startu procesów", enabled: true);
        Check("downloadedFiles", "Pobrane pliki", settings.MonitorDownloadedFiles);
        Check("persistence", "Zmiany autostartu", settings.MonitorPersistenceChanges);
        Check("tcpConnections", "Połączenia sieciowe", settings.MonitorNetworkConnections);
        Check("dns", "Cache DNS", enabled: true);
        CheckWindows("Antywirus Windows", antivirus);
        CheckWindows("Zapora Windows", firewall);

        if (limitations.Any(item => item.StartsWith("security:", StringComparison.Ordinal)))
        {
            var names = limitations.Where(item => item.StartsWith("security:", StringComparison.Ordinal))
                .Select(item => item[9..]).ToArray();
            return new("ATTENTION_REQUIRED", "Wymagana uwaga",
                "Windows Security Center zgłasza problem albo nie potwierdza stanu: " + string.Join(", ", names) + ". Sentinel nie zmienia ustawień zabezpieczeń Windows.",
                checkedAt, limitations);
        }

        var monitorLimitations = limitations.Where(item => !item.StartsWith("security:", StringComparison.Ordinal)).ToArray();
        return monitorLimitations.Length > 0
            ? new("LIMITED_PROTECTION", "Ochrona ograniczona",
                "Nie działa lub nie jest włączone: " + string.Join(", ", monitorLimitations) + ". Pozostałe źródła mogą nadal działać.", checkedAt, limitations)
            : new("LIMITED_PROTECTION", "Monitorowanie działa · zakres ograniczony",
                "Dostępne źródła monitorowania działają. Sentinel nie blokuje procesów ani ruchu i nie zastępuje Microsoft Defender.",
                checkedAt, ["no-process-or-network-blocking", "snapshot-and-feed-limitations"]);

        void Check(string key, string label, bool enabled)
        {
            if (!enabled) { limitations.Add(label); return; }
            if (!sourceStates.TryGetValue(key, out var state) || string.IsNullOrWhiteSpace(state) ||
                UnavailableMarkers.Any(marker => state.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                limitations.Add(label);
        }

        void CheckWindows(string label, string? state)
        {
            if (string.IsNullOrWhiteSpace(state) || state.Contains("wymaga uwagi", StringComparison.OrdinalIgnoreCase) ||
                state.Contains("wstrzymane", StringComparison.OrdinalIgnoreCase) ||
                state.Contains("nie jest monitorowane", StringComparison.OrdinalIgnoreCase) ||
                !state.Contains("stan dobry", StringComparison.OrdinalIgnoreCase))
                limitations.Add("security:" + label);
        }
    }
}
