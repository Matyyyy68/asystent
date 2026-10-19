# PLAN-003 — pliki i reputacja

1. **Cel:** na jawne żądanie oceniać wybrany plik przez hash, podpis i audytowane źródło reputacji.
2. **Stan obecny:** `Sentinel.Engine` na jawne żądanie otwiera wybrany plik do 256 MiB tylko do odczytu, liczy SHA-256 i zwraca status Authenticode (`Valid`, `NotSigned`, błędny/niezaufany lub `Unknown`). Nie wydaje werdyktu bezpieczeństwa; brak reputacji i automatycznego monitorowania.
3. **Braki:** walidacja podpisu, allow/deny źródło, pliki pobrane i monitorowanie lokalizacji.
4. **Decyzje:** najpierw ręczny skan; brak automatycznego odczytu prywatnych katalogów; reputacja zewnętrzna wyłącznie po świadomym opt-in i bez wysyłania pliku.
5. **Zależności:** podpis Authenticode/WinVerifyTrust, feed hashy/licencja, model zdarzeń.
6. **Etapy:** (a) ograniczenie rozmiaru, uchwyt tylko do odczytu i TOCTOU — wdrożone; (b) sprawdzenie Authenticode przez izolowany Windows PowerShell bez ładowania profili — wdrożone; (c) provider reputacji z `unknown` jako wynik; (d) UX zgody/źródeł — częściowo, ręczny wybór pliku; (e) opcjonalny ograniczony monitoring Downloads.
7. **Pliki:** engine file case, nowy core file analyzer/provider, UI, testy.
8. **Prywatność:** hash jest pseudonimizującym identyfikatorem; nie wysyłać automatycznie nazw/ścieżek/plików.
9. **Testy:** hash znanego fixture, limit 0/256 MiB/większy, brak dostępu, sygnatura fixture i sieć wyłączona.
10. **Akceptacja:** żaden hash bez feedu nie daje „bezpieczny”; źródło i świeżość werdyktu są widoczne.
11. **Ryzyka:** podpis legalny nie dowodzi bezpieczeństwa; nieznany plik nie dowodzi malware; feed ma licencję/false positive.
12. **Status:** `IN_PROGRESS` — hash i Authenticode działają na żądanie i przechodzą Engine IPC z syntetycznym niepodpisanym plikiem. Brak audytowanego feedu reputacji i monitorowania pobrań.

