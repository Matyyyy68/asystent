# PLAN-003 — pliki i reputacja

1. **Cel:** na jawne żądanie oceniać wybrany plik przez hash, podpis i audytowane źródło reputacji.
2. **Stan obecny:** `Sentinel.Engine` na jawne żądanie otwiera wybrany plik do 256 MiB tylko do odczytu, liczy SHA-256, zwraca status Authenticode i sprawdza dokładne dopasowanie do lokalnej listy hashy zaimportowanej przez użytkownika. Brak listy i brak dopasowania nie są werdyktem bezpieczeństwa; źródło listy nie jest niezależnie weryfikowane.
3. **Braki:** walidacja i ocena zaufania podpisu, audytowane źródło hashy, wskazanie pochodzenia każdego wpisu, pliki pobrane i monitorowanie lokalizacji.
4. **Decyzje:** najpierw ręczny skan; brak automatycznego odczytu prywatnych katalogów; bieżący feed jest lokalny i ręcznie dostarczony, bez łączności sieciowej. Ewentualne zewnętrzne źródło wymaga osobnego audytu licencji, świeżości i prawdziwości.
5. **Zależności:** podpis Authenticode/WinVerifyTrust, feed hashy/licencja, model zdarzeń.
6. **Etapy:** (a) ograniczenie rozmiaru, uchwyt tylko do odczytu i TOCTOU — wdrożone; (b) sprawdzenie Authenticode przez izolowany Windows PowerShell bez ładowania profili — wdrożone; (c) lokalny provider dokładnych SHA-256 z limitem 20 MiB/250 000 wpisów i atomową walidacją — wdrożony; (d) ręczny wybór pliku do skanu i listy — wdrożone; (e) audytowany, aktualizowany feed i opcjonalny, ograniczony monitoring Downloads — pozostają.
7. **Pliki:** engine file case, nowy core file analyzer/provider, UI, testy.
8. **Prywatność:** hash jest pseudonimizującym identyfikatorem; nie wysyłać automatycznie nazw/ścieżek/plików.
9. **Testy:** syntetyczny hash dopasowany w lokalnej bazie przez Engine IPC; testy .NET obejmują dokładne dopasowanie, brak feedu, brak dopasowania, deduplikację, walidację i zachowanie poprzedniej listy po nieprawidłowym imporcie. Skan pliku fixture sprawdza SHA-256 i `NotSigned`. Limit rozmiaru pliku 256 MiB jest wdrożony; pełne graniczne testy i fixture podpisu nadal brakują.
10. **Akceptacja:** brak listy lub brak dopasowania nigdy nie daje „bezpieczny”; UI pokazuje brak niezależnej weryfikacji źródła; import jest lokalny, atomowy i ograniczony.
11. **Ryzyka:** podpis legalny nie dowodzi bezpieczeństwa; nieznany plik nie dowodzi malware; feed ma licencję/false positive.
12. **Status:** `IN_PROGRESS` — ręczne SHA-256/Authenticode oraz lokalna lista hashy działają i przechodzą .NET/Engine IPC; UI importuje listę jawnie. Brak audytowanego feedu, walidacji zaufania podpisu i monitorowania pobrań.

