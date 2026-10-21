# PLAN-002 — DNS i threat intelligence

1. **Cel:** jasno raportować świeżość źródeł i wiarygodne zdarzenia DNS/reputacji z mierzalnym opóźnieniem.
2. **Stan obecny:** `DomainReputation` importuje feed CERT ręcznie do SQLite, obsługuje normalizację, 48 h i rollback; `collect` odczytuje cache Windows przez `ipconfig /displaydns` co 15–300 s, bez podnoszenia uprawnień. Parser normalizuje nazwy, odrzuca metadane i ogranicza wynik do 2000 wpisów. Test Windows-live wykonał cache read na zwykłym koncie; wcześniejszy `Get-DnsClientCache` zwracał `Access denied`.
3. **Braki:** cache nie daje PID/timestamp zapytania; nie ma IP feedu ani URLhaus. Windows Event Log `Microsoft-Windows-DNS-Client/Operational` jest wyłączony na maszynie audytu; nie ma w nim dostępnych zdarzeń. Microsoft dokumentuje zdarzenie DNS Client Query Completed (3008), ale włączenie kanału wymaga zmiany systemowej i nie zostało wykonane.
4. **Decyzje:** utrzymać ręczne, stałe źródło i dokładne dopasowanie; odróżnić pustą bazę od świeżej; rozważyć opcjonalny, jawnie włączany DNS Client Operational jako źródło zdarzeń; nie klasyfikować na podstawie wieku/nazwy. Nie zmieniać konfiguracji systemu ani nie wymagać admina po cichu.
5. **Zależności:** schemat zdarzeń, licencje źródeł, Internet tylko przy jawnej aktualizacji, Windows event source.
6. **Etapy:** (a) status feedu `never_loaded/active/stale/error`; (b) diagnostyka czasu/ostatniego błędu; (c) fixture feedów walidacji; (d) spike ETW/logu DNS z kanałem włączonym w kontrolowanej maszynie Windows; (e) osobna decyzja o IP feedach.
7. **Pliki:** `DomainReputation.cs`, `Sentinel.Engine/Program.cs`, UI, testy reputation/engine, dokumentacja pokrycia.
8. **Prywatność:** feed pobierany z hosta CERT widzi IP klienta; analizowane URL nie są wysyłane; historia przechowuje tylko domenę wykrycia w ograniczonym przypadku.
9. **Testy:** 0/1/duplikat/niepoprawny feed, wygasły zegar, rollback, offline, kontrolowana domena `.test`, cache bez dopasowania i z nim, timeout/limity.
10. **Akceptacja:** pusty feed nie jest „aktualny”; awaria jawna; poprawna atomowość/rollback; udokumentowany udział cache/ETW i brak claimów pełnego DNS.
11. **Ryzyka:** DoH/DoT/VPN/krótki TTL omijają; ETW nie zobaczy resolvera aplikacyjnego/DoH; CERT jest ograniczonym źródłem.
12. **Status:** `IN_PROGRESS` — podstawowy feed i polling zweryfikowane; pusty feed nie jest już przedstawiany jako aktualny, z regresyjnym testem i wydaniem v0.15.7. Status Engine i pakiet diagnostyczny udostępniają czas ostatniego udanego odczytu oraz czas ostatniego błędu DNS; kontrakt jest testowany w IPC, a test Windows-live sprawdza odczyt cache i znacznik sukcesu. Weryfikacja event logu pozostaje zablokowana wyłączonym kanałem systemowym; pominięcia DoH/DoT/VPN i IP feeds pozostają.

