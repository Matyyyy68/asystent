# PLAN-002 — DNS i threat intelligence

1. **Cel:** jasno raportować świeżość źródeł i wiarygodne zdarzenia DNS/reputacji z mierzalnym opóźnieniem.
2. **Stan obecny:** `DomainReputation` importuje feed CERT ręcznie do SQLite, obsługuje normalizację, 48 h i rollback; `collect` pyta cache Windows co 15/60 s. Test Windows/network przeszedł dla 125344 domen.
3. **Braki:** ETW DNS nie jest badane; cache nie daje PID/timestamp zapytania; UI może przedstawiać pusty feed jako aktualny; nie ma IP feedu ani URLhaus.
4. **Decyzje:** utrzymać ręczne, stałe źródło i dokładne dopasowanie; odróżnić pustą bazę od świeżej; zbadać DNS Client ETW jako opcjonalne źródło; nie klasyfikować na podstawie wieku/nazwy.
5. **Zależności:** schemat zdarzeń, licencje źródeł, Internet tylko przy jawnej aktualizacji, Windows event source.
6. **Etapy:** (a) status feedu `never_loaded/active/stale/error`; (b) diagnostyka czasu/ostatniego błędu; (c) fixture feedów walidacji; (d) spike ETW i coverage test; (e) osobna decyzja o IP feedach.
7. **Pliki:** `DomainReputation.cs`, `Sentinel.Engine/Program.cs`, UI, testy reputation/engine, dokumentacja pokrycia.
8. **Prywatność:** feed pobierany z hosta CERT widzi IP klienta; analizowane URL nie są wysyłane; historia przechowuje tylko domenę wykrycia w ograniczonym przypadku.
9. **Testy:** 0/1/duplikat/niepoprawny feed, wygasły zegar, rollback, offline, kontrolowana domena `.test`, cache bez dopasowania i z nim, timeout/limity.
10. **Akceptacja:** pusty feed nie jest „aktualny”; awaria jawna; poprawna atomowość/rollback; udokumentowany udział cache/ETW i brak claimów pełnego DNS.
11. **Ryzyka:** DoH/DoT/VPN/krótki TTL omijają; ETW nie zobaczy resolvera aplikacyjnego/DoH; CERT jest ograniczonym źródłem.
12. **Status:** `IN_PROGRESS` — podstawowy feed i polling zweryfikowane; diagnostyka semantyki statusu i ETW pozostałe.

