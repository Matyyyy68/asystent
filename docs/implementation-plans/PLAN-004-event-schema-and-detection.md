# PLAN-004 — wspólny model zdarzeń i detekcja

1. **Cel:** wersjonowane, testowalne zdarzenie wspólne dla ręcznych reguł, DNS, browsera, plików i przyszłego Enterprise.
2. **Stan obecny:** `SecurityEvent` lokalny ma timestamp/risk/category/application/explanation/recommendation/status; kontrakt Enterprise ma `eventId/occurredAt/category/risk/ruleCode`. To różne schematy, bez wspólnego źródła, confidence, evidence i wersji reguły.
3. **Braki:** deduplikacja między odrębnymi modułami, niepewność jako struktura oraz wspólny adapter Enterprise bez heurystycznego mapowania kategorii. Jawne `eventId` deduplikuje ponowiony zapis lokalny od v0.15.31; zdarzenia bez identyfikatora nadal dostają nowy GUID. Projekcja Enterprise przenosi ograniczone metadane, lecz nie jest współdzielonym, wersjonowanym kontraktem; batch, w którym to samo ID powtarza się w ramach jednej transakcji, nadal jest odrzucany atomowo.
4. **Decyzje:** additive SQLite migration; tekst prywatny/pełny URL pozostaje wyłączony; confidence oddzielone od ryzyka; wartości nieznane nie są wymuszane.
5. **Zależności:** `LocalStore`, kontrakt server API v1 (kompatybilność), retencja/eksport, klient Electron.
6. **Etapy:** (a) kontrakt v1 i dokument; (b) migracja i test legacy db; (c) adapter starych zdarzeń; (d) `ruleVersion/source/evidence codes`; (e) dedupe/status false positive; (f) adapter Enterprise.
7. **Pliki:** `Models.cs`, `LocalStore.cs`, `Sentinel.Engine/Program.cs`, serwerowe `SecurityEvents.cs`, testy Core/API, renderer.
8. **Prywatność:** bez treści, haseł, pełnych URL i ekranu; `evidence` ograniczone do kodów/przesłanek redagowanych; retention.
9. **Testy:** migracja starych baz, brak utraty historii, enum/version validation, idempotence, retencja, eksport redaction, cross-contract fixtures.
10. **Akceptacja:** wszystkie nowe źródła zapisują v1 zdarzenia; legacy odczyt działa; false positive i source są widoczne; feed/API nie przyjmują nadmiarowych pól.
11. **Ryzyka:** migracje i zgodność z istniejącymi danymi; schemat API wymaga wersjonowania.
12. **Status:** `IN_PROGRESS` — wdrożono lokalny kontrakt zdarzenia v1 w SQLite v8: jawna schemaVersion, GUID, źródło, wersja reguły, opcjonalny confidence oraz proces ID/nazwa. Migracje v3, v5, v7 i v8 zachowują historię; odczyt, redagowany eksport JSON/CSV i UI przenoszą metadane. CSV ma UTF-8 BOM i zabezpieczenie przed formułami arkusza. UI obsługuje false positive przez IPC. Zapis zmian monitorów i zdarzeń jest atomowy. Od v0.15.31 powtórzenie tego samego jawnego `eventId` zwraca istniejący rekord bez duplikacji, a test sprawdza stabilność lokalnego ID. Confidence pozostaje puste bez kalibracji. Nadal do zrobienia: jawny adapter Enterprise, deduplikacja między źródłami i korelacja.

