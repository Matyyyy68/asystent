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
12. **Status:** `IN_PROGRESS` — wdrożono lokalny kontrakt zdarzenia v1 w SQLite v8 oraz projekcję Enterprise v1 obejmującą schemaVersion, allowlistowane źródło, bezpieczny ruleVersion, kategorię, ryzyko, czas i GUID. Serwer przechowuje pochodzenie po migracji v7→v8; rekordy historyczne dostają `unknown`/null/1. Testy sprawdzają payload bez treści/URL, normalizację niedozwolonych metadanych, zachowanie źródła przez lokalną kolejkę i migrację bez utraty zdarzeń. Odczyt administracyjny pokazuje pochodzenie i wersję. Migracje lokalne v3/v5/v7/v8 zachowują historię; redagowany eksport JSON/CSV, false-positive UI, atomowość i idempotencja lokalna pozostają zweryfikowane. Confidence pozostaje puste bez kalibracji. Nadal do zrobienia: generowany wspólny DTO, deduplikacja między źródłami i korelacja.

