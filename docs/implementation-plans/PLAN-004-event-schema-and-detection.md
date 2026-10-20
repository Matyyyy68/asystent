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
12. **Status:** `IN_PROGRESS` — v0.15.32 wdraża Enterprise event v1 w lokalnej kolejce SQLite v10 i serwerowej bazie v8, przekazując `schemaVersion`, allowlistowane `source` i bezpieczny `ruleVersion`; widok admina prezentuje te wartości, a stare wpisy dostają bezpieczne domyślne metadane. Wydanie v0.15.32, client .NET 190/190, server tests 20/20, Release build, HTTP API smoke oraz installer build/self-test PASS (`39472685283`, `39472689007`). Testy sprawdzają payload bez treści/URL, walidację niedozwolonych metadanych, kolejkę, migrację bez utraty zdarzeń i odczyt admina. Nadal do zrobienia: generowany wspólny DTO, deduplikacja między źródłami i korelacja. Confidence pozostaje puste bez kalibracji.

