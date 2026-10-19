# PLAN-004 — wspólny model zdarzeń i detekcja

1. **Cel:** wersjonowane, testowalne zdarzenie wspólne dla ręcznych reguł, DNS, browsera, plików i przyszłego Enterprise.
2. **Stan obecny:** `SecurityEvent` lokalny ma timestamp/risk/category/application/explanation/recommendation/status; kontrakt Enterprise ma `eventId/occurredAt/category/risk/ruleCode`. To różne schematy, bez wspólnego źródła, confidence, evidence i wersji reguły.
3. **Braki:** idempotencja lokalna, provenance, wersja analizy, niepewność jako struktura, dedupe między modułami i obsługa false positive w aktywnym UI.
4. **Decyzje:** additive SQLite migration; tekst prywatny/pełny URL pozostaje wyłączony; confidence oddzielone od ryzyka; wartości nieznane nie są wymuszane.
5. **Zależności:** `LocalStore`, kontrakt server API v1 (kompatybilność), retencja/eksport, klient Electron.
6. **Etapy:** (a) kontrakt v1 i dokument; (b) migracja i test legacy db; (c) adapter starych zdarzeń; (d) `ruleVersion/source/evidence codes`; (e) dedupe/status false positive; (f) adapter Enterprise.
7. **Pliki:** `Models.cs`, `LocalStore.cs`, `Sentinel.Engine/Program.cs`, serwerowe `SecurityEvents.cs`, testy Core/API, renderer.
8. **Prywatność:** bez treści, haseł, pełnych URL i ekranu; `evidence` ograniczone do kodów/przesłanek redagowanych; retention.
9. **Testy:** migracja starych baz, brak utraty historii, enum/version validation, idempotence, retencja, eksport redaction, cross-contract fixtures.
10. **Akceptacja:** wszystkie nowe źródła zapisują v1 zdarzenia; legacy odczyt działa; false positive i source są widoczne; feed/API nie przyjmują nadmiarowych pól.
11. **Ryzyka:** migracje i zgodność z istniejącymi danymi; schemat API wymaga wersjonowania.
12. **Status:** `IN_PROGRESS` — wdrożono lokalny kontrakt zdarzenia v1 w SQLite v6: jawna schemaVersion, GUID, źródło, wersja reguły, opcjonalny confidence oraz proces ID/nazwa. Migracje v3 i v5 zachowują historię; odczyt, eksport i UI przenoszą metadane, UI obsługuje false positive przez IPC. Confidence pozostaje puste bez kalibracji. Nadal do zrobienia: adapter Enterprise i korelacja/deduplikacja.

