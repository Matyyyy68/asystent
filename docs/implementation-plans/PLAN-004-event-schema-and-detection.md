# PLAN-004 — wspólny model zdarzeń i detekcja

1. **Cel:** wersjonowane, testowalne zdarzenie wspólne dla ręcznych reguł, DNS, browsera, plików i przyszłego Enterprise.
2. **Stan obecny:** lokalny `SecurityEvent` i Enterprise DTO mają różne zakresy, ale wspólny transportowy kontrakt `EnterpriseEventV1` oraz batch/result w `src/Sentinel.Contracts` są współdzielone przez klienta i serwer. Wspólny walidator pilnuje ID, czasu, kategorii, ryzyka, kodu reguły, źródła i wersji schematu.
3. **Braki:** deduplikacja między odrębnymi modułami, niepewność jako struktura i correlation ID. Jawne `eventId` deduplikuje ponowiony zapis lokalny od v0.15.31; zdarzenia bez identyfikatora nadal dostają nowy GUID. Lokalny adapter mapuje kategorię na Enterprise heurystycznie; batch, w którym to samo ID powtarza się w ramach jednej transakcji, nadal jest odrzucany atomowo.
4. **Decyzje:** additive SQLite migration; tekst prywatny/pełny URL pozostaje wyłączony; confidence oddzielone od ryzyka; wartości nieznane nie są wymuszane.
5. **Zależności:** `LocalStore`, kontrakt server API v1 (kompatybilność), retencja/eksport, klient Electron.
6. **Etapy:** (a) wspólny kontrakt v1 i walidator — wykonano; (b) migracja i test legacy db — wykonano; (c) adapter starych zdarzeń — częściowo; (d) `ruleVersion/source/evidence codes` — źródło/wersja wykonane; (e) deduplikacja/status false positive — idempotencja i status wykonane, cross-source pozostaje; (f) adapter Enterprise — używa współdzielonego DTO, kategoryzacja pozostaje heurystyczna.
7. **Pliki:** `src/Sentinel.Contracts/EnterpriseEventV1.cs`, `Models.cs`, `LocalStore.cs`, `Sentinel.Engine/Program.cs`, serwerowe `SecurityEvents.cs`, testy Core/API, renderer.
8. **Prywatność:** bez treści, haseł, pełnych URL i ekranu; `evidence` ograniczone do kodów/przesłanek redagowanych; retention.
9. **Testy:** migracja starych baz, brak utraty historii, enum/version validation, idempotence, retencja, eksport redaction, cross-contract fixtures.
10. **Akceptacja:** wszystkie nowe źródła zapisują v1 zdarzenia; legacy odczyt działa; false positive i source są widoczne; feed/API nie przyjmują nadmiarowych pól.
11. **Ryzyka:** migracje i zgodność z istniejącymi danymi; schemat API wymaga wersjonowania.
12. **Status:** `IN_PROGRESS` — v0.15.32 wdraża Enterprise event v1 w lokalnej kolejce SQLite v10 i serwerowej bazie v8. v0.15.33 przenosi transportowy DTO, batch/result i walidację do wspólnego projektu `Sentinel.Contracts`, używanego bezpośrednio przez klienta i API. Client .NET 190/190, server tests 20/20, Release server build i HTTP API smoke PASS. Payload nie obejmuje treści/URL, a walidator wspólny odrzuca nieprawidłowe ID, daty, kategorie, ryzyko, identyfikatory reguł i wersje schematu. Nadal do zrobienia: deduplikacja między źródłami, correlation ID, strukturalne evidence/confidence i zastąpienie heurystycznego mapowania kategorii. Confidence pozostaje puste bez kalibracji.

