# Testowanie i walidacja

## Zweryfikowane w bieżącym checkoutcie (2026-11-03)

- `npm test --prefix desktop`: PASS, 79/79, w tym jawna kwarantanna oraz ograniczony widok lokalnego inwentarza aplikacji.
- `npm run lint --prefix desktop`: PASS (TypeScript i kontrola składni Electron).
- `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release --no-restore`: PASS, 447 testów, 2 środowiskowe SKIP. Obejmuje parser stanu Defendera i nieprawidłowe wyniki, korelację plik Downloads → proces po identycznym SHA-256 i oknie ±10 minut, brak korelacji dla innego hasha/starego pliku, inwentarz aplikacji i timeout rejestru.
- `dotnet build Sentinel.sln -c Release --no-restore`: PASS, 0 ostrzeżeń/błędów; osobno Setup Release i autotest kreatora też PASS.
- `dotnet build src/Sentinel.Agent/Sentinel.Agent.csproj -c Release --no-restore`: PASS, 0 ostrzeżeń/błędów.
- `dotnet build installer/Sentinel.Setup/Sentinel.Setup.csproj -c Release --no-restore`: PASS, 0 ostrzeżeń/błędów.
- `Sentinel.AI.Setup.dll --wizard-self-test`: PASS (kod 0).
- Publikacja Engine do `artifacts/engine` oraz `node scripts/test-engine.cjs`: PASS na bieżącym kodzie; IPC weryfikuje lokalny inventory i kontrakt dostępności/pól Defendera, a także procesy, kontrolowane fixture'y i prywatność.
- `npm run build --prefix desktop -- --configLoader runner`: PASS; Vite przekształcił 1584 moduły.
- Engine IPC sprawdza również dostępność zagregowanego stanu antywirusa i zapory Windows Security Center.
- `ProcessSnapshotMonitorTests`: 18/18 PASS, w tym Windows parent snapshot, dowody relacji, umiarkowane ryzyko i reset licznika w kolejnym cyklu.
- Po publikacji aktualnego Engine `node scripts/test-engine.cjs`: PASS, wraz z asercją typu licznika `suspiciousProcessLaunches` w IPC.
- Windows CI [41696210343](https://github.com/Matyyyy68/asystent/actions/runs/41696210343) PASS dla commita `dcb6d01` w pełnych 20 krokach: build/test, Electron smoke, Downloads/junction, autostart, Chrome/Edge, install/update/uninstall, widoczny kreator i Enterprise API. Nie obejmuje jeszcze bieżącego inventory readera.
- `git diff --check`: PASS; są tylko ostrzeżenia Git o konwersji LF/CRLF.

## Niezweryfikowane / wymagają kolejnej bramki CI

- Bieżąca integracja Defendera i korelacja Downloads → proces wraz z inventory readerem wymagają pełnego Windows CI po push; lokalny cmdlet Defendera zwrócił Access Denied, a Engine IPC poprawnie przetestowała kontrakt stanu niedostępnego.
- Rollback instalatora, zachowanie istniejących wpisów HKCU, widoczność menu Eksploratora na czystym Windows 10/11.
- Integracyjny test awarii samego watchdoga, powiadomień/dźwięków w aktywnej sesji i wydajności na reprezentatywnych maszynach.
- Usługa Windows SCM, automatyczne aktualizacje, blokada wykonania/ruchu, ocena CVE i rozpoznanie konkretnego AV/sygnatur nie są wdrożone.

Nie uruchamiano instalatora, przeglądarki ani GUI produktu na komputerze użytkownika; nie instalowano certyfikatów i nie uruchamiano rzeczywistego malware. Nie należy zaliczać wymienionych testów integracyjnych jako PASS.

Lokalny pełny packaging pozostaje niedostępny bez przywrócenia wymaganej zależności Electron 45; zainstalowany Electron 44.9.1 nie spełnia `^45.0.0`. Nie uruchomiono `npm ci` ani nie pobierano zależności. Wcześniejszy zdalny Windows CI zbudował payload na runnerze.
