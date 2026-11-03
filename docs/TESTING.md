# Testowanie i walidacja

## Zweryfikowane w bieżącym checkoutcie (2026-11-03)

- `npm test --prefix desktop`: PASS, 67/67, w tym klient Core Agent, stan Windows Security Center w UI i parser argumentów kontroli pojedynczego pliku.
- `npm run lint --prefix desktop`: PASS (TypeScript i kontrola składni Electron).
- `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release --no-restore`: PASS, 417 testów, 2 środowiskowe SKIP. Obejmuje testy nowej reguły Office → interpreter/skrypt, lokalny Toolhelp parent snapshot oraz licznik alertu.
- `dotnet build Sentinel.sln -c Release --no-restore`: PASS, 0 ostrzeżeń/błędów; osobno Setup Release i autotest kreatora też PASS.
- `dotnet build src/Sentinel.Agent/Sentinel.Agent.csproj -c Release --no-restore`: PASS, 0 ostrzeżeń/błędów.
- `dotnet build installer/Sentinel.Setup/Sentinel.Setup.csproj -c Release --no-restore`: PASS, 0 ostrzeżeń/błędów.
- `Sentinel.AI.Setup.dll --wizard-self-test`: PASS (kod 0).
- Publikacja Engine/UrlHost/Agent do `artifacts/engine` oraz `node scripts/test-engine.cjs`: PASS, proces/IPC, kontrolowane fixture'y i prywatność.
- `npm run build --prefix desktop -- --configLoader runner`: PASS; Vite przekształcił 1582 moduły.
- Engine IPC sprawdza również dostępność zagregowanego stanu antywirusa i zapory Windows Security Center.
- `ProcessSnapshotMonitorTests`: 18/18 PASS, w tym Windows parent snapshot, dowody relacji, umiarkowane ryzyko i reset licznika w kolejnym cyklu.
- Po publikacji aktualnego Engine `node scripts/test-engine.cjs`: PASS, wraz z asercją typu licznika `suspiciousProcessLaunches` w IPC.
- Ostatni pełny Windows CI run [41666279158](https://github.com/Matyyyy68/asystent/actions/runs/41666279158) PASS dla builda, smoke Electron, Downloads, autostartu, Chrome/Edge, install/update/uninstall z produkcyjnym hostem, widocznego kreatora i API Enterprise. Run poprzedza bieżącą regułę rodzic–potomek; ta zmiana wymaga nowego CI po wypchnięciu.
- `git diff --check`: PASS; są tylko ostrzeżenia Git o konwersji LF/CRLF.

## Niezweryfikowane / wymagają kolejnej bramki CI

- Bieżąca zmiana reguł i Toolhelp parent-child oraz kompletna bramka Windows CI po tej zmianie.
- Rollback instalatora, zachowanie istniejących wpisów HKCU, widoczność menu Eksploratora na czystym Windows 10/11.
- Integracyjny test awarii samego watchdoga, powiadomień/dźwięków w aktywnej sesji i wydajności na reprezentatywnych maszynach.
- Usługa Windows SCM, automatyczne aktualizacje, bezpieczne reakcje/quarantine i rozpoznanie konkretnego AV/sygnatur nie są wdrożone.

Nie uruchamiano instalatora, przeglądarki ani GUI produktu na komputerze użytkownika; nie instalowano certyfikatów i nie uruchamiano rzeczywistego malware. Nie należy zaliczać wymienionych testów integracyjnych jako PASS.

Lokalny pełny packaging pozostaje niedostępny bez przywrócenia wymaganej zależności Electron 45; zainstalowany Electron 44.9.1 nie spełnia `^45.0.0`. Nie uruchomiono `npm ci` ani nie pobierano zależności. Wcześniejszy zdalny Windows CI zbudował payload na runnerze.
