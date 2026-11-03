# Testowanie i walidacja

## Zweryfikowane w bieżącym checkoutcie (2026-11-03)

- `npm test --prefix desktop`: PASS, 67/67, w tym klient Core Agent, stan Windows Security Center w UI i parser argumentów kontroli pojedynczego pliku.
- `npm run lint --prefix desktop`: PASS (TypeScript i kontrola składni Electron).
- `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release --no-restore`: PASS, 404 testy, 2 środowiskowe SKIP.
- `dotnet build Sentinel.sln -c Release --no-restore`: PASS, 0 ostrzeżeń/błędów; osobno Setup Release i autotest kreatora też PASS.
- `dotnet build src/Sentinel.Agent/Sentinel.Agent.csproj -c Release --no-restore`: PASS, 0 ostrzeżeń/błędów.
- `dotnet build installer/Sentinel.Setup/Sentinel.Setup.csproj -c Release --no-restore`: PASS, 0 ostrzeżeń/błędów.
- `Sentinel.AI.Setup.dll --wizard-self-test`: PASS (kod 0).
- Publikacja Engine/UrlHost/Agent do `artifacts/engine` oraz `node scripts/test-engine.cjs`: PASS, proces/IPC, kontrolowane fixture'y i prywatność.
- `npm run build --prefix desktop -- --configLoader runner`: PASS; Vite przekształcił 1582 moduły.
- Engine IPC sprawdza również dostępność zagregowanego stanu antywirusa i zapory Windows Security Center.
- `git diff --check`: PASS; są tylko ostrzeżenia Git o konwersji LF/CRLF.

## Niezweryfikowane / wymagają izolowanego Windows runnera

- Pełny packaging `build-user.ps1 -Offline -Installer` i aktualny osadzony payload.
- Pełny `--self-test` z bieżącym payloadem oraz widoczny kreator instalacji. Wcześniejsze próby pełnego self-testu blokowały się na Chromium AppContainer/ACL; tamten wynik nie dotyczy bieżącego pakietu.
- Instalacja/aktualizacja/deinstalacja bieżącego artefaktu na czystym Windows, zachowanie istniejących wpisów HKCU, widoczność menu Eksploratora w Windows 10/11.
- Integracyjny test named pipe i faktycznej pracy agenta po zamknięciu Electron, awarii i ponownym uruchomieniu.
- Testy powiadomień/dźwięków w aktywnej sesji Windows oraz ograniczenia częstotliwości.
- Wydajność i dokładność monitorowania na reprezentatywnych maszynach.

Nie uruchamiano instalatora, przeglądarki ani GUI produktu na komputerze użytkownika; nie instalowano certyfikatów i nie uruchamiano rzeczywistego malware. Nie należy zaliczać wymienionych testów integracyjnych jako PASS.

Pełna bramka packagingu zatrzymała się przed buildem z powodu niespójnego lokalnego drzewa npm: zainstalowany Electron 44.9.1 nie spełnia wymaganego `^45.0.0`. Nie uruchomiono `npm ci` ani nie pobierano zależności.
