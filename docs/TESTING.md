# Testowanie i walidacja

## Zweryfikowane w bieżącym checkoutcie (2026-11-03)

- `npm test --prefix desktop`: PASS, 87/87, w tym testy grupowania wielu plików, formatowania Authenticode oraz jawnego braku lokalnej listy hashy.
- `npm run lint --prefix desktop`: PASS (TypeScript i kontrola składni Electron).
- `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release --no-restore`: PASS, 450 testów, 2 środowiskowe SKIP. Obejmuje parser stanu Defendera i nieprawidłowe wyniki, korelację Downloads → proces, inwentarz aplikacji, timeout rejestru, wybór najwyższej wagi dźwięku dla grupowanych powiadomień, cztery odmienne tony PCM i trwały, jednokrotny znacznik pierwszego zakończenia analizy.
- `dotnet build Sentinel.sln -c Release --no-restore`: PASS po dodaniu `Sentinel.Service`, 0 ostrzeżeń/błędów.
- `Sentinel.Service.exe --self-test`: sprawdza deskryptor DACL, walidację protokołu/statusu, starzenie i przyszły czas próbki, lokalny round-trip named pipe oraz regresję backoffu 1–30 s z resetem po stabilnych 60 s; używa unikalnej nazwy testowej, nie tworzy katalogu danych ani nie rejestruje usługi.
- Self-contained publish Engine + Service (`--no-restore`) i złożenie payloadu `artifacts/service`: PASS; sprawdzono wymagane pliki Service/Engine/Core/Contracts/SQLite oraz brak Agent/UrlHost. To test układu payloadu, nie pełnego instalatora ani rejestracji SCM.
- `scripts/test-service-scm.ps1`: workflow Windows CI publikuje osobny host i sprawdza na jednorazowym runnerze SCM start/stop, konto LocalService, rzeczywisty ACL ProgramData, pierwszy cykl Engine i statusowy pipe. Skrypt odmawia kolizji z istniejącą usługą/katalogiem i usuwa wyłącznie własny serwis, dane i katalog tymczasowy; lokalnie wykonano parser PowerShell oraz publish/self-test bez rejestracji usługi. Run [41716942484](https://github.com/Matyyyy68/asystent/actions/runs/41716942484) zaliczył build i testy oraz utworzył usługę, ale `sc.exe start` zakończył się błędem 5 (`Access is denied`) przed sprawdzeniem konta/ACL/pipe. Test otrzymał zmianę nadającą LocalService wyłącznie RX na własnym tymczasowym payloadzie; weryfikacja tej poprawki oczekuje na Windows CI.
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
- Usługa Windows SCM nie jest jeszcze wdrożona w instalowanym produkcie; automatyczne aktualizacje, blokada wykonania/ruchu, ocena CVE i rozpoznanie konkretnego AV/sygnatur również nie są gotowe.

Nie uruchamiano instalatora, przeglądarki ani GUI produktu na komputerze użytkownika; nie instalowano certyfikatów i nie uruchamiano rzeczywistego malware. Nie należy zaliczać wymienionych testów integracyjnych jako PASS.

Lokalny pełny packaging pozostaje niedostępny bez przywrócenia wymaganej zależności Electron 45; zainstalowany Electron 44.9.1 nie spełnia `^45.0.0`. Nie uruchomiono `npm ci` ani nie pobierano zależności. Wcześniejszy zdalny Windows CI zbudował payload na runnerze.
# Weryfikacja zbiorczego menu kontekstowego

- `npm test --prefix desktop`: 87/87 PASS; testy sprawdzają grupowanie równoległych wezwań z Explorera, deduplikację, limit 15 elementów, kolejkę podczas aktywnego sprawdzania, rozdzielenie SHA-256 od Authenticode, brak listy i sanitację nazwy.
- `dotnet build installer/Sentinel.Setup/Sentinel.Setup.csproj --no-restore`: PASS, 0 ostrzeżeń i błędów.
- Testy nie odtwarzają rzeczywistego wielokrotnego zaznaczenia w Explorerze ani widoczności pozycji menu na czystych Windows 10/11; ten gate pozostaje wymagany.
