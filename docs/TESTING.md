# Testowanie i walidacja

## Zweryfikowane w bieżącym checkoutcie (2026-11-04)

- F04 — nowe profile domyślnie mają AutoUpdateCertFeed=true; legacy JSON bez tej właściwości przyjmuje nowy default, a jawne false zachowuje się po restarcie magazynu. Test Engine IPC potwierdza brak pobierania przed pierwszym collect i wyłącza feed przed testowymi cyklami, więc nie wykonuje live requestu. node scripts/test-engine.cjs: PASS.
- Aktualna bramka lokalna: .NET 450 PASS + 2 środowiskowe SKIP; desktop 90/90, lint, produkcyjny Vite build 1584 modułów; Engine publish/IPC, Setup Release build (0 warnings/errors), --wizard-self-test, checker produktu i macierzy luk PASS.

- `npm test --prefix desktop`: PASS, 90/90, w tym testy wersjonowanego status pipe i klienta Node przez kontrolowany transport.
- `npm run lint --prefix desktop`: PASS (TypeScript i kontrola składni Electron).
- `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release --no-restore`: PASS, 450 testów, 2 środowiskowe SKIP. Obejmuje parser stanu Defendera i nieprawidłowe wyniki, korelację Downloads → proces, inwentarz aplikacji, timeout rejestru, wybór najwyższej wagi dźwięku dla grupowanych powiadomień, cztery odmienne tony PCM i trwały, jednokrotny znacznik pierwszego zakończenia analizy.
- `dotnet build Sentinel.sln -c Release --no-restore`: PASS po dodaniu `Sentinel.Service`, 0 ostrzeżeń/błędów.
- `Sentinel.Service.exe --self-test`: sprawdza deskryptor DACL, walidację protokołu/statusu, starzenie i przyszły czas próbki, lokalny round-trip named pipe oraz regresję backoffu 1–30 s z resetem po stabilnych 60 s; używa unikalnej nazwy testowej, nie tworzy katalogu danych ani nie rejestruje usługi.
- Self-contained publish Engine + Service (`--no-restore`) i złożenie payloadu `artifacts/service`: PASS; sprawdzono wymagane pliki Service/Engine/Core/Contracts/SQLite oraz brak Agent/UrlHost. To test układu payloadu, nie pełnego instalatora ani rejestracji SCM.
- Pełny Windows CI run [41734288659](https://github.com/Matyyyy68/asystent/actions/runs/41734288659): PASS. Obejmuje build aplikacji, 452/452 testy .NET, SCM start/stop z LocalService, chroniony ProgramData, rzeczywisty pierwszy cykl Engine i klienta status pipe Node/Electron; Electron smoke, Known Folder, 120-sekundowy soak Downloads junction, autostart, Chrome/Edge E2E, headless install/verify/uninstall, widoczny install/repair/update/uninstall i testy API Enterprise. Poprzedni run [41731627812](https://github.com/Matyyyy68/asystent/actions/runs/41731627812) wskazał błędne odrzucenie dodatkowego bitu `Synchronize` w ACE LocalService. Poprawiono porównanie, a run 41734288659 potwierdził ACL i pełny cykl instalatora na jednorazowym Windows runnerze. To nie jest test na fizycznym komputerze odbiorcy.
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
- Wymuszony rollback aktualizacji usługi jest teraz częścią headless testu CI: awaria po aktywacji nowego payloadu ma potwierdzić przywrócenie poprzedniej usługi, jej heartbeat, aplikacji i plików użytkownika. Windows CI [41856785028](https://github.com/Matyyyy68/asystent/actions/runs/41856785028) PASS: INTEGRATION_TEST_ROLLBACK_SUCCESS, odtworzenie poprzedniej usługi/aplikacji i zachowanie pliku użytkownika. Zachowanie zastanych wpisów HKCU i widoczność menu Eksploratora na czystym Windows 10/11 nadal wymagają osobnego potwierdzenia.
- Integracyjny test awarii samego watchdoga, powiadomień/dźwięków w aktywnej sesji i wydajności na reprezentatywnych maszynach.
- Rejestracja SCM przez jawny UAC i pełny cykl install/repair/update/uninstall są zweryfikowane na izolowanym runnerze Windows (41734288659). Wymuszony test rollbacku po błędzie helpera przeszedł w CI 41856785028. Nadal brakuje przekazywania zdarzeń Agent → Service, wspólnej historii, testu startu przed logowaniem, automatycznych aktualizacji, blokowania wykonania/ruchu, oceny CVE i rozpoznania konkretnego AV/WSC.

Nie uruchamiano instalatora, przeglądarki ani GUI produktu na komputerze użytkownika; nie instalowano certyfikatów i nie uruchamiano rzeczywistego malware. Nie należy zaliczać wymienionych testów integracyjnych jako PASS.

Lokalny pełny packaging pozostaje niedostępny bez przywrócenia wymaganej zależności Electron 45; zainstalowany Electron 44.9.1 nie spełnia `^45.0.0`. Nie uruchomiono `npm ci` ani nie pobierano zależności. Wcześniejszy zdalny Windows CI zbudował payload na runnerze.
# Weryfikacja zbiorczego menu kontekstowego

- `npm test --prefix desktop`: 87/87 PASS; testy sprawdzają grupowanie równoległych wezwań z Explorera, deduplikację, limit 15 elementów, kolejkę podczas aktywnego sprawdzania, rozdzielenie SHA-256 od Authenticode, brak listy i sanitację nazwy.
- `dotnet build installer/Sentinel.Setup/Sentinel.Setup.csproj --no-restore`: PASS, 0 ostrzeżeń i błędów.
- Testy nie odtwarzają rzeczywistego wielokrotnego zaznaczenia w Explorerze ani widoczności pozycji menu na czystych Windows 10/11; ten gate pozostaje wymagany.
