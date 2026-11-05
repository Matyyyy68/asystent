# Sentinel Protection Engine — stan architektury

Stan na 2026-11-05. Ten dokument opisuje kod w repozytorium, a nie docelowy diagram produktu.

## Przepływ

```text
Windows SCM (LocalService)
        │ starts/restarts independent Engine; protected ProgramData store
        ├─ Sentinel.Engine: system-context collection and service event history
        │
Per-user Agent ── inherited stdio JSON-lines IPC ── Sentinel.Engine
        │                                          ├─ user-context collectors, including real Downloads
        │                                          ├─ local SQLite event store
        │                                          └─ rules, reputation, analysis
        │
        ├─ SID-restricted named pipe: status, service history, acknowledgements
        └─ bounded event batches + durable cursor ──> Service Engine/store
                 UI reads protection status/history; Agent delivers tray notifications
```

Instalator rejestruje host SCM z zweryfikowanego payloadu. Usługa działa jako `LocalService`, chroni własny katalog ProgramData ACL-em i uruchamia własny Engine, który wykonuje kolekcję bez otwartego UI; po błędzie stosuje ograniczony backoff. Agent i usługa mają oddzielne Engine'y oraz bazy. Agent przesyła ograniczone porcje zdarzeń named pipe z ACL dla SID instalującego użytkownika; kursor przesuwa się dopiero po pełnym potwierdzeniu, a identyfikator zdarzenia zabezpiecza powtórzenia. Usługa udostępnia status i historię przez uwierzytelniony pipe, a Agent odczytuje nowe zdarzenia do lokalnych powiadomień.

Niezależność usługi jest częściowa: jej profil Downloads to izolowany katalog usługi, nie profil użytkownika. Rzeczywisty Downloads użytkownika jest monitorowany przez per-user Engine, więc ochrona tego obszaru wymaga aktywnej sesji Agenta. Windows CI potwierdza instalację/rollback/deinstalację oraz SCM na izolowanym Windows Server runnerze; fizyczna instalacja i restart Windows użytkownika nie zostały zweryfikowane.

## Granice ochrony

- Kanał Agent–Engine używa odziedziczonego stdin/stdout i wersjonowanych komunikatów JSON-lines; nie nasłuchuje na porcie TCP.
- WMI dostarcza obserwacje startu/zakończenia procesów do ograniczonej kolejki. Procesy i relacje są uzupełniane snapshotem; snapshot jest też ścieżką awaryjną.
- Pliki z Downloads są obserwowane przez `FileSystemWatcher` i okresowe uzgadnianie. Nie jest to systemowy minifilter ani pełne monitorowanie wszystkich katalogów.
- Zmiana wersji importowanej listy SHA-256 uruchamia ponowne hashowanie ograniczonego baseline Downloads. SQLite przechowuje checkpoint i wznowi przerwaną kolejkę po restarcie.
- Tabele połączeń i wybrane wpisy persistence są odczytywane okresowo. Nie ma kolektora WFP ani pełnego ETW.
- Korelacja używa identyfikatorów procesu w oknie czasu i wspólnego SHA-256 pobranego pliku/uruchomionego obrazu. Nie tworzy jeszcze uniwersalnego grafu incydentów.
- Lokalna lista hashy jest wejściem reputacji, a nie automatyczną blokadą; źródło listy i jej aktualność muszą być pokazane.
- Kwarantanna obsługuje jawnie wybrane pliki. Nie ma automatycznego kończenia procesów ani blokowania ruchu.

## Stan modułów

**Działa i przetestowano:** SCM host LocalService, restart/backoff Engine, chroniony ProgramData, uwierzytelniony pipe statusu/historii, przekazywanie zdarzeń Agent→Service z ACK i trwałym kursorem, testy install/repair/update/rollback/uninstall na runnerze Windows; WMI lifecycle z kolejką ograniczoną i snapshot fallbackiem; monitor Downloads z uzgadnianiem; snapshoty TCP/DNS/persistence; reguły detekcji; inspekcja SHA-256/Authenticode; ręczna kwarantanna; powiadomienia tray. Pełny Windows CI dla `cd1aad0` [42062610505](https://github.com/Matyyyy68/asystent/actions/runs/42062610505) przeszedł build/testy (.NET 485/485, desktop 112/112), SCM/pipe, Electron, Downloads/junction soak, autostart, Chrome/Edge, headless i widoczny instalator oraz Enterprise API (23/23).

**Częściowo działa:** usługa jest niezależna od UI, ale nie zastępuje per-user Engine dla Downloads i ustawień właściwych dla użytkownika; część historii i kolektorów działa w obu instancjach. WMI nie gwarantuje odbioru zdarzeń podczas awarii/restartu. Core liczy fail-closed status świeżości i źródeł oraz uwzględnia Windows Security Center. Korelacja jest ograniczona do dostępnych kluczy i okien czasu.

**Częściowo zaimplementowano:** `RiskEngine` oblicza deterministyczną heurystykę 0–100 dla ręcznej analizy tekstu/URL, a `ThreatAssessment` zwraca wynik wraz z poziomem i wskaźnikami. To nie jest skalibrowane prawdopodobieństwo; wynik nie jest jeszcze częścią trwałego schematu zdarzeń ani nie jest stosowany do monitorów systemowych.

**Nie zaimplementowano:** WFP, pełne ETW, systemowy monitoring wszystkich plików, uniwersalna i skalibrowana ocena ryzyka, automatyczna izolacja procesów lub sieci, podpisywane przyrostowe aktualizacje bazy threat intelligence, pełna konsolidacja stanu i korelacji pomiędzy dwiema bazami oraz fizyczny test instalacji i restartu na czystym Windows użytkownika.

## Modułowe notatki

[Monitoring procesów](PROCESS_MONITORING.md) · [monitoring plików](FILE_MONITORING.md) · [monitoring sieci](NETWORK_MONITORING.md) · [detekcja](DETECTION_ENGINE.md) · [ryzyko](RISK_ENGINE.md) · [threat intelligence](THREAT_INTELLIGENCE.md) · [reakcje](RESPONSE_ENGINE.md) · [AI](AI_ENGINE.md) · [wydajność](PERFORMANCE.md) · [prywatność](PRIVACY.md) · [testy](ENGINE_TESTING.md).

## Weryfikacja

Test integrujący krótkotrwały proces z syntetycznym wejściem WMI jest w `ProcessSnapshotMonitorTests`. Test nie uruchamia WMI ani nie zmienia konfiguracji systemu. Testy regresji wykonuje się przez `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj`.
