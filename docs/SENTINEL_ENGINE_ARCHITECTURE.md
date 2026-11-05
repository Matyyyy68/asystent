# Sentinel Protection Engine — stan architektury

Stan na 2026-11-05. Ten dokument opisuje kod w repozytorium, a nie docelowy diagram produktu.

## Przepływ

```text
Windows SCM service (health + service events)
        │ secured local named pipe
Per-user Agent ── inherited stdio JSON-lines IPC ── Sentinel.Engine
                                                   ├─ WMI process lifecycle queue
                                                   ├─ process/TCP/persistence snapshots
                                                   ├─ Downloads FileSystemWatcher + reconciliation
                                                   ├─ DNS Client Operational event log (when enabled)
                                                   ├─ local SQLite event store
                                                   └─ rule-based analysis, reputation, notifications
```

Engine i Agent działają w sesji użytkownika; usługa SCM jest osobnym procesem o odrębnych uprawnieniach. UI nie jest wymagane do działania usługi, ale część kolektorów i analizy użytkownika działa w procesie Engine uruchamianym przez Agenta. Sam fakt działania usługi SCM nie oznacza, że każdy kolektor działa jako usługa.

## Granice ochrony

- Kanał Agent–Engine używa odziedziczonego stdin/stdout i wersjonowanych komunikatów JSON-lines; nie nasłuchuje na porcie TCP.
- WMI dostarcza obserwacje startu/zakończenia procesów do ograniczonej kolejki. Procesy i relacje są uzupełniane snapshotem; snapshot jest też ścieżką awaryjną.
- Pliki z Downloads są obserwowane przez `FileSystemWatcher` i okresowe uzgadnianie. Nie jest to systemowy minifilter ani pełne monitorowanie wszystkich katalogów.
- Tabele połączeń i wybrane wpisy persistence są odczytywane okresowo. Nie ma kolektora WFP ani pełnego ETW.
- Korelacja używa identyfikatorów procesu w oknie czasu i wspólnego SHA-256 pobranego pliku/uruchomionego obrazu. Nie tworzy jeszcze uniwersalnego grafu incydentów.
- Lokalna lista hashy jest wejściem reputacji, a nie automatyczną blokadą; źródło listy i jej aktualność muszą być pokazane.
- Kwarantanna obsługuje jawnie wybrane pliki. Nie ma automatycznego kończenia procesów ani blokowania ruchu.

## Stan modułów

**Działa:** lokalny magazyn i retencja, IPC procesu Engine, obserwacja procesów WMI z kolejką ograniczoną i snapshotowym fallbackiem, monitor Downloads, snapshoty TCP/DNS/persistence, reguły detekcji, inspekcja SHA-256/Authenticode asynchronicznie, lokalna kwarantanna i powiadomienia tray.

**Częściowo działa:** ciągła ochrona wymaga uruchomionego Agenta, bo to Agent utrzymuje Engine użytkownika i wywołuje cykl `collect`; WMI nie gwarantuje odbioru zdarzeń podczas awarii/restartu; status opisuje komponenty, ale nie jest jednolitym, niezależnym od UI stanem wszystkich kolektorów. Korelacja jest ograniczona do dostępnych kluczy i okien czasu.

**Nie zaimplementowano:** WFP, pełne ETW, systemowy monitoring wszystkich plików, uniwersalny risk engine 0–100, automatyczna izolacja procesów lub sieci, podpisywane przyrostowe aktualizacje bazy threat intelligence, pełna niezależna od sesji użytkownika usługa kolektorów i czysty test Windows po instalacji.

## Weryfikacja

Test integrujący krótkotrwały proces z syntetycznym wejściem WMI jest w `ProcessSnapshotMonitorTests`. Test nie uruchamia WMI ani nie zmienia konfiguracji systemu. Testy regresji wykonuje się przez `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj`.
