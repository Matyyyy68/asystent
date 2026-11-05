# Monitoring procesów

## Implementacja

Engine używa dwóch źródeł:

1. Zdarzeń WMI start/stop (`Win32_ProcessStartTrace`, `Win32_ProcessStopTrace`) w kolejce do 4096 wpisów. Po błędzie startu albo nieoczekiwanym zatrzymaniu subskrypcji silnik próbuje ją odtworzyć po 5, 10, 20… sekundach, maksymalnie co 5 minut; snapshot pozostaje aktywnym fallbackiem.
2. Snapshotu PID/nazw jako fallbacku i rekonsyliacji.

Alerty procesu zawierają źródło (`process-wmi` albo `process-snapshot`), PID, nazwę, czas obserwacji i kody dowodów. WMI dostarcza Parent PID nawet dla krótkiego procesu; jeśli jego nazwy nie da się ustalić, zapisujemy Parent PID jako ograniczone wyjaśnienie bez przypisywania nazwy. Dla nadal działających procesów relacja parent-child jest odczytywana z Windows; dla zdarzenia WMI silnik może też dopasować Parent PID do bieżącego snapshotu, nawet gdy dziecka nie ma już w snapshotcie. Pozwala to zastosować regułę Office → interpreter do krótkiego procesu, z umiarkowanym poziomem heurystycznym i jawną informacją o ograniczeniach. WMI start może zachować fakt uruchomienia krótkiego procesu, lecz niekoniecznie jego ścieżkę ani hash.

Dla dostępnego obrazu kolejka asynchroniczna oblicza SHA-256, sprawdza lokalną reputację i Authenticode. Odczyt nie zapisuje command line. Zmiana rozmiaru lub czasu pliku podczas hashowania unieważnia hash. Wynik nie podpisuje samodzielnie werdyktu malware; niezaufany hash nie powoduje automatycznej blokady.

## Detekcja

Reguły relacji rodzic–dziecko oznaczają wybrane kombinacje Office → interpreter jako podejrzane. Zdarzenie jest wskazówką wymagającą weryfikacji, a nie potwierdzeniem infekcji. Nieznana nazwa procesu, brak podpisu, lokalizacja TEMP ani sam brak reputacji nie są wystarczającym dowodem zagrożenia.

## Ograniczenia

- To nie jest pełny ETW kernel collector ani audyt Security Event 4688.
- Nie ma command line, stosów, modułów DLL ani telemetrii zachowania wewnątrz procesu.
- Nie każdy start przetrwa niedostępność WMI; snapshot może przeoczyć krótko żyjący proces.
- Kolektor jest uruchamiany przez Engine w sesji użytkownika i Agent musi go utrzymywać.
- Nie ma automatycznego zatrzymywania procesów.

## Test

`WmiProcessStartEventCapturesShortLivedProcessMissingFromSnapshot` sprawdza, że zdarzenie wejściowe startu zostaje zapisane nawet bez PID w snapshotcie. `WmiParentPidAppliesBehaviorRuleToShortLivedOfficeChild` sprawdza heurystyczną klasyfikację dziecka Office na podstawie WMI Parent PID i snapshotu rodzica, mimo braku dziecka w snapshotcie. Pozostałe testy sprawdzają baseline, filtrowanie, kolejkę, relację rodzic–dziecko i inspekcję obrazu.

`WindowsWmiSourceObservesBenignChildOrReportsSnapshotFallback` uruchamia bezpieczny `cmd.exe /c exit 0` i szuka jego eventu WMI, jeśli subskrypcja jest dostępna; przy braku dostępu sprawdza stan fallbacku. W bieżącym środowisku testowym subskrypcja zwróciła `ManagementException`, a niezależne `Get-CimInstance` zwróciło `Access denied`. Test zaliczył zatem ścieżkę fallbacku, nie odbiór zdarzenia WMI. Lokalny PASS nie jest dowodem, że subskrypcja WMI jest dostępna w każdym kontekście konta.
