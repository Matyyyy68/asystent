# Zbieranie zdarzeń Windows

## Procesy

`WindowsProcessTraceSource` używa WMI `Win32_ProcessStartTrace` i `Win32_ProcessStopTrace`. WMI callback nie zapisuje do bazy bezpośrednio: waliduje PID/nazwę/czas, a zdarzenia trafiają do kolejki o pojemności 4096 elementów. Przy przeciążeniu nowy wpis jest odrzucany i licznik `droppedProcessEvents` jest ujawniany w odpowiedzi statusu i collect. Wyłączenie WMI lub błąd uprawnień pozostawia snapshot PID/nazw jako źródło awaryjne; stan podaje typ błędu.

Zdarzenia WMI są opróżniane przy cyklu Engine `collect`. Start procesu, którego PID nie występuje już w migawce, nadal może trafić do historii, lecz nie ma wtedy dostępnej ścieżki obrazu ani weryfikacji podpisu. Jeśli start lub stop widzi też snapshot, para PID/nazwa/typ jest deduplikowana. Stop z WMI i zniknięcie z migawki są jednym typem cyklu życia.

Monitor nie zbiera linii poleceń. Ścieżka obrazu jest pobierana tylko dla nadal działającego procesu, a inspekcja pliku wykonuje się w ograniczonej kolejce. To nie jest gwarantowany audyt każdego procesu: WMI może być niedostępne, proces może zakończyć się przed odczytem metadanych, a awaria komputera powoduje lukę.

## Pozostałe źródła

- Downloads: `FileSystemWatcher` plus okresowa rekonsyliacja i baseline; tylko znany katalog Downloads.
- DNS: Windows DNS Client Operational Event Log, jeśli kanał jest dostępny/włączony, oraz okresowy cache DNS. Cache nie wiąże domeny z konkretnym procesem.
- Sieć: ograniczone snapshoty tabel TCP/UDP z PID; nie widać pełnej historii krótkich połączeń.
- Persistence: snapshoty wybranych Run/startup/task/service.
- Usługa: stan SCM i transfer wybranych zdarzeń przez lokalny named pipe.

Sentinel nie przechwytuje pakietów, nie deszyfruje HTTPS i nie instaluje certyfikatu MITM. ETW i WFP nie są obecnie podłączone.

- Microsoft Defender: `WindowsDefenderOperationalLogSource` odpytuje kanał `Microsoft-Windows-Windows Defender/Operational` o zdarzenia 1116–1119, 5007 i 5008. Przy pierwszym uruchomieniu ustawia kursor na najnowszym obsługiwanym rekordzie, potem odczytuje ograniczone partie i wykrywa reset dziennika. Parser dopuszcza wyłącznie nazwę i poziom wykrycia, kategorię oraz nazwę/status działania; nie zapisuje ścieżek plików, kont ani poprzednich i nowych wartości konfiguracji. Wpisy są lokalne dla danego Engine, mają stabilne ID i nie powodują automatycznej kwarantanny. Testy używają syntetycznego XML; nie wywołują prawdziwego wykrycia Defendera, a dostępność kanału zależy od Windows i uprawnień procesu.

## Utrzymanie

WMI jest źródłem best-effort; queue overflow, błąd źródła i awaria Engine muszą być widoczne w diagnostyce. Snapshot PID/nazw zachowuje rolę rekonsyliacji i nie jest dowodem, że zdarzeniowy kolektor działa.
