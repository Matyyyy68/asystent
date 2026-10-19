# Postęp projektu Sentinel AI

**Aktualizacja:** 2026-10-19  
**Etap:** audyt bazowy wykonany; naprawa testów Enterprise zakończona; lokalny kontrakt zdarzeń v1 i interfejs lokalnej bazy wiedzy wdrożone; pozostałe plany realizowane.

Audyt obejmuje 20 obszarów: 7 zweryfikowanych w opisanym zakresie, 10 częściowych, 2 brakujące i 1 blokowany decyzją właściciela. Żaden z 10 planów nie jest jeszcze w pełni zamknięty; 4 plany mają wdrożone i przetestowane etapy. Statusów funkcji nie sumuję do procentu ukończenia produktu.

Nie wyliczam procentu ukończenia: brak stabilnego, ważonego katalogu kryteriów, a udział UI zawyżałby gotowość produktu bezpieczeństwa. Postęp liczę przez zweryfikowane przepływy i jawne ograniczenia.

## Zweryfikowane przepływy

- Klient: 146 testów .NET (w tym 32 równoległe zapisy SQLite, zgoda/profil/kolejka Enterprise, cap 10 000, odmowa niepełnego potwierdzenia batcha, odwołanie zgody i DPAPI round-trip sprawdzony w interaktywnej sesji Windows), build Electron/UI oraz IPC → reguły → SQLite; testy obejmują false positive, odrzucenie endpointu zdalnego, import/wyszukanie/usunięcie prywatnego dokumentu, redagowany eksport, kopie i przywracanie obu baz, cykl życia procesu, zalew 10k PID i odzyskanie po błędzie źródła.
- Windows/reputacja: aktualizacja CERT Polska (ponad 125 tys. domen), cache DNS i kontrolowany snapshot TCP/UDP z PID procesu dla loopback.
- Instalator 0.15.1: build po pełnym teście klienta, smoke IPC i buildzie UI; `--self-test` instalacji w katalogu tymczasowym, ACL AppContainer oraz renderer → preload → IPC → .NET → SQLite PASS. Rozmiar 279275383 B, SHA-256 `2441351AFD10EC1132CE34425512A0D328807350241A60CA5AAB5FAED44B9334`. Nie jest to test czystego komputera. GitHub Release zostanie utworzony przez workflow po wypchnięciu tagu.
- Zasoby silnika: pięciominutowy pomiar lokalny, 60 próbek co 5 s, 257 procesów systemowych; średnie CPU procesu 0,057% logicznej mocy wszystkich procesorów, working set 43,4 MiB początkowo / 53,8 MiB maksimum, `collect` mediana 5 ms i maksimum 1 359,8 ms. To pojedyncza sesja bez wysokiego syntetycznego obciążenia, nie gwarancja wydajności.
- Witryna: test lokalnych linków/zasobów, 63 ilustracje, lint i produkcyjny build.
- Enterprise: 19 testów jednostkowych, build rozwiązania serwera i test HTTP API: bootstrap/login, RBAC, polityki, AI z bramką zgody, FTS5, zaproszenie, agent, heartbeat i unieważnianie.

## Wykonane w tym audycie

- Rozróżniono aktywny klient Electron od historycznego WPF i odrębnego Enterprise API.
- Potwierdzono, że DNS jest próbkowanym cache; TCP/UDP są snapshotem punktów końcowych, a procesy próbkowane są co 5 s, co może pominąć krótkie zdarzenia.
- Naprawiono testy serwera, które pozostawiały zablokowane pliki SQLite z powodu domyślnego poolingu połączeń w trzech fixture'ach.
- Utworzono raport luk i 10 planów. Lokalny model zdarzeń v1 ma teraz jawne schemaVersion, GUID, źródło, wersję reguły, opcjonalny confidence i proces PID/nazwę; migracja SQLite v6 zachowuje starszą historię, ponowne uruchomienie i eksport testują te pola.
- Poprawiono nazwę sekcji UI z „Baza wiedzy” na „Reguły, reputacja i baza”, zgodnie z zawartością ekranu po podłączeniu indeksu lokalnego.
- Widok historii pokazuje schemat, źródło i wersję reguł; można oznaczyć zdarzenie jako fałszywy alarm, bez wymyślania pewności detekcji.
- Podłączono istniejący lokalny indeks FTS5 do aktywnego klienta: import TXT/MD/DOCX, wyszukiwanie, lista i usuwanie. Zawartość dokumentów zostaje w prywatnym indeksie, nie w zdarzeniach.
- Podłączono też orchestrator lokalnego AI: interfejs sprawdza modele wyłącznie przez loopback i wymaga jawnego włączenia; awaria modelu zachowuje wynik reguł i dodaje niepewność.
- Eksport historii JSON i kopie SQLite historii/ustawień oraz bazy wiedzy są dostępne w UI przez systemowy wybór ścieżki. Komunikat prywatności wyraźnie mówi o braku szyfrowania; testy sprawdzają redakcję eksportu, poprawny nagłówek SQLite oraz ponowne otwarcie kopii indeksu wiedzy.
- Przywracanie historii/ustawień jest dostępne po potwierdzeniu i wyborze kopii. Waliduje integralność SQLite, schemat v6 i ustawienia, zastępuje historię/ustawienia/kolejkę w transakcji i zachowuje profil instalacji. Restore bazy wiedzy waliduje SQLite/schemat/metadane i odtwarza FTS5. Testy obu ścieżek potwierdzają round-trip; uszkodzone kopie nie zmieniają aktywnych danych.
- Test mock HTTP pokrywa Ollama opt-in, odrzucenie endpointu zdalnego, redakcję sekretów i przekazanie dopasowanego fragmentu lokalnej wiedzy.
- Naprawiono skrypt przywracania offline backupu serwera na Windows: połączenia SQLite są jawnie zamykane, a synchronizacja staging file używa zapisywalnego uchwytu. Dwa testy kopii/restore przechodzą na Windows (wcześniej ujawniały `WinError 32` oraz `fsync` na read-only handle).
- Ręczna kontrola pliku zachowuje limit 256 MiB i hashuje uchwyt otwarty tylko do odczytu; do wyniku dodano status Authenticode przez Windows PowerShell Security. Syntetyczny niepodpisany `.ps1` w Engine IPC zwraca `NotSigned`; wynik nie jest klasyfikacją bezpieczeństwa. Feed reputacji i monitoring pobrań nadal nie istnieją.
- PLAN-001 otrzymał snapshot TCP/UDP z PID i nazwą procesu; kontrolowany Windows loopback test potwierdził atrybucję. Krótkie i ciągłe zdarzenia pozostają poza zakresem tego kroku.
- Dodano polling widocznych procesów co 5 s, zapis pojawienia/zniknięcia PID w historii, pauzę, wykluczenia i limit 100 zmian na próbkę. Kontrolowany proces potomny potwierdza oba stany. WMI start trace zwrócił `Access denied`, dlatego nie wymaga się admina i pozostaje jawne ograniczenie krótkich procesów.
- W teście integracyjnym zsyntetyzowano 10 500 PID: monitor zachował limit 10 000 PID/100 zdarzeń na próbkę, pokazał 9 900 pominiętych zmian i po cyklu start/stop 19 800 pominiętych łącznie. Test z rzeczywistym zapisem do SQLite przeszedł w ok. 1 s; CPU/RAM i długotrwałe obciążenie nie były mierzone.
- Diagnostyka UI pokazuje working set, pamięć prywatną i skumulowany CPU silnika; `scripts/benchmark-engine.cjs` obsługuje pomiary od 30 s do 15 min. Pięciominutowa sesja zebrała 60 próbek co 5 s; wynik podano wyżej.
- Rekomendacja wariantu Enterprise rozdziela funkcje aktywne (pairing, metadane, heartbeat, polityka lokalna) od brakującej analizy serwerowej treści, zatwierdzania/revoke w kliencie i podpisanych aktualizacji; test chroni przed deklarowaniem brakujących funkcji.
- Aktywny klient Enterprise otrzymał pairing HTTPS z jednorazowym zaproszeniem i zgodą, DPAPI CurrentUser, status, heartbeat, stosowanie wspieranej polityki lokalnej oraz throttled sync kolejki metadanych. `LocalStore` nie tworzy kolejki Enterprise dla profilu User lub bez zgody; przy braku zgody Engine wstrzymuje całą komunikację z serwerem, nigdy nie wysyła przywróconej kolejki, a jej wyłączenie usuwa oczekujące metadane bez kasowania historii.
- Dwie wcześniejsze rozgrzane próbki process snapshot + IPC + zapis SQLite trwały 15,3 ms i 28,8 ms; osobny benchmark zasobów opisano wyżej.

## W trakcie / zablokowane

- W trakcie: szczegółowe wdrożenia planów 001–010; PLAN-001 ma snapshot TCP/UDP, próbkowane zdarzenia procesu i test awarii/odzyskania źródła; PLAN-004/005 mają wdrożone i przetestowane etapy, a PLAN-007 ma eksport i kopie/restore obu baz z testami. Dodano także test 32 równoległych zapisów SQLite; limity rozmiaru, brak miejsca i ACL nadal wymagają pracy.
- Wymaga czystej maszyny Windows: pełny GUI instalatora, upgrade/rollback/uninstall, autostart po restarcie i ręczna instalacja rozszerzeń Chrome/Edge.
- Wymaga zakończenia GitHub Actions po tagu `v0.15.1` oraz późniejszej kontroli live Pages; tag `v0.15.0` istniał bez odpowiadającego Release.
- Wymaga decyzji właściciela: licencja źródeł i warunki redystrybucji. Wymaga zakupu/decyzji: podpis kodu dla bezpiecznego autoupdate.
- `npm audit` zgłosił 8 umiarkowanych alertów w łańcuchu narzędzia budującego instalator (`electron-builder` dev dependency → `sprintf-js`); GitHub Advisory obecnie nie podaje poprawionej wersji. `npm audit fix --force` proponuje downgrade narzędzia, więc nie stosowałem automatycznej, potencjalnie niezgodnej zmiany. To zależność build-time; należy ponowić audyt po publikacji poprawki upstream.

## Następny konkretny krok

Kontynuować [PLAN-007](implementation-plans/PLAN-007-database-and-privacy.md): zweryfikować test współbieżnych zapisów, następnie zaprojektować jawne limity i diagnostykę rozmiaru bez cichego usuwania historii. Test braku miejsca i ACL wymagają osobnych, kontrolowanych warunków Windows.

