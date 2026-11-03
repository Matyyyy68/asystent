# Ochrona autonomiczna — stan faktyczny

## Działa obecnie

- `Sentinel.Agent` jest procesem użytkownika Windows z ikoną w zasobniku. Po instalacji instalator uruchamia agenta i rejestruje jego start przy logowaniu w HKCU Run.
- Repozytorium zawiera teraz `Sentinel.Service`: host SCM uruchamia `Sentinel.Engine` jako `LocalService`, wykonuje cykl `collect` co sekundę, zapisuje dane w katalogu ProgramData z chronionym DACL i używa własnego katalogu pobrań profilu usługi. Host i kontrola DACL budują się; self-test sprawdza jawnie trzy SID-y (LocalService, SYSTEM, Administratorzy). To komponent źródłowy, jeszcze nie część instalowanego produktu.
- Osobny watchdog w tej samej sesji uruchamia proces agenta i wznawia go po awarii z rosnącym odstępem 1–30 s. Watchdog ma nazwany semafor, żeby nie uruchamiać wielu kopii. Nie jest to supervisor systemowy.
- Agent uruchamia `Sentinel.Engine` niezależnie od okna Electron, wykonuje `collect` co sekundę i udostępnia lokalne IPC przez named pipe ograniczony do bieżącego użytkownika Windows.
- Zamknięcie samego okna Electron nie zatrzymuje agenta ani silnika. Menu zasobnika pozwala ponownie otworzyć UI i sprawdzić stan.
- Agent restartuje proces Engine, gdy żądanie zawiedzie. Klient Electron ponawia połączenie do agenta; watchdog uruchamia agenta ponownie po jego awarii.
- Monitor procesów korzysta ze snapshotów PID oraz migawki Windows Toolhelp dla nowych PID-ów. Reguła Office uruchamiające interpreter/host skryptów tworzy lokalne zdarzenie o umiarkowanym ryzyku i balonik z 10-minutową deduplikacją. To heurystyka do sprawdzenia, nie potwierdzenie malware ani blokada; relacje mogą być pominięte przy krótkich procesach.
- Alerty o lokalnych dopasowaniach DNS, hashy nowych plików, hashy obrazów nowo uruchomionych procesów, nowych połączeń TCP do zaimportowanych adresów IP i zmianach autostartu w lokalizacjach zapisywalnych przez użytkownika mają 10-minutowy limit per typ i krótki lokalny ton dobrany do wagi sygnału. Różne alerty odebrane w jednym cyklu są łączone w jeden krótki balonik; kliknięcie balonika otwiera okno aplikacji, a szczegóły pozostają w lokalnej historii. Komunikat jawnie mówi, że Sentinel nie zablokował ruchu ani procesu, a lokalna lista nie jest niezależnie zweryfikowana. Zmiana autostartu jest sygnałem do weryfikacji, nie werdyktem malware.
- Po pierwszym poprawnym cyklu agent odtwarza raz na profilu użytkownika odrębny, krótki ton zakończenia analizy. Jeżeli ten cykl ma alerty, odtwarzany jest wyłącznie ton alertu. Znacznik zakończenia jest lokalny w `%LOCALAPPDATA%/Sentinel AI/State/first-analysis-completed.v1`; brak dostępu do zapisu nie przerywa ochrony ani nie powoduje ponawiania dźwięku w bieżącym procesie.
- Raz na minutę agent sprawdza zagregowany stan antywirusa i zapory Windows Security Center. Zgłasza brak monitorowania, wstrzymanie lub stan wymagający uwagi jako informację systemową, a nie wykrycie malware. Nie zmienia konfiguracji Windows.
- Aktualizacja/deinstalacja prosi działającego agenta o zamknięcie i nie zastępuje jego plików, jeśli proces nie zatrzymał się w limicie.
- Pierwsze otwarcie UI automatycznie wykonuje `collect` po uzyskaniu gotowości silnika i pokazuje ograniczony, rzeczywisty zakres pierwszego sprawdzenia. Status udostępnia czas zakończenia ostatniego poprawnego cyklu; jest on pamiętany tylko przez bieżący proces Engine i odtwarza się po jego następnym udanym cyklu po restarcie.
- Przy starcie Engine odczytuje lokalnie nazwy, wersje i wydawców z rejestru deinstalacji aplikacji. UI pokazuje tę listę dopiero na żądanie; nie są czytane ścieżki ani komendy deinstalacji. Nie jest to skan CVE ani ocena bezpieczeństwa zainstalowanych programów.

## Granice autonomii

Instalowany produkt nadal używa agenta i watchdoga działających w sesji zalogowanego użytkownika: nowy host SCM nie jest jeszcze instalowany, nie ma kanału IPC do Agenta/UI, a jego osobna baza nie jest łączona z historią użytkownika. Autostart HKCU nie działa przed logowaniem ani po wylogowaniu. Awaria samego watchdoga nie jest odzyskiwana, dopóki nie zaloguje się ponownie użytkownik lub nie uruchomi UI. Nie ma aktywnego blokowania ruchu ani pełnego źródła zdarzeń ETW/WFP. Agent cyklicznie pobiera migawki/zdarzenia obsługiwane przez Engine; nie oznacza to pełnego monitorowania każdej aktywności komputera.

Pobrane pliki, TCP/UDP i część kontroli trwałości/autostartu pozostają zależne od ustawień i dostępności źródeł. DNS nie obejmuje wiarygodnie DoH/DoT/VPN ani nie przypisuje zapytań do procesu. W przypadku awarii samego agenta nie działa jeszcze niezależny supervisor systemowy.

## Dalsze prace wymagane do wizji pełnej usługi

Host SCM, pętla uruchamiania Engine i tworzenie chronionego katalogu danych są już w kodzie. Przed dostarczeniem funkcji użytkownikowi trzeba jeszcze dodać autoryzowany IPC i przekazanie zdarzeń do Agenta, uniknąć podwójnego monitorowania, spakować komponenty do katalogu chronionego przed zapisem, połączyć z UAC/instalatorem i skonfigurować odzyskiwanie/upgrade/uninstall. Host nie był rejestrowany ani uruchamiany jako usługa na tym komputerze; self-test ACL nie potwierdza rzeczywistego ACL ani działania SCM.
