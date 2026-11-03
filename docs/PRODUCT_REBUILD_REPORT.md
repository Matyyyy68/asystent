# Raport przebudowy produktu Sentinel AI

**Stan: etap pośredni, cel z promptu nie jest ukończony.** Raport opisuje wyłącznie aktualny kod i wyniki testów; nie potwierdza pełnej ochrony ani gotowości wydania.

## 1. Interfejs

- Usunięto wybór profilu DNS z pierwszego uruchomienia.
- Pierwszy start ma osobny ekran sprawdzenia; zwykła nawigacja pojawia się po udanym `collect`.
- Podstawowa nawigacja pokazuje przegląd i zdarzenia. Pozostałe narzędzia są zwinięte pod „Narzędzia zaawansowane”; szczegóły monitorów na stronie przeglądu są dodatkowo zwinięte pod „Szczegóły monitorowania”.
- Status rozróżnia brak silnika, pierwsze sprawdzenie, pauzę, ograniczenie monitora, stan Windows wymagający uwagi, stan Windows niepotwierdzony i działające źródła. Główny widok pokazuje czas zakończenia ostatniego poprawnego cyklu przekazany przez Engine; po restarcie Engine pole wraca po następnym udanym cyklu. Sukces oznacza „Monitorowanie działa”, nie aktywne blokowanie.
- Historia zdarzeń tłumaczy ryzyko i status na język polski. Źródło, wersja reguł i kody dowodów są rozwijane na żądanie; użytkownik może odróżnić zdarzenie „Sprawdzone” od „Fałszywego alarmu”.

## 2. Instalator

- Ekran startowy ma duży przycisk „ZAINSTALUJ”; lokalizacja i skróty pozostają opcjonalnymi ustawieniami zaawansowanymi.
- Świeża ścieżka przechodzi przez preflight, lokalny payload, konfigurację i weryfikację.
- Payload i instalacja sprawdzają obecność silnika, agenta, Core i Contracts.
- Agent ma być uruchomiony od razu i przy logowaniu. Przy aktualizacji instalator prosi o zamknięcie agenta, a przy rollbacku próbuje go wznowić.
- Lokalny offline build nie mógł zbudować produkcyjnego pakietu, bo `node_modules` zawiera Electron 44.9.1, a lockfile wymaga `^45.0.0`; nie pobierałem zależności na komputer użytkownika. Windows CI zbudował pakiet przy użyciu wymaganej wersji Electron 45.

## 3. Pierwsze sprawdzenie

- UI wykonuje lokalny `collect`, odświeża stan i zapisuje ukończenie dopiero po powodzeniu.
- Podczas pierwszego cyklu Engine odczytuje nazwy, wersje i wydawców z rejestru deinstalacji Windows w widokach 64/32-bit oraz HKCU. Szczegóły są dostępne wyłącznie lokalnie w rozwiniętych detalach UI; nie czyta się poleceń/ścieżek instalacji i nie zapisuje inwentarza do historii.
- Odczyt listy zainstalowanych aplikacji nie mapuje wersji do CVE ani nie potwierdza aktualności programów lub Defendera.
- Przy błędzie nie pokazuje udanej analizy; pozwala ponowić próbę.
- To nie jest pełny skan dysku ani werdykt o bezpieczeństwie komputera.

## 4. Mechanizmy Windows

- Procesy: cykliczne snapshoty PID/nazw, kontrola obrazów i ograniczona korelacja relacji rodzic–potomek z Toolhelp. Reguła Office → interpreter/skrypt daje umiarkowane ostrzeżenie, nie blokadę ani werdykt malware.
- Downloads: FileSystemWatcher i uzgadnianie katalogu Downloads.
- Trwałość: snapshoty rejestru Run/RunOnce, Startup, zadań harmonogramu oraz wybranych usług/sterowników.
- Sieć: snapshoty TCP/UDP, bez treści ruchu.
- DNS: lokalny cache `ipconfig /displaydns`; dziennik DNS Operational tylko jeśli jest dostępny/włączony.
- Windows Security Center: tylko do odczytu, stan zagregowany kategorii antywirusa i zapory, cache jednej minuty. Nie identyfikuje produktu ani wersji sygnatur.

Nowe profile domyślnie włączają lokalne monitorowanie procesów, Downloads, trwałości i TCP/UDP. Zapisane wcześniej preferencje nie są nadpisywane. Zbieranie tekstu aktywnego okna i autoaktualizacja zewnętrznych list pozostają wyłączone.

## 5. Zakres obserwacji

- Są to snapshoty i wybrane zdarzenia z określonymi odstępami; krótkie procesy i połączenia mogą zostać pominięte.
- Hash plików porównuje się z lokalnie zaimportowaną listą. Brak dopasowania ani podpis cyfrowy nie dowodzą bezpieczeństwa.
- DNS nie obejmuje wiarygodnie DoH/DoT/VPN i nie przypisuje zapytań do procesu.
- WFP, pełne ETW/Security Center integration, skanowanie wszystkich plików i aktywne blokowanie nie są wdrożone.

## 6. Silnik detekcji

- Istniejące reguły, lokalne listy reputacji i obserwacje systemowe zapisują ustrukturyzowane zdarzenia z ryzykiem, źródłem, uzasadnieniem, zaleceniem i statusem.
- Po odczytaniu obrazu procesu Engine koreluje go z najbliższym, kompatybilnym zdarzeniem Downloads po identycznym SHA-256 i oknie czasu ±10 minut. Nie łączy niezależnych dopasowań tego samego hasha. Ten dowód nie potwierdza bezpośredniej ścieżki uruchomienia.
- Lokalny model AI pozostaje opcjonalny; brak modelu nie wyłącza reguł.
- Ręczna kwarantanna jest dostępna tylko dla nowego pliku z Downloads, którego SHA-256 dopasowano do lokalnej listy. Electron wymaga osobnego potwierdzenia, a Engine sprawdza hash przy wybranym pliku, bez uruchamiania i bez nadpisywania. Przywrócenie jest jawne i ponownie kontroluje hash. Automatyczna kwarantanna, usuwanie i blokada wykonania nie są wdrożone.

## 7. Powiadomienia i dźwięk

- Agent pokazuje baloniki dla lokalnych dopasowań DNS i hashy plików pobranych oraz nowych procesów, połączeń TCP do zaimportowanych adresów IP, zmian autostartu w lokalizacjach zapisywalnych przez użytkownika oraz dla antywirusa/zapory, gdy Windows Security Center zgłasza stan wymagający uwagi lub brak monitorowania. Alerty mają limit 10 minut per typ; różne sygnały wykryte w jednym cyklu są grupowane do jednego krótkiego balonika, którego kliknięcie otwiera aplikację.
- Agent generuje lokalnie trzy krótkie, ciche tony Sentinel w formacie PCM WAV. Aktualne sygnały agenta mają poziom ostrzeżenia i odtwarzają ton ostrzegawczy; wzorce informacji i poważnego ostrzeżenia są przygotowane, ale nie są jeszcze przypisane do odrębnych typów zdarzeń. Awaria urządzenia audio nie zatrzymuje agenta. Odtwarzania na fizycznej aktywnej sesji Windows nie zweryfikowano.
- Ikona zasobnika zmienia się przy alertach i błędzie silnika.
- Menu zasobnika ma skrót „Ostatnie alerty”, który otwiera historię zdarzeń w Electron.
- Menu zasobnika oferuje ręczne sprawdzenie najnowszego stabilnego wydania przez GitHub API. Użytkownik sam otwiera stronę wydania; brak automatycznego pobierania, weryfikowanego manifestu i instalacji aktualizacji.
- Korelacja obserwacji dotyczących tego samego incydentu między źródłami oraz test dźwięku w aktywnej sesji Windows pozostają do wykonania.

## 8. Menu kontekstowe

- Per-user wpis „Sprawdź w Sentinel AI” obsługuje jeden plik.
- Analiza lokalna liczy SHA-256, odczytuje Authenticode i pokazuje ograniczony komunikat. Nie uruchamia, nie usuwa ani nie blokuje pliku.
- Deinstalator usuwa tylko własny wpis. Widoczność wpisu w Explorerze na czystym Windows 10/11 nie została tu przetestowana.

## 9. Autonomia

- `Sentinel.Agent` i jego watchdog działają w sesji użytkownika; agent odpytuje Engine niezależnie od okna Electron.
- Watchdog wznawia awarię procesu agenta z backoffem 1–30 s; agent odtwarza proces Engine po błędzie.
- Zamknięcie UI nie kończy Core. Instalator zatrzymuje i próbuje wznowić Core przy zmianie plików.
- Watchdog sam nie jest odzyskiwany po awarii; nie jest to usługa Windows SCM/LocalSystem i nie działa przed logowaniem.

## 10. Prywatność i ograniczenia

- Domyślne obserwacje oraz historia są lokalne; SQLite nie jest szyfrowana.
- Tekst okien, hasła, klawiatura, ekran, treść HTTPS i prywatne pliki nie są ukrycie przechwytywane ani wysyłane.
- Sentinel nie zastępuje Microsoft Defender, nie identyfikuje konkretnego programu AV z samego zagregowanego WSC i nie blokuje ruchu.

## 11. Walidacja wykonana

- Bieżący checkout zawiera inwentarz nazw, wersji i wydawców z rejestru oraz ograniczony do 3 s czas oczekiwania na jego odczyt. Lokalnie: pełne .NET 441 PASS + 2 środowiskowe SKIP; testy desktop 79/79, lint i produkcyjny Vite (1584 moduły) PASS; Engine publish i IPC inventory PASS. Dokładna korelacja Downloads → proces ma testy .NET dla zgodnego hasha, niewłaściwego hasha i starego zdarzenia. Pełny Windows CI nowego commita oczekuje.
- Windows CI [41696210343](https://github.com/Matyyyy68/asystent/actions/runs/41696210343) dla `dcb6d01` PASS we wszystkich 20 krokach: testy/build, Electron smoke, Downloads/junction, autostart, Chrome/Edge, headless install/update/uninstall, widoczny kreator i Enterprise API. Potwierdza test na izolowanym runnerze Windows, nie na komputerze użytkownika.
- Wcześniejsze walidacje: Windows CI 41673687559 i 41679066451 dla uproszczenia strony/alertów oraz 41685182964 dla instalatora i ograniczenia statusu DNS również zakończyły się PASS.
- Setup Release oraz `--wizard-self-test`: wcześniejsze przejścia PASS; bieżący Windows CI zbudował i przetestował pełny instalator oraz cykl kreatora.
- `git diff --check`: bez błędów whitespace; Git zgłasza tylko przewidywaną konwersję LF/CRLF.
- Testy polityki alertów WSC obejmują stany zdrowy, wymagający uwagi, nieobserwowany, wstrzymany i niedostępny. Testy streszczeń baloników sprawdzają deduplikację kategorii, limit długości Windows i obsługę pustej paczki.
- Test monitora TCP potwierdza, że pojedyncze nowe dopasowanie lokalnego IP jest przekazywane do alertu, a kolejny zwykły cykl zwraca zero dopasowań. Test IPC Engine sprawdza zerową wartość dla bazowej próbki.
- Test monitora trwałości potwierdza alertowalny licznik wyłącznie dla zapisanej zmiany w lokalizacji zapisywalnej przez użytkownika i zeruje go w kolejnym niezmienionym cyklu.
- Test kolejki inspekcji obrazu procesu potwierdza dedykowany licznik po udanym dopasowaniu lokalnego SHA-256 i jego jednorazowy odbiór przez agenta.
- Testy relacji procesów pokrywają regułę Office → interpreter, umiarkowane ryzyko, dowody rodzic/child, limit alertu do bieżącego cyklu i działanie odczytu Toolhelp na Windows.
- Windows CI run [41657844276](https://github.com/Matyyyy68/asystent/actions/runs/41657844276): build aplikacji/pakietu, testy źródeł, smoke Electron, Downloads, autostart, Chrome/Edge E2E i E2E z zainstalowanym hostem — PASS. Aktualizacja ujawniła błąd podwójnego `Dispose` w `ApplicationContext`: wyjątek .NET powodował ponowne uruchamianie agenta przez watchdog. Po naprawie idempotentnego sprzątania pełny Windows CI [41666279158](https://github.com/Matyyyy68/asystent/actions/runs/41666279158) zakończył się PASS. Dla commita `f42108a` run [41671769059](https://github.com/Matyyyy68/asystent/actions/runs/41671769059) przeszedł 419 testów .NET, ale test ujawnianej wersji reguł wykrył nieaktualny tekst UI; poprawka jest w `6fe951e`, run [41673687559](https://github.com/Matyyyy68/asystent/actions/runs/41673687559) dla `6fe951e` zakończył się PASS we wszystkich 20 krokach: build/test, Electron smoke, izolowany Downloads i junction soak, autostart Windows, Chrome/Edge, headless install/update/uninstall, widoczny kreator oraz API Enterprise.
- W odpowiedzi na awarię zatrzymania Core w widocznym teście kreatora dodano ograniczone, bezpieczne ponawianie polecenia shutdown. Osobno naprawiono stan główny UI: błąd lub brak pierwszego odczytu cache DNS obniża go do „Ochrona ograniczona”, a rozwinięte szczegóły pokazują również opcjonalny kanał DNS Operational. Testy desktop: 70/70 PASS. Windows CI [41685182964](https://github.com/Matyyyy68/asystent/actions/runs/41685182964) dla commita `c0061cd` zakończył się PASS we wszystkich krokach, w tym widocznym cyklu install/repair/uninstall po retry shutdown. Test potwierdza działanie na jednorazowym Windows runnerze, nie na komputerze odbiorcy.
- Po uproszczeniu prezentacji historii desktop ma 74/74 testy PASS, lint TypeScript/Node PASS, a `Sentinel.Agent` buduje się bez ostrzeżeń i błędów. Testy sprawdzają polskie etykiety także w grupach, oddzielenie „Sprawdzone” od „Fałszywego alarmu”, chowanie metadanych technicznych oraz trasę „Ostatnie alerty” dla zimnego startu i działającej instancji. Pełny Windows CI tych zmian oczekuje.
- Pełny packaging offline przerwał się przed budowaniem z powodu lokalnego Electron 44.9.1 vs wymagane `^45.0.0`. Nie instalowano zależności ani niczego nie pobierano.
- Windows CI dla `c7b56bc` został anulowany podczas budowania po wypchnięciu następnego commita; nie jest wynikiem PASS. CI dla bieżącego `a972a71` (run [41701134976](https://github.com/Matyyyy68/asystent/actions/runs/41701134976)) wystartował i jest w trakcie audytu NuGet; jego wynik pozostaje nieznany.

## 12. Pozostałe prace

- Windows CI [41696210343](https://github.com/Matyyyy68/asystent/actions/runs/41696210343) dla `dcb6d01` PASS we wszystkich krokach: build i testy źródeł, Electron smoke, Downloads/junction, autostart, Chrome/Edge, headless instalacja/aktualizacja/deinstalacja, widoczny kreator oraz Enterprise API. Potwierdza izolowany runner; nie zastępuje fizycznego testu na czystym Windows 10/11.
- Bieżące `a972a71` zawiera ograniczenie oczekiwania na rejestr, z testem lokalnym w pełnym .NET suite (439 PASS, 2 środowiskowe SKIP); pełny Windows CI tego commita nadal działa i nie ma jeszcze wyniku końcowego.
- Korelacja obrazu procesu z pasującym hashem pobranego pliku jest lokalnie zweryfikowana w pełnym .NET suite; potrzebuje pełnego Windows CI po push.
- Agent i watchdog pozostają user-mode: nie ma usługi SCM, pracy przed logowaniem ani niezależnego recovery samego watchdoga.
- Rozszerzyć wspólną korelację między źródłami, inwentaryzację informacji dostępnych podczas pierwszej analizy oraz bezpieczne, uzasadnione reakcje. Nie implementować twierdzeń o blokadzie bez działającego mechanizmu.
- Dodać podpisany manifest i bezpieczny updater aplikacji; aktualny check jedynie wskazuje stronę stabilnego wydania. WSC nie określa produktu AV ani wersji sygnatur.
- Zweryfikować widoczność menu Explorer i dźwięk w aktywnej sesji na czystym fizycznym Windows. Bieżące CI testuje runner izolowany.
- Licencję źródeł wskaże właściciel później; nie wybierać jej bez jego decyzji. Bieżąca zmiana nie tworzy podpisanego ani opublikowanego instalatora; publicznym wydaniem pozostaje v0.15.38.
- Nie oznaczać celu jako ukończonego do czasu domknięcia pozostałych punktów lub jawnego zawężenia zlecenia przez właściciela.
