# Raport przebudowy produktu Sentinel AI

**Stan: etap pośredni, cel z promptu nie jest ukończony.** Raport opisuje wyłącznie aktualny kod i wyniki testów; nie potwierdza pełnej ochrony ani gotowości wydania.

**Najnowsze potwierdzenie:** pełny Windows CI [41891594622](https://github.com/Matyyyy68/asystent/actions/runs/41891594622) dla `83e1b7f` zakończył PASS: .NET 459/459, live SCM status/history pipe i Agent pipe, Electron smoke, Downloads + soak junctionów, autostart, Chrome/Edge, headless i widoczny cykl instalatora oraz Enterprise API 23/23 + HTTP smoke. Wcześniejsze błędy pipe w tym cyklu diagnostycznym zostały rozwiązane dla zatwierdzonego commita; rezultat nie zastępuje testu czystego, fizycznego komputera Windows. Nierozwiązane ograniczenia wymieniono niżej.

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
- Microsoft Defender: odrębne, lokalne zapytanie `Get-MpComputerStatus` raportuje jego włączenie, ochronę w czasie rzeczywistym, wersję i wiek sygnatur. Odświeża się co 5 minut (po błędzie co 15 minut), ma timeout 4 s i stan niedostępny, jeśli cmdlet nie działa. Na środowisku testowym WMI odmówiło dostępu; stan ten nie jest mylony z zagregowanym WSC ani alternatywnym AV.

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
- Agent generuje lokalnie cztery krótkie, ciche tony Sentinel w formacie PCM WAV: informacyjny, ostrzegawczy, krytyczny i zakończenia analizy. Dopasowania do lokalnej reputacji SHA-256/IP, której źródła nie zweryfikowano, odtwarzają ton informacyjny; DNS, WSC oraz heurystyki autostartu i relacji procesów odtwarzają ostrzegawczy. Zgrupowane sygnały wybierają najwyższą wagę. Ton krytyczny pozostaje nieużywany, bo Sentinel nie ma aktywnej blokady. Po pierwszym poprawnym cyklu monitorowania ton zakończenia jest odtwarzany raz na profil użytkownika, o ile cykl nie zgłosił alertu. Awaria urządzenia audio nie zatrzymuje agenta. Odtwarzania na fizycznej aktywnej sesji Windows nie zweryfikowano.
- Ikona zasobnika zmienia się przy alertach i błędzie silnika.
- Menu zasobnika ma skrót „Ostatnie alerty”, który otwiera historię zdarzeń w Electron.
- Menu zasobnika oferuje ręczne sprawdzenie najnowszego stabilnego wydania przez GitHub API. Użytkownik sam otwiera stronę wydania; brak automatycznego pobierania, weryfikowanego manifestu i instalacji aktualizacji.
- Korelacja obserwacji dotyczących tego samego incydentu między źródłami oraz test dźwięku w aktywnej sesji Windows pozostają do wykonania.

## 8. Menu kontekstowe

- Per-user wpis „Sprawdź w Sentinel AI” obsługuje zaznaczenie do 15 plików. Explorer uruchamia komendę dla elementów zaznaczenia, a pojedyncza instancja Sentinel grupuje ścieżki, kolejno wykonuje lokalne sprawdzenie i prezentuje jeden raport zbiorczy. Duplikaty ścieżek są deduplikowane, a batch jest ograniczony do 15 plików.
- Analiza lokalna liczy SHA-256 i odczytuje Authenticode; komunikat pokazuje te sygnały oddzielnie dla każdego pliku. Nie uruchamia, nie usuwa ani nie blokuje pliku, a brak dopasowania lub prawidłowy podpis nie gwarantują bezpieczeństwa.
- Instalator ustawia `MultiSelectModel=Document`, weryfikuje ten stan i przy deinstalacji usuwa go tylko wtedy, gdy wartość nadal jest własna. Microsoft opisuje model `Document` jako ograniczony do 15 elementów; widoczność menu i rzeczywista selekcja wielu plików w Explorerze na czystym Windows 10/11 nadal wymagają testu integracyjnego ([dokumentacja Microsoft](https://learn.microsoft.com/en-us/windows/win32/shell/how-to-employ-the-verb-selection-model)).

## 9. Autonomia

- `Sentinel.Agent` i jego watchdog działają w sesji użytkownika; agent odpytuje Engine niezależnie od okna Electron.
- Watchdog wznawia awarię procesu agenta z backoffem 1–30 s; agent odtwarza proces Engine po błędzie.
- Zamknięcie UI nie kończy Core. Instalator zatrzymuje i próbuje wznowić Core przy zmianie plików.
- Watchdog sam nie jest odzyskiwany po awarii. Host SCM działa jako LocalService z chronionym Program Files/ProgramData. Instalator żąda jawnego UAC; UI odczytuje heartbeat i do 12 ostatnich wpisów usługi, pozwala zmienić ich status, Połączona lista pozwala pobierać starsze strony po 12 wpisów (odczyt Engine do 500 retained); pełny live pipe przeszło w CI 41891594622. Nadal nie scala baz ani nie deduplikuje wspólnych sygnałów. Lokalna zmiana dodaje maksymalnie 500 zachowanych zdarzeń usługi do JSON i CSV eksportów z kolumną origin; .NET 457/459 (2 środowiskowe SKIP), desktop 101/101, lint i UI build przechodzą. Windows CI tej integracji jeszcze nie sprawdził. Start przed logowaniem nie był testowany na fizycznym systemie, a publiczne wydanie v0.15.38 nie zawiera aktualnego hosta. Agent i usługa prowadzą oddzielne silniki i bazy, więc wspólne monitorowanie może się dublować.

## 10. Prywatność i ograniczenia

- Nowe profile odświeżają lokalny feed domen CERT przez stały HTTPS endpoint co 24 h; żądanie nie zawiera analizowanych adresów. Użytkownik może wyłączyć tę funkcję w narzędziach zaawansowanych; zapisane ustawienie false jest zachowane. To nie jest reputacja plików/IP ani niezależna weryfikacja wydawcy.

- Domyślne obserwacje oraz historia są lokalne; SQLite nie jest szyfrowana.
- Tekst okien, hasła, klawiatura, ekran, treść HTTPS i prywatne pliki nie są ukrycie przechwytywane ani wysyłane.
- Sentinel nie zastępuje Defendera ani innego AV, nie włącza/wyłącza ochrony i nie blokuje ruchu. Szczegóły Defendera są niedostępne tam, gdzie cmdlet nie działa; WSC nadal nie ustala nazwy alternatywnego AV.

## 11. Walidacja wykonana

- Bieżący checkout zawiera inwentarz nazw, wersji i wydawców z rejestru, limit 3 s oczekiwania, korelację Downloads → proces po najbliższym zgodnym SHA-256 oraz warunkowy odczyt Defendera. Lokalnie: pełne .NET 457 PASS + 2 środowiskowe SKIP; desktop 96/96, lint i Release buildy bez ostrzeżeń/błędów PASS. Windows CI [41864826701](https://github.com/Matyyyy68/asystent/actions/runs/41864826701) potwierdził automatyczny feed CERT, obniżenie statusu UI przy braku heartbeat, .NET 452/452 i wszystkie kroki workflow. Run [41889366362](https://github.com/Matyyyy68/asystent/actions/runs/41889366362) dla historii przeszedł build, ale żywy pipe zakończył EOF po `InvalidOperationException` (`0x80131509`) w `stage=write-response`. Nowy logger dodaje ograniczone nazwy metod stosu, bez argumentów i treści zdarzeń; lokalny build usługi przechodzi, a nowy Windows CI jeszcze nie. Agent zapisuje preferencję powiadomień do małego pliku stanu, a testy potwierdzają jej odczyt po restarcie. Cmdlet Defendera zwrócił Access Denied (`0x80041003`) w lokalnym środowisku, więc jego status jest jawnie niedostępny, a nie zgadywany.
- Windows CI [41696210343](https://github.com/Matyyyy68/asystent/actions/runs/41696210343) dla `dcb6d01` PASS we wszystkich 20 krokach: testy/build, Electron smoke, Downloads/junction, autostart, Chrome/Edge, headless install/update/uninstall, widoczny kreator i Enterprise API. Potwierdza test na izolowanym runnerze Windows, nie na komputerze użytkownika.
- Wcześniejsze walidacje: Windows CI 41673687559 i 41679066451 dla uproszczenia strony/alertów oraz 41685182964 dla instalatora i ograniczenia statusu DNS również zakończyły się PASS.
- Setup Release oraz `--wizard-self-test`: wcześniejsze przejścia PASS; bieżący Windows CI zbudował i przetestował pełny instalator oraz cykl kreatora.
- `git diff --check`: bez błędów whitespace; Git zgłasza tylko przewidywaną konwersję LF/CRLF.
- Aktualizacja 2026-11-04: Windows CI [41734288659](https://github.com/Matyyyy68/asystent/actions/runs/41734288659) zakończył się PASS po poprawce ACL wykrytej w [41731627812](https://github.com/Matyyyy68/asystent/actions/runs/41731627812). Pełny run potwierdził build oraz testy .NET 452/452, host SCM LocalService/ACL/first collect/status pipe, Electron smoke, Downloads i 120-sekundowy soak junction, autostart, Chrome/Edge E2E, headless install/verify/uninstall, widoczny install/repair/update/uninstall i Enterprise API. Test wykonano na izolowanym runnerze Windows, nie na komputerze odbiorcy. Lokalnie desktop ma 90/90 testów i lint PASS; Setup Release 0 ostrzeżeń/błędów; produkcyjny Vite build PASS z `--configLoader runner`. Nie uruchomiono instalatora na komputerze użytkownika.
- Testy polityki alertów WSC obejmują stany zdrowy, wymagający uwagi, nieobserwowany, wstrzymany i niedostępny. Testy streszczeń baloników sprawdzają deduplikację kategorii, limit długości Windows i obsługę pustej paczki.
- Test monitora TCP potwierdza, że pojedyncze nowe dopasowanie lokalnego IP jest przekazywane do alertu, a kolejny zwykły cykl zwraca zero dopasowań. Test IPC Engine sprawdza zerową wartość dla bazowej próbki.
- Test monitora trwałości potwierdza alertowalny licznik wyłącznie dla zapisanej zmiany w lokalizacji zapisywalnej przez użytkownika i zeruje go w kolejnym niezmienionym cyklu.
- Test kolejki inspekcji obrazu procesu potwierdza dedykowany licznik po udanym dopasowaniu lokalnego SHA-256 i jego jednorazowy odbiór przez agenta.
- Testy relacji procesów pokrywają regułę Office → interpreter, umiarkowane ryzyko, dowody rodzic/child, limit alertu do bieżącego cyklu i działanie odczytu Toolhelp na Windows.
- Windows CI run [41657844276](https://github.com/Matyyyy68/asystent/actions/runs/41657844276): build aplikacji/pakietu, testy źródeł, smoke Electron, Downloads, autostart, Chrome/Edge E2E i E2E z zainstalowanym hostem — PASS. Aktualizacja ujawniła błąd podwójnego `Dispose` w `ApplicationContext`: wyjątek .NET powodował ponowne uruchamianie agenta przez watchdog. Po naprawie idempotentnego sprzątania pełny Windows CI [41666279158](https://github.com/Matyyyy68/asystent/actions/runs/41666279158) zakończył się PASS. Dla commita `f42108a` run [41671769059](https://github.com/Matyyyy68/asystent/actions/runs/41671769059) przeszedł 419 testów .NET, ale test ujawnianej wersji reguł wykrył nieaktualny tekst UI; poprawka jest w `6fe951e`, run [41673687559](https://github.com/Matyyyy68/asystent/actions/runs/41673687559) dla `6fe951e` zakończył się PASS we wszystkich 20 krokach: build/test, Electron smoke, izolowany Downloads i junction soak, autostart Windows, Chrome/Edge, headless install/update/uninstall, widoczny kreator oraz API Enterprise.
- W odpowiedzi na awarię zatrzymania Core w widocznym teście kreatora dodano ograniczone, bezpieczne ponawianie polecenia shutdown. Osobno naprawiono stan główny UI: błąd lub brak pierwszego odczytu cache DNS obniża go do „Ochrona ograniczona”, a rozwinięte szczegóły pokazują również opcjonalny kanał DNS Operational. Testy desktop: 70/70 PASS. Windows CI [41685182964](https://github.com/Matyyyy68/asystent/actions/runs/41685182964) dla commita `c0061cd` zakończył się PASS we wszystkich krokach, w tym widocznym cyklu install/repair/uninstall po retry shutdown. Test potwierdza działanie na jednorazowym Windows runnerze, nie na komputerze odbiorcy.
- Po uproszczeniu prezentacji historii desktop ma 74/74 testy PASS, lint TypeScript/Node PASS, a `Sentinel.Agent` buduje się bez ostrzeżeń i błędów. Testy sprawdzają polskie etykiety także w grupach, oddzielenie „Sprawdzone” od „Fałszywego alarmu”, chowanie metadanych technicznych oraz trasę „Ostatnie alerty” dla zimnego startu i działającej instancji. Pełny Windows CI tych zmian oczekuje.
- Pełny packaging offline przerwał się przed budowaniem z powodu lokalnego Electron 44.9.1 vs wymagane `^45.0.0`. Nie instalowano zależności ani niczego nie pobierano.
- Starsze runy `c7b56bc` i `a972a71` zostały anulowane po wypchnięciu kolejnych commitów; nie są wynikami PASS.

## 12. Pozostałe prace

- Windows CI [41734288659](https://github.com/Matyyyy68/asystent/actions/runs/41734288659) PASS we wszystkich krokach, w tym budowa pełnego instalatora i instalacja/naprawa/aktualizacja/deinstalacja headless oraz widoczny kreator. Potwierdza izolowany Windows runner; nie zastępuje fizycznego testu na czystym Windows 10/11. Wymuszony rollback helpera potwierdził nowszy CI [41856785028](https://github.com/Matyyyy68/asystent/actions/runs/41856785028).
- Odczyt Defendera i korelacja obrazu procesu z pasującym hashem pobranego pliku są lokalnie zweryfikowane; potrzebują pełnego Windows CI najnowszego commita.
- Instalator SCM i status heartbeat w UI przeszły install/repair/update/uninstall w Windows CI [41734288659](https://github.com/Matyyyy68/asystent/actions/runs/41734288659). Test wymuszonego rollbacku helpera przeszedł w CI [41856785028](https://github.com/Matyyyy68/asystent/actions/runs/41856785028). UI pobiera teraz ograniczoną historię usługi, ale wspólna baza, pełny eksport, deduplikacja i wspólna korelacja nadal nie istnieją; Windows CI dla tej zmiany oczekuje. Start usługi przed logowaniem na fizycznym systemie pozostaje niezweryfikowany.
- Rozszerzyć wspólną korelację między źródłami, inwentaryzację informacji dostępnych podczas pierwszej analizy oraz bezpieczne, uzasadnione reakcje. Nie implementować twierdzeń o blokadzie bez działającego mechanizmu.
- Dodać podpisany manifest i bezpieczny updater aplikacji; aktualny check jedynie wskazuje stronę stabilnego wydania. WSC nie określa nazwy alternatywnego AV; szczegółowe sygnatury Defendera są zależne od dostępu WMI.
- Zweryfikować widoczność menu Explorer i dźwięk w aktywnej sesji na czystym fizycznym Windows. Bieżące CI testuje runner izolowany.
- Licencję źródeł wskaże właściciel później; nie wybierać jej bez jego decyzji. CI zbudował artefakt v0.15.39, ale nie został on podpisany ani opublikowany; publicznym wydaniem pozostaje v0.15.38.
- Nie oznaczać celu jako ukończonego do czasu domknięcia pozostałych punktów lub jawnego zawężenia zlecenia przez właściciela.
