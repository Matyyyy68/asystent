# CHANGELOG

## 2026-10-20 — weryfikacja ACL lokalnej historii

- Dodano Windows test potwierdzający, że SQLite nie inicjalizuje historii, gdy bieżący użytkownik nie może tworzyć plików w katalogu danych; test zawsze przywraca pierwotne ACL.
- Uodporniono test retry monitora procesu: wykrywa faktyczny brak miejsca dla małego zdarzenia, zamiast zakładać go po nieudanym większym zapisie.
- Rozszerzono `scripts/benchmark-engine.cjs` o `--tcp-monitor`, aby włączyć observer i zweryfikować kontrolowane nowe połączenie podczas profilu.
- Pięciominutowy soak TCP: 60 próbek co 5 s, kontrolowane połączenie zapisane, observer pozostał aktywny, 13 wpisów TCP bez pominiętych zmian; CPU 0,056%, working set 45,2–57 MiB, mediana collect 5,6 ms / max 675,9 ms. Jest to pojedynczy pomiar lokalny.
- Pełny zestaw .NET: 159/159 PASS. Fizyczny test pełnego wolumenu i ACL ścieżki po instalacji pozostają do wykonania.

## 2026-10-19 — kandydat 0.15.11

- Zdarzenie nowego połączenia TCP zawiera teraz informację, gdy ten sam PID został zapisany jako nowy proces w ciągu poprzednich 60 sekund. To lokalna korelacja czasowa, jawnie oznaczona jako informacyjna; nie zmienia oceny ryzyka. Pamięć korelacji jest ograniczona do 60 sekund i resetuje się wraz z silnikiem.
- Testy .NET: 158/158; Engine IPC, UI lint/build i produkcyjne buildy PASS. Windows CI build/test/self-test oraz Pages PASS; prerelease [v0.15.11](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.11) zawiera instalator 262489717 B, SHA-256 `3e20f1c1c175392e92a5c07ff4ee520895e37132a71c048219765feac4dd2786`.

## 2026-10-19 — kandydat 0.15.10

- Obserwatory procesów i TCP zachowują punkt odniesienia, dopóki nowe zdarzenia nie zostaną zapisane w historii. Przy `SQLITE_FULL` pokazują stan błędu i ponawiają zapis po odzyskaniu miejsca; test potwierdza zapis zdarzenia procesu po zwolnieniu miejsca.
- Testy .NET: 157/157. UI build/lint i Engine IPC PASS. Windows CI build/test/self-test oraz Pages PASS; prerelease [v0.15.10](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.10) zawiera instalator 262488693 B, SHA-256 `62b517bf665eb2e06f2f44c83524de34d541ea3031d24059f20cd9b3e7e61227`.

## 2026-10-19 — kandydat 0.15.9

- Ograniczono wzrost lokalnej historii SQLite do 512 MiB; przy pełnym dysku lub limicie transakcja jest odrzucana bez automatycznego kasowania starszych zdarzeń, a użytkownik dostaje czytelny komunikat. Test wymuszonego SQLITE_FULL potwierdza rollback batcha i zachowanie wcześniejszych wpisów.
- Testy .NET: 156/156; Engine IPC, build silnika i oba UI buildy PASS. Windows CI i Pages PASS; prerelease [v0.15.9](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.9) zawiera instalator 262488179 B, SHA-256 `12531dae03efe9323f5e92572145edd5c2088e132285c298b63cebbb6c866a3f`.

- Dodano jawny opt-in dla próbkowania TCP co 10 s. Natywny IP Helper zastępuje PowerShell przy snapshotach; nowe zewnętrzne połączenia `Established`/`SynSent` zapisują lokalnie tylko metadane, bez payloadu. Monitoring domyślnie pozostaje wyłączony, a krótkie połączenia mogą zostać pominięte.
- UI, README i strona opisują działanie oraz ograniczenia. Test live w Windows potwierdza wykrycie kontrolowanego nie-loopback połączenia. Testy .NET: 155/155; build silnika, IPC, lint UI i produkcyjny build UI PASS. Windows CI i Pages PASS; opublikowano prerelease [v0.15.8](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.8). Instalator ma 262487667 B, SHA-256 `9ea670966be6a7cb3cd818cc01d32a3276b1a0c78d94d1c6d68b3238d61c2d9a`.

## 2026-10-19 — wydanie testowe 0.15.7

- Pusta tabela domen nie jest już raportowana jako świeży feed, nawet jeśli pozostał aktualny znacznik pobrania. Dopasowanie domen pozostaje wyłączone w takim stanie.
- Dodano regresyjny test pustej bazy reputacji; pełny zestaw .NET przechodzi 152/152, `check-product`, TypeScript/lint i produkcyjny build UI PASS. Windows CI wykonał build, testy, self-test i opublikował prerelease [v0.15.7](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.7). Instalator ma 262481011 B, SHA-256 `8945010bc5fe4c1a73a99d23d883cacccccc7c345551902428569e4c920736f6`; Pages workflow PASS.

## 2026-10-19 — wydanie testowe 0.15.6

- Dodano integracyjny test limitu 20 mln indeksowanych znaków. Test wypełnia FTS5 do limitu i sprawdza, że nadmiarowy import jest odrzucony bez naruszenia istniejącego indeksu.
- Zmiana kodu limitu nie uległa zmianie względem wydania 0.15.5; klient przechodzi 151/151 testów, a `check-product` PASS. Windows CI wykonał build, testy i self-test oraz opublikował prerelease [v0.15.6](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.6). Installer ma 262481011 B, SHA-256 `c4c5b3bc34f5fd571269b586af214b5d7a771863165858473c69374a0a2f270d`; Pages workflow PASS.

## 2026-10-19 — wydanie testowe 0.15.5

- UI lokalnej bazy wiedzy pokazuje teraz limity 100 dokumentów i 20 mln znaków oraz wyjaśnia, że nadmiarowy import nie usuwa wcześniejszych dokumentów.
- Testy jednostkowe 150/150 przechodzą po zmianie logiki limitu w 0.15.4; `check-product`, TypeScript/lint i produkcyjny build UI przechodzą. GitHub Actions potwierdził Windows build/test/self-test i opublikował prerelease [v0.15.5](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.5). Instalator CI ma 262481011 B, SHA-256 `81fb4097a5bd9f72c47f3048ee73c81e664b282e7301f2de7b0a6f9c513a4fea`; Pages workflow również PASS.

## 2026-10-19 — wydanie testowe 0.15.4

- Ograniczono wzrost lokalnej bazy wiedzy: maksymalnie 100 dokumentów i 20 mln indeksowanych znaków. Odrzucony import nie narusza zapisanych danych.
- Testy klienta przechodzą 150/150, a GitHub Actions potwierdził Windows build/test/self-test i opublikował prerelease [v0.15.4](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.4). Instalator CI ma 262480499 B, SHA-256 `5ba6884efb926f3b6cf1814a611433f713a374b35593e8bfbd45df3d10821c7b`; workflow Pages również zakończył się sukcesem.

## 2026-10-19 — ograniczenie wzrostu lokalnej bazy wiedzy

- Import zatrzymuje się po 100 dokumentach lub 20 mln indeksowanych znaków. Transakcja odrzuca przekroczenie przed zapisem i nie usuwa starszych dokumentów; istniejąca treść pozostaje dostępna.
- Test sprawdza limit 100 dokumentów i potwierdza brak utraty istniejących wpisów przy odrzuceniu następnego.

## 2026-10-19 — wydanie testowe 0.15.3

- Dodano pomiar rozmiaru baz SQLite historii i wiedzy, w tym WAL/SHM, stron i rekordów.
- Monitor procesów zapisuje do 100 zmian jednej próbki w pojedynczej transakcji. CI wykazało, że 100 osobnych zapisów przekraczało 30 s na wolniejszym runnerze; test pokrywa atomowość błędnego batcha.
- Klient przechodzi 149/149 testów lokalnie; test syntetycznego zalewu PID spadł z około 50 s na CI do 183 ms lokalnie po batchowaniu. Pełny build instalatora i self-test PASS. Opublikowano [prerelease v0.15.3](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.3); CI zbudowało i zweryfikowało installer 262479987 B, SHA-256 `d6f29ebfd0928db63353c1b88216cac9bb97f47819e0431dee89ed4ec0d47e88`. Pages workflow PASS. Lokalny build ma 279280503 B i SHA-256 `B19AA84956674BDE9933735B8EB5D9AD06C3EDE18CB432447817D9DA9EBD5A4B`; to odrębny artefakt niż opublikowany build CI.

## 2026-10-19 — nieopublikowany kandydat 0.15.2

- Dodano diagnostykę rozmiaru plików SQLite historii i bazy wiedzy, w tym WAL/SHM, liczbę stron, wolne strony i rekordy; pomiar jest widoczny w sekcji prywatności.
- Dodano testy metryk obu baz oraz kontrolę statusu storage w smoke teście silnika. Klient przechodzi 148/148 testów .NET; check-product, TypeScript, IPC i self-test instalatora PASS.
- Workflow tagu `v0.15.2` nie przeszedł: test 10 000 zmian PID trwał 50 s przy progu 30 s. Poprawkę wydajnościową zawiera 0.15.3.

## 2026-10-19 — wydanie testowe 0.15.1

- Wydano poprawki audytu, monitoringu Enterprise i przywracania kopii serwera z Windows.
- Zweryfikowano 146/146 testów klienta, 19/19 testów API serwera, 2/2 testy restore backupu, testy witryny/lint/build oraz `--self-test` instalatora.
- Opublikowano prerelease [v0.15.1](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.1) z instalatorem 262475379 B oraz plikiem `.sha256`; workflow GitHub przeszedł build i self-test. SHA-256 instalatora: `B428155C0BA41306CAED43A5BF5B52BBAB7D0A490E4868A8E639540145ED38AA`.

## 2026-10-19 — audyt i lokalny kontrakt zdarzeń v1

- Dodano audyt luk, postęp prac i 10 planów wdrożenia, które rozdzielają zweryfikowane funkcje, braki i zewnętrzne ograniczenia.
- Dodano lokalnym zdarzeniom `schemaVersion`, stabilny GUID, źródło, wersję reguł, opcjonalną ocenę confidence oraz PID/nazwę procesu. SQLite migruje do v6 bez utraty historii; migracje z v3/v5, odczyt, ponowna inicjalizacja i eksport mają testy.
- Nie zapisuje się sztucznego confidence: deterministyczne reguły nie mają skalibrowanej pewności.
- Poprawiono nazwę nawigacji „Baza wiedzy” na „Reguły, reputacja i baza”, zgodnie z zawartością ekranu po podłączeniu lokalnego indeksu.
- Podłączono lokalne FTS5 do UI/IPC: jawny import TXT/MD/DOCX, wyszukiwanie, lista i usuwanie; test IPC sprawdza, że tekst dokumentu nie trafia do historii.
- Historia pokazuje pochodzenie i wersję reguł oraz umożliwia oznaczenie fałszywego alarmu.
- Podłączono opcjonalny provider Ollama do aktywnej analizy. Wybór modelu i opt-in są jawne; endpoint musi być loopback, a awaria modelu wraca do lokalnych reguł.
- Rozszerzony IPC smoke test weryfikuje odrzucenie zdalnego endpointu, działanie fałszywych alarmów oraz import/search/delete wiedzy.
- Zbudowano i uruchomiono `--self-test` instalatora 0.15.0 po integracji Enterprise i Authenticode: 279275383 B, SHA-256 `9DD5FFFA070DADA8CD818F09BFA46A4AB42550E78C172EFB30FA13ACF9DC013C`.
- Audyt npm wskazał 8 umiarkowanych alertów w dev-only łańcuchu electron-builder/sprintf-js bez opublikowanej poprawki; szczegóły i ograniczenie opisano w raporcie audytu.
- Ulepszono ręczny snapshot Windows do 800 połączeń TCP i 200 lokalnych punktów UDP z PID/nazwą procesu, jeśli dostępne. Loopback integration test potwierdza korelację obu protokołów; nie jest to monitoring ciągły.
- Dodano próbki widocznych procesów co 5 sekund z informacyjnymi zdarzeniami pojawienia/zniknięcia PID, pauzą, wykluczeniami i limitem 100 zdarzeń/próbkę. Test potomnego procesu weryfikuje oba przejścia.
- Dodano eksport historii JSON oraz kopie lokalnych baz historii/ustawień i wiedzy przez systemowy wybór pliku. UI ostrzega, że pliki są nieszyfrowane; testy IPC sprawdzają redakcję eksportu i format kopii SQLite, a test Core ponownie otwiera kopię bazy wiedzy.
- Skrypt budowania instalatora oblicza SHA-256 bez zależności od dostępności polecenia `Get-FileHash`; nowy build i instalacyjny self-test przechodzą.
- Dodano test integracyjny zalewu procesu: 10 500 syntetycznych PID weryfikuje limit 10 000 w migawce, limit 100 zapisów na próbkę oraz liczenie pominiętych zdarzeń podczas startu i zakończenia procesów.
- Diagnostyka pokazuje pamięć roboczą/prywatną i skumulowany czas CPU silnika; benchmark 300-sekundowy zebrał 60 próbek `collect`. Na bieżącej maszynie wynik wyniósł 43,4–53,8 MiB working set, 0,057% średniego CPU względem całkowitej mocy logicznych procesorów, medianę 5 ms i maksimum 1 359,8 ms. To pojedynczy pomiar bez wysokiego obciążenia syntetycznego.
- Test źródła procesu wymusza błąd odczytu, potwierdza komunikat diagnostyczny i brak zdarzeń, a następnie sprawdza odzyskanie i wznowienie zapisu; łącznie testy klienta: 137/137.
- Dodano przywracanie historii/ustawień i lokalnego indeksu wiedzy po kontroli integralności/schematu. Restore historii zachowuje profil instalacji, a restore FTS5 odtwarza dokumenty i wyszukiwanie. Testy potwierdzają round-trip i brak utraty przy uszkodzonej kopii; klient przechodzi 140/140 testów.
- Ręczna kontrola pliku do 256 MiB sprawdza SHA-256 oraz status podpisu Authenticode w izolowanym Windows PowerShell. Engine IPC testuje niepodpisany syntetyczny plik; hash i podpis nie są werdyktem bezpieczeństwa, reputacji nadal brak.
- Wyłączono SQLite pooling w testowych fixture'ach Enterprise, aby bazy tymczasowe były zwalniane przed usunięciem katalogów.
- Zaktualizowano rekomendację wariantu Enterprise: odróżnia teraz dostępne parowanie/heartbeat/politykę lokalną od brakującego serwerowego kontekstu, zatwierdzania i podpisanych aktualizacji.
- Dodano do aktywnego Electron parowanie Enterprise przez HTTPS z jednorazowym zaproszeniem i jawną zgodą; urządzeniowy token jest chroniony Windows DPAPI CurrentUser. Heartbeat, lokalna polityka (wspierany tryb local), oraz kolejka i synchronizacja samych metadanych działają po parowaniu. Kolejka jest ograniczona do 10 000 wpisów i nie wyrzuca oczekujących zdarzeń; UI pokazuje jej rozmiar. Odmowa blokuje parowanie i transmisję; odwołanie zgody zatrzymuje całe połączenie, usuwa oczekujące metadane, a klient odrzuca niepełne potwierdzenie batcha. Test DPAPI przeszedł poza sandboxem, a testy klienta rozszerzono do 145.
- Walidacja klienta .NET: 146/146 testów, w tym równoległe zapisy SQLite; test DPAPI przeszedł w interaktywnej sesji Windows (w sandboxie bez profilu DPAPI ścieżka testu jest pomijana).

## 2026-10-19 — naprawa i walidacja instalatora

- Naprawiono brak uprawnień `ALL APPLICATION PACKAGES` dla katalogu aplikacji; instalator teraz sprawdza wynik `icacls`, wymagany do uruchomienia sandboxa Chromium.
- Pasek postępu liczy rzeczywiście skopiowane bajty, anulowanie przerywa ekstrakcję i usuwa staging, a aktualizacja zachowuje pliki użytkownika spoza pakietu.
- Dodano log etapów instalacji, błędów ACL i rejestracji hosta oraz możliwość otwarcia logu z komunikatu błędu. Błędy hosta nie są już ignorowane.
- Odinstalowanie usuwa pliki aplikacji z pakietu, pozostawia dodatkowe pliki użytkownika i usuwa wyłącznie skróty wskazujące na instalację Sentinel AI.
- Test `--self-test` wykonuje instalację w katalogu tymczasowym, ustawia ACL i uruchamia aplikację w izolowanym profilu, sprawdzając renderer, IPC i silnik .NET. Smoke test nie zależy od zrzutu ekranu GPU.

## 2026-10-19 — biblioteka ilustracji Sentinel AI

- Zastąpiono starsze ilustracje z niepożądanymi tłami zestawem 63 nowych, minimalistycznych grafik PNG RGBA w siedmiu kategoriach.
- Zintegrowano przezroczyste grafiki z witryną, ekranami aplikacji i kreatorem własnego instalatora Windows; sześć ilustracji instalatora jest osadzanych w pliku EXE.
- Dodano katalog `media/illustrations/README.md` oraz test dekodujący PNG, który sprawdza rzeczywiste piksele alfa, format, wymiary i dokładne duplikaty.
- Podglądy wszystkich kategorii sprawdzono na jasnym i ciemnym tle; stare zasoby WebP nie są już używane i zostały usunięte.
- Workflow witryny włącza GitHub Pages przez `configure-pages`, jeśli repozytorium nie ma jeszcze ustawionego źródła publikacji.

## 2026-10-18 — 0.14.0, przebudowa Sentinel AI User (wersja rozwojowa)

### Zrealizowano

- Sklonowano repozytorium i przeprowadzono audyt. Przyczyną błędu hosta Chrome/Edge było odrzucanie argumentów origin i `--parent-window` przekazywanych przez Chromium; poprawiono walidację i dodano testy.
- Dodano React + TypeScript + Electron, proces silnika .NET z wersjonowanym IPC przez stdio, historię SQLite, reguły ręcznej analizy, sterowanie obserwacją, kreator pierwszego uruchomienia z trzema priorytetami, widok TCP i diagnostykę. WPF przeniesiono do `legacy/` i usunięto z aktywnego solution.
- Dodano dokładną reputację domen CERT Polska: IDN, deduplikację, limit, timeout, atomowy import, poprzednią kopię, wygaśnięcie i lokalne dopasowanie. Kolektor cache DNS Windows ostrzega po dopasowaniu, zapisuje zdarzenie i ogranicza powiadomienia.
- Dodano własną ikonę, motywy, dostępność, nowy dashboard i witrynę statyczną z rzeczywistym zrzutem aplikacji. Workflow Pages uruchamia się ręcznie, buduje i testuje stronę.
- Dodano markowy kreator NSIS oparty na Electron Builder z opisem prywatności i wyborem autostartu, rejestracją hosta, odinstalowaniem hosta i zachowaniem danych. Stare pliki instalatora pozostają historyczne.
- Zaktualizowano global.json do dostępnej linii SDK i poprawiono test zależny od separatora dziesiętnego w locale.
- Zaktualizowano instrukcje wersjonowania i integracji przeglądarek zgodnie z rzeczywistym IPC, bazą CERT i nowym skryptem wydania.
- Naprawiono start Electron na Windows: instalator przyznaje sandboxowi Chromium odczyt i wykonanie wyłącznie w katalogu programu. W katalogu builda brak tego ACE powodował awarię breakpoint `0x80000003`.

### Wykonane kontrole

- `dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release --no-restore`: 131/131.
- `dotnet publish` silnika i hosta dla win-x64: powodzenie.
- `node scripts/test-engine.cjs`: analiza → SQLite, prywatność, pauza, błędna metoda, usuwanie: powodzenie.
- `node scripts/test-engine.cjs --windows-live`: pobranie 125510 domen CERT Polska, odczyt cache DNS i TCP: powodzenie w środowisku testowym.
- `desktop: npm run build`: powodzenie. Test Electron renderer → kreator pierwszego uruchomienia (60 s) → preload → IPC → .NET w izolowanym profilu i zrzut UI: powodzenie.
- `website: npm test` oraz `npm run build -- --base=/asystent/`: powodzenie.
- Pełny `./scripts/build-user.ps1 -Installer`: powodzenie przed poprawką ACL; następnie `desktop: npm run package`: powodzenie z poprawką. Końcowy instalator x64 ma 155807626 bajtów, SHA-256 `84C8631F7029050F99BAC66278D4E72221C63286B5C37DA596E9F607D31FA2A5`.
- `node scripts/check-product.cjs`, `node scripts/test-engine.cjs` oraz `dotnet build Sentinel.sln -c Release --no-restore`: powodzenie; build .NET bez ostrzeżeń.
- Spakowany `Sentinel AI.exe` uruchomił się i przeszedł smoke test UI → preload → IPC → silnik .NET → SQLite po zastosowaniu testowego ACE dla AppContainer. Dla instalatora ten sam ACE jest teraz częścią NSIS.

### Pozostało przed wydaniem

- Należy jeszcze wykonać test pełnego cyklu życia na czystym Windows. Smoke test uruchomił aplikację z katalogu builda po dodaniu ACE dla AppContainer; test instalacji NSIS i realnego odinstalowania pozostaje do wykonania.
- Potwierdzić rozszerzenie w prawdziwych Chrome i Edge, autostart po logowaniu oraz UX wszystkich ekranów. Publikacja GitHub Pages pozostaje ręczna i nie została wykonana.
- WFP, blokowanie, pełna reputacja URL/IP, klasyfikacja plików i integracja AI w nowym UI nie istnieją. Witryna nie jest opublikowana. Ustalić licencję projektu i usunąć archiwum WPF po przeniesieniu funkcji.

Szczegóły i kroki testowe: `docs/KNOWN-LIMITATIONS.md` oraz `docs/USER-VALIDATION.md`.
