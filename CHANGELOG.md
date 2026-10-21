# CHANGELOG

## Unreleased

- Bieżący build po poprawce atomowego cofania zgody: pełny `scripts/build-user.ps1 -Installer` PASS, .NET 227/227 bez pominięć, Engine IPC, procesy, Windows DNS/TCP/UDP, desktop 9/9, `npm audit` 0, UI build i autotest instalatora PASS. Nieopublikowany instalator v0.15.38: 281235321 B, SHA-256 `2D9A1649EC3EEC15512283D4D50CAFF1A95A6D2B23DE17925B451FC9A3706714`. Windows CI `39663289184` PASS.
- Cofnięcie zgody Enterprise i usunięcie zarówno standardowej, jak i odroczonej kolejki odbywają się teraz w jednej transakcji SQLite. Awaria czyszczenia cofa też zmianę zgody, więc nie zostaje stan, który mógłby ponownie wysłać stare metadane po późniejszym włączeniu. Test wstrzykuje błąd SQLite i sprawdza rollback profilu oraz outboxa; Release .NET 225 PASS / 2 testy platformowe pominięte.
- Pełna walidacja SQLite v17: .NET 225/225 bez pominięć, Engine IPC, procesy, Windows DNS/TCP/UDP, desktop 9/9, `npm audit` 0 podatności, UI build i autotest instalatora PASS. Lokalny, nieopublikowany instalator v0.15.38 ma 281235321 B i SHA-256 `003B2F198C6C88F654D381EE9D26146FB5B4CD877D0BE9468BBD10FAA8E184B3`. CI `39661127030` PASS.
- Dodano regresję backup/restore: deferred metadata przetrwa pełną kolejkę 10 000 rekordów, kopię i przywrócenie do innej bazy. Release .NET testy: 224 PASS, 2 platformowe pominięte.
- Aktywny `RecordDetectionAsync` zapisuje teraz zdarzenie i jawnie skategoryzowany wpis Enterprise w jednej transakcji SQLite; wcześniej omijał atomowy `AddAsync`. Przy limicie 10 000 wpisów lokalne wykrycie zostaje zapisane, a silnik zachowuje status `queue_full`. Testy sprawdzają zapis kategorii/kodu, wycofanie obu rekordów po awarii kolejki oraz zachowanie wykrycia i sygnału pełnej kolejki. Pełna walidacja lokalna: .NET 225/225 bez pominięć, Engine IPC, Windows DNS/TCP/UDP, desktop 9/9, `npm audit` 0 podatności, UI build i installer self-test PASS. Windows CI `39659219376` PASS. Lokalny instalator testowy 281233785 B, SHA-256 `889B97C46F3D3BB03F5D21D9D28921384F535327237A610CDC1A88BAC46A8BAA`; nie został opublikowany.

- Pakiet diagnostyczny może teraz zachować nazwę typu nieobsłużonego wyjątku .NET odczytaną z początku stderr silnika, np. `System.InvalidOperationException`. Eksport waliduje nazwę i nie zapisuje komunikatu wyjątku ani ścieżek; test sprawdza redakcję. To ułatwia rozpoznanie klasy awarii, ale nie ustala jej przyczyny. Lokalnie: .NET 221 PASS / 2 platformowe pominięte, desktop 9/9, Engine IPC, DNS/TCP/UDP, UI production build i installer self-test PASS. Windows CI `39654091454` PASS. Artefakt testowy ma SHA-256 `28207AEF330C2AC059D5C52046A24E5FE785514E500885A16C3C5456715F8281`; nie został opublikowany.

- SQLite v16 łączy potwierdzone wykrycia CERT dla tego samego hosta oraz zgodne dopasowania lokalnego SHA-256 pliku między Downloads i ręczną analizą. Scalanie wymaga tego samego rodzaju sygnału, ryzyka, okna 60 s i nowego źródła; każda obserwacja zachowuje własny identyfikator, czas, źródło i dowody. Alert Downloads nie zapisuje nazwy pliku, a hash pozostaje lokalnie i nie trafia do JSON/CSV ani Enterprise. Testy .NET 223/223, desktop 9/9, DNS/TCP/UDP + Engine IPC, produkcyjny UI build i autotest instalatora PASS; Windows CI `39649636891` PASS.

- Doprecyzowano opisy pauzy: silnik nadal pobiera co sekundę PID i nazwy procesów oraz aktualizuje lokalny baseline, ale nie zapisuje zdarzeń z tego monitora. Diagnostyka pokazuje teraz ten stan wprost; test sprawdza komunikat i zachowanie baseline'u.

- URL z częścią przed `@` podnosi teraz ryzyko z niskiego do umiarkowanego, bo może ukryć właściwy host przed użytkownikiem. Wersja reguł wzrosła do `2026.10.2`. Korpus regresyjny obejmuje 25 ręcznie przygotowanych scenariuszy, w tym `https://paypal.com@attacker.test/login`: TP=13, FP=0, TN=12, FN=0 przy progu Moderate. Test Browser Host potwierdza ostrzeżenie i brak ujawnienia domeny w odpowiedzi. To test syntetyczny, nie reprezentatywny pomiar skuteczności produkcyjnej.

- Procesy są teraz próbkowane co około 1 s zamiast co 5 s, by ograniczyć pomijanie krótkich zdarzeń. Profil lokalny 30 s: CPU 0,377% całkowitej mocy procesorów i working set maks. 56 MiB przy 1 s; punkt odniesienia 5 s: 0,130% i 51 MiB. Windows CI `39628465280` PASS (214/214 .NET, installer self-test, Enterprise API 22/22, HTTP API smoke). To krótka sesja na jednej maszynie; procesy krótsze od próbki nadal mogą zostać pominięte.

- Pakiet diagnostyczny do pomocy technicznej zawiera teraz stan procesu .NET, ograniczony kod zakończenia i samą flagę obecności stderr. Status jest allowlistowany, kod jest filtrowany do ASCII alfanumerycznych/`-_` i 40 znaków; treść stderr nie trafia do eksportu. Test IPC sprawdza eksport i oczyszczenie kodu; Windows CI `39625685631` PASS.

- Czytnik TCP/UDP wybiera teraz deterministyczne 800 połączeń i 200 endpointów UDP oraz przekazuje do monitora informację o obcięciu tabel. SQLite v15 utrwala osobne flagi TCP/UDP; monitor wstrzymuje alerty podczas niepełnej próbki i po restarcie, a wznawia je po kolejnej pełnej próbce. Dodano testy stabilnego limitera, zmian składu, restartu i migracji v14→v15. Windows CI `39625685631` PASS dla połączonej rewizji: .NET 214/214, installer self-test, testy serwera 22/22 i API smoke.

- Snapshot procesów wybiera deterministycznie pierwsze 10 000 PID i zapisuje w SQLite v14, czy próbka została obcięta. Monitor pomija wnioski o startach lub zniknięciach, których nie da się wiarygodnie wyciągnąć z niepełnej próbki; po pełnej próbce wraca do normalnego wykrywania. Dodano test limitu, restartu, metadanych bez zmian baseline'u i migracji v13→v14. Lokalna walidacja Windows: .NET 211/211 bez pominięć, pełny `scripts/build-user.ps1 -Installer`, testy serwera 22/22 PASS. Windows CI `39619932040` PASS dla commita `484126f`, w tym build/test aplikacji i Enterprise API.

- Windows CI ujawniło, że kontrola Authenticode może zwrócić `Unknown` przy wolnym starcie Windows PowerShell. Zwiększono timeout z 10 do 30 s, pozostawiając wynik `Unknown` przy timeout/błędzie. Pełny lokalny build/test/self-test instalatora PASS; Windows CI `39615470449` PASS: .NET 208/208, desktop 6/6, Engine IPC, self-test instalatora, Enterprise API 22/22 i HTTP API smoke.

- Test Windows uruchamia aktywny proces Engine przy lokalnym API Enterprise po TLS: zatrzymuje API, sprawdza `sync_failed` i zachowanie kolejki, uruchamia tę samą bazę/certyfikat ponownie, a po skonfigurowanym interwale zwykłe `collect` automatycznie wysyła kolejkę i czyści rekord. Serwer nie otrzymuje lokalnej treści ani wyjaśnienia. Test przypina certyfikat wyłącznie w pamięci Debug Engine; magazyny Windows są nietknięte. Pełne testy serwera Windows 22/22 PASS. Pełny build/self-test instalatora, .NET 208/208, API smoke, Windows-live DNS i desktop 6/6 przeszły dla poprzedniej wersji testu; workflow dla bieżącego commitu nie został potwierdzony.
- Odczyt cache DNS używa `ipconfig /displaydns`, który działa bez uprawnień administratora; poprzednie `Get-DnsClientCache` zwracało `Access denied` na zwykłym koncie. Dodano parser z normalizacją/limitem 2000 nazw oraz czas ostatniego udanego odczytu i błędu w statusie i diagnostyce. .NET 208/208, Windows-live DNS cache i Engine IPC PASS; pełny build/self-test instalatora PASS. Lokalny, nieopublikowany instalator testowy 281219449 B, SHA-256 `986BB232544CB7F7E09CF9295485470E016E9B240362188C0001361AED568DF3`. Build skrypt uruchamia teraz `--dns-live`, aby kolejne Windows CI weryfikowało rzeczywisty odczyt cache; wynik tego przebiegu CI oczekiwany.
- Rozszerzono izolowany self-test instalatora o deinstalację: usuwa wszystkie pliki z payloadu i kopię deinstalatora, zachowuje plik spoza pakietu oraz obie bazy danych. Tryb testowy nie zmienia wpisów rejestru, skrótów ani rejestracji Native Messaging. Pełne `npm run package` zakończyło się PASS; artefakt testowy 281218937 B, SHA-256 `36BD25EFA75A9259A0D95B023E017052D8C69A90664FFCFA96AB52E8A02FA493`. Workflow Windows uruchamia teraz także `./scripts/build-user.ps1 -Installer`; CI `39507776707` PASS: .NET 207/207, Enterprise API 21/21 i autotest instalatora PASS. Instalator nie został opublikowany jako nowe wydanie.
- Workflow GitHub Pages po wdrożeniu sprawdza publiczną stronę, wszystkie jej zewnętrzne linki HTTPS, dostępność wersjonowanego instalatora i sidecara SHA-256 oraz format sidecara. Pages run `39505227865` PASS z pełnym checkiem wszystkich linków; Windows CI `39505227855` PASS. Wcześniejszy run `39504764915` sprawdzał poprzednią wersję checku.
- Wyniki lokalnej analizy AI mogą teraz wskazywać ponumerowane fragmenty FTS5: silnik dopuszcza tylko indeksy źródeł faktycznie przekazane w bieżącym żądaniu, a UI pokazuje nazwę dokumentu, fragment i cytowany tekst przy wskaźniku. Etykieta wyjaśnia, że wskazanie modelu nie jest niezależną weryfikacją źródła. Testy .NET 207/207, Engine IPC, desktop 6/6, UI production build i autotest instalatora PASS; pełny npm audit 0 podatności.
- Live TLS E2E Enterprise odtwarza teraz przerwę w dostępności: test wyłącza i wznawia API z tą samą bazą, ponawia zachowany batch i potwierdza idempotencję. Tymczasowy certyfikat liścia jest przypięty w pamięci klienta testowego; żaden magazyn zaufanych Windows nie jest modyfikowany. Pełny zestaw testów serwera 21/21 PASS poza sandboxem.
- Pełny npm audit znalazł 8 umiarkowanych alertów w łańcuchu `electron-builder` → `@electron/get` → `global-agent` → `sprintf-js`. Wymuszono `@electron/get` 5.1.0 przez npm overrides; nowy lockfile, `npm ci` i pełny audit pokazują 0 podatności, a produkcyjny audit również 0. Pełny `scripts/build-user.ps1 -Installer` po tej poprawce przeszedł: .NET 203/203, Engine IPC, desktop 6/6, UI build, electron-builder oraz autotest instalatora PASS. Nie zmieniono opublikowanego wydania v0.15.38.
- Poprawiono FAQ witryny: aktualny klient ma opcjonalne połączenie z lokalnym Ollama, a przepływ rozszerzenia Chrome/Edge został przetestowany w odizolowanych profilach. Instalacja rozszerzenia nadal wymaga osobnej konfiguracji.
- Dodano lokalny import tekstowych PDF do bazy FTS5 z limitem 10 MB, 500 stron i 2 mln znaków. Ekstrakcja nie wykonuje OCR, obrazy bez warstwy tekstowej są odrzucane, a błędny/nadmierny plik nie zmienia indeksu. PdfPig 0.1.16 nie ma zgłoszonych podatności NuGet; pełny zestaw .NET 205/205, Engine IPC, desktop 6/6, build UI i autotest instalatora PASS. Self-test instalatora potwierdza też, że pełna licencja PdfPig trafia do instalowanego Engine. Lokalny artefakt 281215353 B, SHA-256 `475689A35343376A1ADE955A2B2775889D6C9E16E7BB3AF4D5168C897BFB2FCC`; pozostaje artefaktem testowym, nie nowym wydaniem.
- Windows-specific tests now use xUnit discovery-time skip attributes. A runner without a usable current-user DPAPI profile reports the two DPAPI-dependent checks as skipped instead of failed at execution time; ACL coverage still runs on Windows. Validation in this non-interactive session: .NET 201 passed / 2 skipped, desktop tests 6/6, Engine IPC and self-contained Engine/UrlHost publish PASS, desktop production build PASS. The aggregate build script stopped at the UI build because sandboxed esbuild could not read the parent directory; the same UI build passed with approved filesystem access.
- Rozszerzono izolowany self-test instalatora o aktualizację istniejącego katalogu, zachowanie plików spoza payloadu i rollback po anulowaniu po zamianie katalogów. Test sprawdza też, że anulowanie loguje etap transakcji, a nie ekstrakcji.
- Instalator wstępnie wybiera teraz zarejestrowaną lokalizację Sentinel AI, jeśli znajduje się ona w profilu użytkownika; test odrzuca lokalizację systemową.
- Dodano ręczną rotację poświadczenia Enterprise z potwierdzeniem użytkownika, ochroną DPAPI i blokadą komunikacji po cofnięciu zgody.
- Dodano test rzeczywistego procesu Engine: kolejka Enterprise i pairing przetrwają brak serwera oraz restart procesu, cofnięcie zgody czyści kolejkę bez kasowania historii lokalnej. Weryfikacja: .NET 203/203, server 21/21, desktop 6/6. Wcześniejsza próba retry procesu Engine wyświetliła prośbę o zaufanie certyfikatowi testowemu; instalacji do magazynu Windows nie zatwierdzono. Osobny live TLS E2E odtwarza awarię i wznowienie API, przypinając tymczasowy certyfikat wyłącznie w pamięci klienta testowego, bez zmian w Windows. Ponowienie kolejki wewnątrz procesu Engine po powrocie serwera pozostaje niezweryfikowane.
- Testy wymagające Windows (DPAPI, rzeczywisty Engine z DPAPI oraz ACL systemu plików) jawnie raportują pominięcie poza Windows zamiast liczyć brak wykonania jako sukces. Pełny zestaw Windows .NET po tej zmianie: 203/203.

## 0.15.38 — prerelease (2026-10-20)

- Zdarzenia przeglądarki zapisują kody przesłanek z analizy URL, dzięki czemu historia prawidłowo opisuje wspólną grupę jako korelację domeny, a nie PID procesu. Weryfikacja lokalna i Windows CI `39489166139` PASS; Pages `39489165920` PASS; instalator build/self-test/release `39489181456` PASS. [GitHub Release v0.15.38](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.38) zawiera instalator 262559349 B, SHA-256 `bb34834eb654e450728f95093d500715b5f6ef5ab9f7825c32d146b9fb2c4cd8` oraz sidecar `.sha256`. Lokalny instalator ma 279359865 B, SHA-256 `C075B4DC57A03FBB982C4880044AB7DBC40981F49304C95D06BF962623CCF75F`. Chrome 155 i Edge 155 E2E PASS na osobnych, izolowanych profilach: CDP załadował rozszerzenie, lokalny fixture `.test` przeszedł przez Native Messaging, a UI pokazało oczekiwane przesłanki; proxy blokowało ruch zewnętrzny. Tymczasowe profile, manifest i wpis HKCU usunięto.

## 0.15.37 — prerelease (2026-10-20)

- Wspólna domena rejestrowalna koreluje zdarzenia DNS, ostrzeżenia nawigacji Chrome/Edge i ręczną analizę URL w przesuwanym oknie 60 sekund. Każda detekcja pozostaje osobnym zdarzeniem; wspólny correlationId oznacza zbieżność domeny i czasu, nie związek przyczynowy. Tabela SQLite v13 przechowuje wyłącznie SHA-256 domeny i krótkotrwały identyfikator grupy; surowa domena nie trafia do mapy korelacji ani payloadu Enterprise. Restore usuwa mapę ulotną.
- Weryfikacja: .NET 202/202, desktop Node tests 6/6, Engine IPC, desktop UI build, website test/lint/build oraz lokalny installer build/self-test PASS. Windows CI `39487635916`, Pages `39487635904` i installer build/self-test/release `39487663968` PASS. [GitHub Release v0.15.37](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.37) zawiera instalator 262558837 B, SHA-256 `3172230cf759222ef3e2d9d835169f46810bfcdaf27073e047db369fec13b637` i sidecar. Lokalny build 279359353 B, SHA-256 `5CA5B78A1650ECC8CF1EF10BB3E012D2B549558BE33F329D5F3E35D134B8493B`. Rzeczywista nawigacja Chrome/Edge pozostaje nieweryfikowana.

## 0.15.36 — prerelease (2026-10-20)

- Rozszerzenie MV3 nie traci już celu, wskaźników i działań ostrzeżenia po uśpieniu service workera: stan tokenu jest przechowywany w `chrome.storage.session`, wygasa po 10 minutach i jest usuwany po zamknięciu karty lub kontynuowaniu nawigacji. Dane pozostają ograniczone do sesji przeglądarki.
- Dodano regresyjny test restartu workera, odzyskania szczegółów i przycisków oraz odrzucania nieważnych i wygasłych tokenów; wymagane minimum Chrome to 102 (Edge Chromium od tej samej generacji). .NET 198/198, desktop Node tests 6/6, desktop UI build, website test/lint/build, check-product i engine IPC PASS. Windows CI `39484829750`, website Pages `39484829812` i installer build/self-test/release `39484833324` PASS. [GitHub Release v0.15.36](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.36) udostępnia instalator 262555765 B, SHA-256 `7E7DE0CC609140485DCE3DEBDF09E43348B86FF3FF3C07467A3B6EC95949DC88` i sidecar `.sha256`. Lokalny instalator 279356281 B, SHA-256 `49F014D0CF0A4274E13ECE0D55603A69D112A9DF3F1795B2DC637065162FF957`. Rzeczywista nawigacja Chrome/Edge nadal niezweryfikowana.


## 0.15.35 — prerelease (2026-10-20)

- Lokalny model zdarzenia zapisuje uporządkowane, walidowane kody dowodowe bez treści ani URL-i. Monitoring procesu, TCP/UDP, DNS, pobranych plików i ręczna analiza dodają kody właściwe dla źródła; historia pokazuje je użytkownikowi, a eksport JSON/CSV i kopie je zachowują.
- Migracja SQLite v11→v12 dodaje pole `evidence_codes`; starsze zdarzenia dostają pustą listę. Restore obsługuje kopie v6–v12, a Enterprise payload nie zawiera kodów ani lokalnych przesłanek. Poziom pewności nadal pozostaje pusty, dopóki nie zostanie skalibrowany.
- Weryfikacja: .NET 198/198, desktop 4/4, TypeScript/lint/build UI PASS; lokalny installer build i self-test PASS, 279355769 B. Windows CI `39482606635`, website Pages `39482606648` oraz installer build/self-test/release `39482719349` PASS. [GitHub Release v0.15.35](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.35) udostępnia instalator 262555253 B, SHA-256 `6C00804C9C4E1B95DF068D679F34218E47572D0E83B87D93F08F238F92B977E5` i sidecar `.sha256`.


## 0.15.34 — prerelease (2026-10-20)

- Procesy pojawiające się w migawce i nowe połączenia TCP i endpointy UDP z tego samego PID oraz nazwą procesu są łączone identyfikatorem korelacji, jeśli obserwacje są oddalone o najwyżej 60 sekund. Identyfikator jest lokalny; UI nazywa to korelacją czasową i wyjaśnia, że nie dowodzi związku przyczynowego.
- SQLite v11 zapisuje identyfikator korelacji w historii i kopiach zapasowych; eksport JSON/CSV go zachowuje. Restore nadal przyjmuje kopie v6–v11.
- Weryfikacja: .NET 195/195, desktop 4/4, TypeScript/lint i build UI PASS, server tests 20/20, HTTP API smoke PASS. Windows CI `39479871584` i installer build/self-test/release `39479900365` PASS. [GitHub Release v0.15.34](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.34) udostępnia instalator 262552181 B, SHA-256 `1c37638e3ea642697a96a1f9cd420b2d0270f4d4cb9275f81c98f8b8fea3c4cb` i sidecar `.sha256`. Lokalny instalator jest osobnym buildem: 279352697 B, SHA-256 `18931A566F82CE34459E4C0450D147ECE43DC54328274924D70761CC633D17C3`.


## 0.15.33 — prerelease (2026-10-20)

- Client and Enterprise API now compile against one shared, typed `EnterpriseEventV1` contract. The same source defines the batch/result DTOs, event source allowlist, rule-version sanitization, schema validation and accepted date/risk/category/rule-code bounds.
- Verification: client .NET 190/190, server tests 20/20, Release server build and HTTP API smoke PASS. Local full installer build and self-test PASS; 279351161 B, SHA-256 `EB2D6D5FF846534BB464FEC38130A3C7F5FEA89E24D0E18027C5EFF6926C23E3`. GitHub release `v0.15.33` zweryfikowany: 262550645 B, SHA-256 `e87457c78c69962a1eac317cb59ea997407ec018a98788b3693773985a219608`; sidecar `.sha256` opublikowany. Windows validation `39475468088` PASS.


## 0.15.32 — prerelease (2026-10-20)

- Enterprise event v1 now carries a schema version, allowlisted source code and sanitized rule version from the client’s durable queue through the API into server storage and the admin event view. Local and server SQLite upgrades preserve existing pending/history records; old queued events receive safe defaults.
- Verification: client .NET 190/190, server tests 20/20, Release solution build, HTTP API smoke test and local installer build/self-test PASS. Local installer: 279339897 B, SHA-256 `4FA4BCB6CA8C77A2A9CCBC914D7FAC1ACA5A8CB1DF6733D5BE08601E6DEC73CF`.


## 0.15.31 — prerelease (2026-10-20)

- Ponowiony zapis lokalnego zdarzenia z tym samym jawnym `eventId` zwraca istniejący rekord i nie tworzy duplikatu; test sprawdza stabilność ID. Pełny build/self-test PASS, .NET 186/186 i desktop 4/4. Windows CI `39467119852`, Pages `39467119876`, installer build/self-test/release `39467120476` PASS. [Release v0.15.31](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.31): instalator 262536309 B, SHA-256 `a82c91f25b6425f30ef4fb7ee3bc924b2c937598ad511d3055b37b13047309fc` i sidecar. Lokalny instalator 279336825 B, SHA-256 `8A0F654D49F8F6431E5E9076DB1CF4E3F83B25DC23BB02713DAC6FCFFDD43D5F`.
- Test integracyjny bazy wiedzy dowodzi, że trafienia FTS5 trafiają do promptu jawnie włączonej Ollama jako niezaufane źródła; poprawiono opis F11, który błędnie twierdził, że wyszukiwany indeks nie jest używany w analizie.


## 0.15.30 — prerelease (2026-10-20)

- Doprecyzowano w karcie bazy wiedzy, że przy włączonej Ollama do pięciu dopasowanych fragmentów trafia do modelu działającego lokalnie; fragmenty nie są wysyłane do Internetu ani zapisywane w historii zdarzeń. Test `SQLITE_FULL` wypełnia bazę dużymi, prawidłowymi rekordami i nie zależy od pozostałego miejsca po wycofaniu transakcji. Windows CI `39464916564`, Pages `39464916630` oraz installer build/self-test/release `39464922942` PASS. [Release v0.15.30](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.30): instalator 262536309 B, SHA-256 `cff5abd1781c6b41648c169827eccf26c15c7ff1b34bbdf91cab2ee069089daa` i sidecar. Lokalny self-test instalatora: 279336825 B, SHA-256 `6494FDE494DDCE0D458539FC5B7C27908754C30F0A0F58D77FCAD1D4E4F555D2`.


## 0.15.29 — kandydat nieopublikowany (2026-10-20)

- Pierwsza próba Windows installer workflow dla tagu nie przeszła: test ponowienia po `SQLITE_FULL` nie wypełniał bazy deterministycznie na runnerze. Poprawkę testu i korektę prywatności zawiera v0.15.30.


## 0.15.28 — prerelease (2026-10-20)

- Diagnostyka desktop pokazuje stan procesu silnika, kod ostatniego zakończenia oraz sam fakt wystąpienia stderr bez ujawniania jego treści. Stan jest dostępny także podczas ponawiania startu. Dodano regresyjne testy snapshotu diagnostycznego i prywatności. Windows CI `39461730985`, Pages `39461730984` i installer build/self-test/release `39461735757` PASS. [Release v0.15.28](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.28): instalator 262536309 B, SHA-256 `5834d0d220d14ad93d39af75f2328cba10985921ca4f6b0acc22e134901bbf63` i sidecar `.sha256`. Lokalny self-test instalatora PASS; SHA-256 `96E20AF8E3B57562383C87C3AAEAB2D79DF5BF47CF15250E2B96C0ABB284ECE3`.


## 0.15.27 — prerelease (2026-10-20)

- Watchdog żądań wykrywa zawieszony silnik .NET: po 45 s odrzuca żądanie, kończy proces i ponawia start z backoffem. Testy desktop 4/4, .NET 184/184, Engine IPC, desktop build i installer self-test PASS. Windows CI `39459914877`, Pages `39459915119` i installer build/self-test/release `39459920461` PASS. [Release v0.15.27](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.27): instalator 262536309 B, SHA-256 `fc3e4719a63a5f4e6a9cc4e7a0ba9831d108e9622014a32cab38f8d6c49b7a16` i sidecar `.sha256`. Lokalny instalator: 279336825 B, SHA-256 `B57B04E6CEB4235384D5AA5C1356A45FD0D7950911074EBE937FB18BD3F8B934`.


## 0.15.26 — prerelease (2026-10-20)

- Aktywny klient Electron ponawia start procesu .NET po błędzie startu, zakończeniu procesu, błędzie IPC lub niepoprawnej odpowiedzi, z wykładniczym opóźnieniem do 30 s. Oczekujące żądania są odrzucane; surowy stderr nie jest zapisywany ani logowany. Trzy testy procesu silnika są wykonywane przez `scripts/build-user.ps1`; desktop lint/build, 184/184 testów .NET i Engine IPC PASS. Windows CI `39458266067`, Pages `39458266050` i installer build/self-test/release `39458271344` PASS. [Release v0.15.26](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.26): instalator 262536309 B, SHA-256 `b8ac30ed1ea1aaf2d2c67ef8ca869a8a1bdd7d62d703c8f23d7efe5b802a0388` i sidecar `.sha256`. Lokalny self-testowany instalator: 279336825 B, SHA-256 `5EE1D167C30F75A38E2E14E4EBEC0D82CBA50E9EEACF9C17DCA7FEF728F6551F`.
- `npm audit` potwierdza 8 umiarkowanych alertów wyłącznie w łańcuchu build-time `electron-builder`/`sprintf-js`; `--omit=dev` raportuje zero. Testowana propozycja npm downgrade do 26.5.0 dodaje 8 high i 1 critical przez `tar`; przywrócono builder 26.15.3.


## 0.15.25 — prerelease (2026-10-20)

- Downloads monitor samoczynnie ponawia inicjalizację podczas kolejnego cyklu collect po przejściowym błędzie SQLite lub dostępu do katalogu. Nie wymaga ręcznego przełączania ustawienia ani restartu procesu.
- Testy .NET 184/184, `check-product`, website lint/test/build PASS. Pełny Windows build-user z Engine IPC, instalatorem i self-testem PASS. Lokalny instalator: 279335801 B, SHA-256 `084617E5E987BD4A6FBCF1E09E2D2FE8F6D15D9331CED98BB51312223D651183`. Windows CI `39455405422`, Pages `39455405535` i installer build/self-test/release `39455410177` PASS. [Release v0.15.25](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.25): instalator 262535285 B, SHA-256 `a8efcf946b60e54f5f12206aae1d9c2631f28a84b0a322c473033e954de4a5d0` i sidecar `.sha256`.


## 0.15.24 — prerelease (2026-10-20)

- Monitoring Downloads czyści stan pamięci przy błędzie odczytu SQLite podczas startu i pozwala ponowić inicjalizację bez restartu procesu. Dodano regresję, która uruchamia watcher po naprawie bazy.
- Testy .NET 184/184, `check-product`, website lint/test i desktop lint PASS. Pełny Windows build-user z Engine IPC, installerem i self-testem PASS. Windows CI `39453439410`, Pages `39453439395`, installer build/self-test/release `39453444163` PASS. [Release v0.15.24](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.24): instalator 262535285 B, SHA-256 `3d7f261d6ffb465faff3f6903d1095b1a3796de35afab199c39d4da21f24b82b` i sidecar `.sha256`. Lokalny instalator: 279335801 B, SHA-256 `1F6ABC982453385886AF26FC42039E51C2AE17351A3810C90BECA00221A71FE6`.


## 0.15.23 — prerelease (2026-10-20)

- Monitoring Downloads zapisuje lokalny baseline ścieżek, rozmiarów i czasów modyfikacji. Po restarcie silnika porównuje pliki z ostatnim stanem i wykrywa nowe lub zmienione pliki; wyłączenie i pauza czyszczą baseline. Wykrycie i postęp baseline'u zapisują się atomowo. Migracja SQLite v9 zachowuje dotychczasową historię.
- UI jawnie informuje, że ścieżki baseline'u są przechowywane lokalnie bez szyfrowania.
- Testy .NET 183/183, Engine IPC, desktop lint/build i website test/lint/build PASS. Windows CI `39451059431`, Pages `39450039001`, installer build/self-test/release `39451070868` PASS. [Release v0.15.23](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.23) zawiera instalator 262535285 B, SHA-256 `7bec3d5ba09b2099441ae07149ab5f0a63f7c4372532716709ef108dd9980f50` i sidecar `.sha256`. Lokalny self-testowany instalator: 279335801 B, SHA-256 `DB38738EC079110CBD091D79014AE3DCD6AA9068626D032161973DA49315857A`.


## 0.15.22 — prerelease (2026-10-20)

- Dodano redagowany pakiet diagnostyczny JSON do pomocy technicznej. Zawiera wersje OS/runtime, stany monitorów, ustawienia nieidentyfikujące i metryki baz, bez historii zdarzeń, treści, URL-i, ścieżek i nazw procesów.
- Testy .NET 179/179, Engine IPC z asercjami prywatności pakietu diagnostycznego i CSV, desktop lint/build PASS. Website test/lint/build PASS. Windows validation `39446717025`, Pages `39446717099` i installer release/self-test `39446715416` PASS. [Release v0.15.22](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.22): instalator 262526581 B, SHA-256 `70fdfef27512e6f1279d470e58a62b0ed039ad0554fb75489da8ecc9b4931bdd` oraz sidecar `.sha256`. Lokalny instalator (279327097 B, SHA-256 `39B680321A7EFA9E6085E74B0A41A426D32CC3AF4355149D46184C7BE520C0CF`) również przeszedł self-test.


## 0.15.21 — prerelease (2026-10-20)

- Dodano eksport redagowanej historii CSV z poziomu widoku zdarzeń. Format zawiera metadane wszystkich zachowanych zdarzeń, nadaje się do otwarcia w Excelu i neutralizuje formuły arkusza.
- Testy .NET 179/179, Engine IPC z redakcją eksportu CSV, desktop lint/build PASS. Website test/lint/build PASS. Windows validation `39444882046`, Pages `39444882532` i installer release/self-test `39444882540` PASS. [Release v0.15.21](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.21): instalator 262523509 B, SHA-256 `218d4202b85e598e5423b9a1881e5df0e81ebf2adbc46b004e345bcd20f9da72` oraz sidecar `.sha256`. Lokalny build instalatora (279324025 B, hash `DEB91B1F70A2B31E224245A8FD2B33649AC3E5F6F5DFFAA831E99966B7D83C21`) również przeszedł self-test.


## 0.15.20 — prerelease (2026-10-20)

- Limit metadanych baseline'u Downloads obejmuje całą sesję monitorowania, nie tylko stan początkowy. Po osiągnięciu limitu watcher zatrzymuje się jawnie, zamiast dalej zwiększać zużycie pamięci.
- Testy .NET 178/178, Engine IPC, kontrolowany TCP, desktop/website test-lint-build PASS. Windows CI `39441943631`, Pages `39441943558` i installer release/self-test `39441965987` PASS. [Release v0.15.20](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.20) zawiera instalator 262521973 B, SHA-256 `0c2236a48806817fb2fd8fcdf1e7f3b2c62128042860ec11ce387edb77a87f1d` oraz sidecar `.sha256`.


## 0.15.19 — prerelease (2026-10-20)

- Opt-in monitoring Downloads odtwarza teraz utracone powiadomienia przez porównanie plików w katalogu po przepełnieniu kolejki lub bufora FileSystemWatcher. Stan początkowy do 100 000 plików wyklucza pliki istniejące przed włączeniem; przetwarzanie nadal respektuje limit rozmiaru i budżet każdej próbki. Dodano test przepełnienia z małą kolejką oraz test, że plik sprzed włączenia nie jest skanowany.
- Testy .NET 177/177, Engine IPC i kontrolowany test TCP PASS; desktop/website test, lint i build PASS. Windows CI `39439950267`, Pages `39439950410` i installer release/self-test `39440093224` PASS. [Release v0.15.19](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.19) zawiera instalator 262521461 B, SHA-256 `3826706412de6803397de93a39767400ecceb70b9876180d1e10d80f680be25b` i sidecar `.sha256`.


## 0.15.18 — prerelease (2026-10-20)

- Downloads watcher rozwiązuje ścieżkę przez Windows Known Folder, aby obsłużyć folder przekierowany przez użytkownika lub organizację; jeśli API niedostępne, używa `%USERPROFILE%\Downloads`.
- Po zapełnieniu bounded queue watcher zgłasza łączną liczbę pominiętych zdarzeń w diagnostyce. Próbka pozostaje ograniczona do 512 MiB hashowanych danych.
- Testy .NET 176/176, Engine IPC, website/desktop lint i build oraz Windows validation `39436563958` PASS; Pages `39436564072` i release/self-test `39437009572` PASS. [Release v0.15.18](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.18) zawiera instalator 262519413 B, SHA-256 `c929dda0ec88ce881682462b83a575deb4dd28de48eb7b8c460358027aacbb20` i sidecar `.sha256`.


## 0.15.17 — prerelease (2026-10-20)

- Dodano domyślnie wyłączony watcher Downloads. Po opt-in sprawdza wyłącznie nowe pliki w głównym katalogu Downloads i wyłącznie względem lokalnej listy SHA-256. Nie wysyła pliku ani hasha do sieci; zapisuje lokalne zdarzenie tylko przy dopasowaniu. Pauza zatrzymuje watcher.
- Watcher ogranicza kolejkę do 1000 pozycji, skanuje maksymalnie 10 plików i 512 MiB na próbkę, pomija symlinki/reparse points i pliki ponad 256 MiB, czeka 750 ms od ostatniej zmiany i respektuje wyłączenie opcji.
- .NET 176/176, Engine IPC, desktop/website lint/build i Windows CI `39433555518` PASS. Release CI `39434090207` PASS, w tym instalator self-test. [Release v0.15.17](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.17) zawiera instalator 262518901 B, SHA-256 `e34b86c62f24d426dd1a2c8888e4fcf8353110beae609587aee331004c6cd189` i sidecar `.sha256`.


## 0.15.16 — prerelease (2026-10-20)

- Baseline procesów jest przechowywany w SQLite v8 i aktualizowany atomowo ze zdarzeniami. Restart silnika pozwala wykryć różnice od ostatniej próbki; pauza przesuwa baseline bez generowania alertów, a wykluczone aplikacje nie są zapisywane w baseline.
- Testy .NET 174/174, pełny build/self-test instalatora, Engine IPC i UI build PASS. GitHub Actions `39428078633` zakończył Windows build/test/self-test i publikację sukcesem. [Release v0.15.16](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.16) zawiera instalator CI 262514293 B, SHA-256 `abff53d5f71d4f7edb30f9b939d48e6f81900d99c3dc5680353f22115322f7c6` oraz sidecar `.sha256`.


## 0.15.15 — prerelease (2026-10-20)

- Sieciowy baseline TCP/UDP jest trwale przechowywany w SQLite v7 i zapisywany atomowo ze zdarzeniami; restart silnika nie powtarza alertów dla wcześniej widzianych endpointów. Wyłączenie monitoringu lub utrata źródła unieważnia baseline przed kolejnym opt-in.
- Testy .NET 170/170 oraz pełny build/self-test lokalnie PASS. GitHub Actions `39425895322` zakończył Windows build/test/self-test sukcesem i opublikował [prerelease v0.15.15](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.15). Instalator CI: 262509685 B, SHA-256 `2735afde7a3ee51044eab8afbc5c96567686836c27ce2e364bf2c147e96b1beb`; dostępny jest także plik `.sha256`.


## 0.15.14 — prerelease (2026-10-20)

- Dodano opcjonalne, ręczne sprawdzanie SHA-256 w MalwareBazaar. Klucz jest chroniony DPAPI; zapytanie wymaga zgody i wysyła wyłącznie hash do stałego endpointu HTTPS. Nieznany hash nie jest oznaczany jako bezpieczny.
- Opt-in obserwacja TCP zapisuje teraz także pojawienie się lokalnego endpointu UDP. Zdarzenie jasno informuje, że migawka endpointu nie dowodzi wysłania datagramu ani nie ujawnia zdalnego celu.
- Odświeżono `docs/KNOWN-LIMITATIONS.md`: opisy aktywnego lokalnego AI, bazy wiedzy, skanowania plików i wydania instalatora odpowiadają aktualnemu kodowi oraz zakresowi testów.
- Testy mock API sprawdzają stały host, pola hash-only, dopasowanie, no-results i odrzucenie niezgodnego hashy. Test historii UDP przechodzi. Release .NET 167/167, Engine IPC oraz pełny build/self-test PASS. Opublikowany jako testowy prerelease v0.15.14; realny MalwareBazaar wymaga autoryzowanego klucza.


## 0.15.13 — prerelease (2026-10-20)

- Naprawiono ekstrakcję instalatora: przed sprawdzeniem rozmiaru pliku opróżniany jest bufor zapisu, a błąd podaje rozmiar skopiowany i oczekiwany.
- Self-test instalatora sprawdza teraz wskaźnik katalogu danych oraz prawidłowy nagłówek SQLite dla historii i lokalnej bazy wiedzy po uruchomieniu aplikacji w izolowanym katalogu.
- Pełny lokalny build instalatora oraz jego self-test PASS; klient .NET 163/163, serwer 19/19, Engine IPC, desktop lint/build i website test/lint/build PASS.
- Prerelease [v0.15.13](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.13): Windows CI build/test/self-test i publikacja PASS. Instalator CI ma 262496373 B, SHA-256 `25194a0f98fde84719bc6fcf565c8bce6269cf5932ab6163379f00420fe072fa`. Lokalny build (279296377 B, SHA-256 `3c9f9d84f515a2496bde98332ffd9171b27c1aa706e9642283c404bdece5b218`) był odrębnym artefaktem.


## 0.15.12 — prerelease (2026-10-20)

- Ręczny skan pliku może teraz sprawdzić SHA-256 w jawnie importowanej lokalnej liście (20 MiB/250 000 hashy); import jest walidowany i atomowy. Nieznany/brakujący hash nie jest oceną bezpieczeństwa, a źródło listy nie jest niezależnie weryfikowane.
- Dodano Windows test potwierdzający, że SQLite nie inicjalizuje historii, gdy bieżący użytkownik nie może tworzyć plików w katalogu danych; test zawsze przywraca pierwotne ACL.
- Uodporniono test retry monitora procesu: wykrywa faktyczny brak miejsca dla małego zdarzenia, zamiast zakładać go po nieudanym większym zapisie.
- Rozszerzono `scripts/benchmark-engine.cjs` o `--tcp-monitor`, aby włączyć observer i zweryfikować kontrolowane nowe połączenie podczas profilu.
- Pięciominutowy soak TCP: 60 próbek co 5 s, kontrolowane połączenie zapisane, observer pozostał aktywny, 13 wpisów TCP bez pominiętych zmian; CPU 0,056%, working set 45,2–57 MiB, mediana collect 5,6 ms / max 675,9 ms. Jest to pojedynczy pomiar lokalny.
- Testy .NET: 163/163 PASS; Engine IPC potwierdza import i dopasowanie syntetycznego pliku. UI lint i produkcyjny build PASS. Fizyczny test pełnego wolumenu i ACL ścieżki po instalacji pozostają do wykonania.
- GitHub Actions Windows build/test/self-test oraz publikacja prerelease PASS. Opublikowany instalator: 262494837 B, SHA-256 `a795f35ed94634e9f847763dbb34117c89aa08d0fc1d8e8be66e081501b01464`. Lokalny artefakt (279295353 B) był odrębnym buildem.
- Naprawiono linki pobrania i sumy na statycznej witrynie, które nadal wskazywały v0.15.3. Website test/lint/build oraz Pages workflow PASS; publiczny URL zwrócił HTTP 200, wskazuje installer v0.15.12 i nie zawiera starego linku v0.15.3.


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
- `npm audit` potwierdza 8 umiarkowanych alertów wyłącznie w łańcuchu build-time `electron-builder`/`sprintf-js`; `--omit=dev` raportuje zero. Testowana propozycja npm downgrade do 26.5.0 dodaje 8 high i 1 critical przez `tar`; przywrócono builder 26.15.3.
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
- SQLite v17 naprawia przepełnienie Enterprise outboxa: po zapełnieniu kolejki do 10 000 wpisów nowe wykrycia zapisują się atomowo w trwałym magazynie odroczonym, a Engine przenosi je do kolejki po zwolnieniu miejsca. Backup/restore, cofnięcie zgody i retencja obejmują także odroczone wpisy. Test sprawdza pełną kolejkę, zachowanie wykrycia i późniejsze przeniesienie wpisu do kolejki.
