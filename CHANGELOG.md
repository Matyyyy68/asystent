# CHANGELOG

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
