# Sentinel AI User

Rozwojowa aplikacja Windows 10/11 x64. React + TypeScript + Electron jest jedynym wspieranym interfejsem. Osobny proces .NET 10 używa lokalnych reguł i SQLite. Nie wymaga konta ani serwera Enterprise. Kod WPF zachowano wyłącznie w `legacy/` jako archiwum migracji; nie jest częścią bieżącego rozwiązania ani instalatora.

**Stan: wersja do testów technicznych, nie gotowy produkt ochronny.** Aplikacja analizuje wklejoną wiadomość lub URL, sprawdza dokładną domenę na jawnie pobranej liście CERT Polska i odczytuje cache DNS Windows po włączeniu obserwacji. Procesy są próbkowane lokalnie mniej więcej co sekundę. Opcjonalny monitoring TCP/UDP jest domyślnie wyłączony; po włączeniu próbuje co sekundę wykrywać nowe połączenia TCP `Established`/`SynSent` i lokalne endpointy UDP, zapisując dostępne metadane. Może pominąć krótkie połączenia; endpoint UDP nie potwierdza wysłania datagramu. Aplikacja nie odczytuje payloadu ani nie blokuje ruchu. DNS nie obejmuje DoH, VPN, pełnych URL ani połączeń po IP. Historia ma limit 512 MiB; zapis przy braku miejsca zostaje odrzucony bez automatycznego usuwania starszych zdarzeń. Monitoring plików w folderze Downloads jest opcjonalny i domyślnie wyłączony: po włączeniu obejmuje nowe i zmienione pliki w tym folderze i podfolderach (do 256 MiB na plik), bez podążania za reparse points. Porównuje SHA-256 lokalnie z listą użytkownika; pliki ani hashe nie są wysyłane. Zmiany są dodatkowo uzgadniane okresowo co 5 minut, a aktywny baseline ma limit 100 000 plików. Ścieżki, rozmiary i czasy modyfikacji zapisuje lokalnie bez szyfrowania, aby wznowić obserwację po restarcie. Ręczny skan oblicza SHA-256, sprawdza Authenticode i może dopasować hash do ręcznie zaimportowanej listy. Przy włączonym monitoringu TCP nowe połączenia można też porównać lokalnie z jawnie zaimportowaną listą adresów IPv4/IPv6 i sieci CIDR; lista nie jest wysyłana, a alert zależy od jej źródła i aktualności. Nieznany lub niedopasowany hash nie oznacza bezpieczeństwa, a źródło listy nie jest niezależnie weryfikowane. WFP, filtrowanie i automatyczne blokowanie ruchu nie są wdrożone. Brak wykrycia nie potwierdza bezpieczeństwa. Sentinel nie zastępuje Windows Defender.

## Wymagania i budowanie

- Windows x64, PowerShell, .NET SDK 10.0.300+ z najnowszą dostępną funkcją SDK, Node.js 24 i npm.
- Internet do pierwszego pobrania zależności. Własny instalator jest publikowany jako pojedynczy plik EXE.
- Brak wymaganych uprawnień administratora; instalacja jest na konto użytkownika. Polityki organizacji mogą zablokować rejestrację hosta.

```powershell
./scripts/build-user.ps1
./scripts/build-user.ps1 -Installer
```

Skrypt uruchamia testy .NET, publikuje dwa samodzielne EXE, sprawdza IPC i buduje React. Parametr `-Installer` tworzy własny kreator instalacji (bez oSI/NSIS) jako `artifacts/desktop/Sentinel.AI.Setup.<wersja>.exe`. Program instaluje się dla bieżącego użytkownika, weryfikuje wbudowany pakiet i zachowuje lokalne dane przy odinstalowaniu. Samodzielne uruchomienie deweloperskie: po `./scripts/build-user.ps1` wykonaj `./desktop/node_modules/.bin/electron.cmd ./desktop`. Nie uruchamiaj bez skompilowanego `artifacts/engine`.

Na pierwszym uruchomieniu obserwacja DNS jest wstrzymana, lista reputacji pusta. Użytkownik może ją pobrać w sekcji „Baza wiedzy”; aplikacja łączy się wtedy wyłącznie z `hole.cert.pl`. Baza pozostaje użyteczna przez 48 godzin od pobrania, potem jest oznaczana jako wygasła. Każdy import jest atomowy, poprzednią wersję można przywrócić. W sekcji reguł można zaimportować własny plik tekstowy z jednym adresem IPv4/IPv6 lub CIDR na wiersz (komentarze zaczynają się od `#`, limit 20 MiB/250 000 wpisów). Lista jest przechowywana lokalnie i dopasowywana do nowych połączeń TCP tylko przy osobno włączonym monitoringu sieci; nie jest pobierana ani wysyłana, a Sentinel nie weryfikuje jej źródła ani licencji. Trafienie tworzy ostrzeżenie, nie blokuje ruchu. W sekcji analizy można też ręcznie zaimportować plik tekstowy z jednym 64-znakowym hashem SHA-256 w każdym wierszu (opcjonalne komentarze zaczynają się od `#`). Lista jest przechowywana lokalnie i używana tylko przy ręcznym skanowaniu; Sentinel nie wysyła listy, pliku ani hashy do sieci i nie weryfikuje źródła listy. Historia i pliki bazy trafiają do `%LOCALAPPDATA%\SentinelAI\data`; historia zawiera oceny, a nie surową treść wiadomości ani pełny URL. Baza nie jest szyfrowana. Retencja jest konfigurowalna.

## Chrome i Edge

Instalator rejestruje host Native oessaging dla obu przeglądarek. Rozszerzenie z `browser-extension/` trzeba ręcznie załadować osobno w `chrome://extensions` i `edge://extensions` (tryb deweloperski → „Załaduj rozpakowane”, folder `resources/BrowserExtension` po instalacji). Po uruchomieniu popupu rozszerzenia diagnostyka aplikacji pokazuje, czy host odpowiedział. Rozszerzenie analizuje lokalnie pełny URL głównej nawigacji i może wyświetlić ostrzeżenie już po rozpoczęciu ładowania; to nie jest twarda blokada. Nie odwiedzaj prawdziwych złośliwych adresów podczas testu. Użyj `https://paypal.com.evil.test/login` lub innej domeny `.test`.

## Testy i walidacja

```powershell
dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release
node scripts/test-engine.cjs
node scripts/test-engine.cjs --windows-live  # pobiera feed i czyta systemowy cache DNS
cd desktop; npm.cmd ci; npm.cmd run build
cd ../website; npm.cmd ci; npm.cmd test; npm.cmd run build -- --base=/asystent/
```

Przed testem na czystym komputerze przeczytaj [procedurę Windows](docs/USER-VALIDATION.md), [architekturę](ARCHITECTURE.md), [ograniczenia](docs/KNOWN-LIoITATIONS.md) i [changelog](CHANGELOG.md).

Do połączenia z serwerem organizacji zobacz [konfigurację klienta Enterprise](docs/ENTERPRISE-CLIENT-SETUP.md). Serwer jest osobnym projektem i wymaga własnego wdrożenia HTTPS.

## Witryna

Źródła są w `website/`, a wspólne ilustracje i obiekty w `media/`. `npm.cmd run dev` uruchamia serwer lokalny, `npm.cmd test` sprawdza linki i zasoby, a `npm.cmd run build -- --base=/asystent/` buduje stronę razem z mediami pod ścieżką repozytorium. `.github/workflows/pages.yml` publikuje zmiany strony i katalogu `media/`; GitHub Pages musi mieć źródło ustawione na GitHub Actions w ustawieniach repozytorium.

Serwer Enterprise w `server/` nie jest częścią tej wersji User i nie jest budowany przez skrypt klienta.
