# Sentinel AI User

Rozwojowa aplikacja Windows 10/11 x64. React + TypeScript + Electron jest jedynym wspieranym interfejsem. Osobny proces .NET 10 używa lokalnych reguł i SQLite. Nie wymaga konta ani serwera Enterprise. Kod WPF zachowano wyłącznie w `legacy/` jako archiwum migracji; nie jest częścią bieżącego rozwiązania ani instalatora.

**Stan: wersja do testów technicznych, nie gotowy produkt ochronny.** Aplikacja analizuje wklejoną wiadomość lub URL, sprawdza dokładną domenę na jawnie pobranej liście CERT Polska i odczytuje cache DNS Windows po włączeniu obserwacji. Opcjonalny, domyślnie wyłączony monitoring TCP próbuje co 10 sekund wykrywać nowe połączenia `Established`/`SynSent` i zapisuje lokalnie ich metadane (IP, port, PID i nazwę procesu, jeśli dostępne). Może pominąć krótkie połączenia; nie rejestruje payloadu ani nie blokuje ruchu. DNS nie obejmuje DoH, VPN, pełnych URL ani połączeń po IP; UDP pozostaje ręcznym snapshotem endpointów. Historia ma limit 512 MiB; zapis przy braku miejsca zostaje odrzucony bez automatycznego usuwania starszych zdarzeń. WFP i kontrola pobranych plików nie są wdrożone; skan pliku na żądanie oblicza wyłącznie SHA-256. Brak wykrycia nie potwierdza bezpieczeństwa. Sentinel nie zastępuje Windows Defender.

## Wymagania i budowanie

- Windows x64, PowerShell, .NET SDK 10.0.300+ z najnowszą dostępną funkcją SDK, Node.js 24 i npm.
- Internet do pierwszego pobrania zależności. Własny instalator jest publikowany jako pojedynczy plik EXE.
- Brak wymaganych uprawnień administratora; instalacja jest na konto użytkownika. Polityki organizacji mogą zablokować rejestrację hosta.

```powershell
./scripts/build-user.ps1
./scripts/build-user.ps1 -Installer
```

Skrypt uruchamia testy .NET, publikuje dwa samodzielne EXE, sprawdza IPC i buduje React. Parametr `-Installer` tworzy własny kreator instalacji (bez MSI/NSIS) jako `artifacts/desktop/Sentinel.AI.Setup.<wersja>.exe`. Program instaluje się dla bieżącego użytkownika, weryfikuje wbudowany pakiet i zachowuje lokalne dane przy odinstalowaniu. Samodzielne uruchomienie deweloperskie: po `./scripts/build-user.ps1` wykonaj `./desktop/node_modules/.bin/electron.cmd ./desktop`. Nie uruchamiaj bez skompilowanego `artifacts/engine`.

Na pierwszym uruchomieniu obserwacja DNS jest wstrzymana, lista reputacji pusta. Użytkownik może ją pobrać w sekcji „Baza wiedzy”; aplikacja łączy się wtedy wyłącznie z `hole.cert.pl`. Baza pozostaje użyteczna przez 48 godzin od pobrania, potem jest oznaczana jako wygasła. Każdy import jest atomowy, poprzednią wersję można przywrócić. Historia i pliki bazy trafiają do `%LOCALAPPDATA%\SentinelAI\data`; historia zawiera oceny, a nie surową treść wiadomości ani pełny URL. Baza nie jest szyfrowana. Retencja jest konfigurowalna.

## Chrome i Edge

Instalator rejestruje host Native Messaging dla obu przeglądarek. Rozszerzenie z `browser-extension/` trzeba ręcznie załadować osobno w `chrome://extensions` i `edge://extensions` (tryb deweloperski → „Załaduj rozpakowane”, folder `resources/BrowserExtension` po instalacji). Po uruchomieniu popupu rozszerzenia diagnostyka aplikacji pokazuje, czy host odpowiedział. Rozszerzenie analizuje lokalnie pełny URL głównej nawigacji i może wyświetlić ostrzeżenie już po rozpoczęciu ładowania; to nie jest twarda blokada. Nie odwiedzaj prawdziwych złośliwych adresów podczas testu. Użyj `https://paypal.com.evil.test/login` lub innej domeny `.test`.

## Testy i walidacja

```powershell
dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release
node scripts/test-engine.cjs
node scripts/test-engine.cjs --windows-live  # pobiera feed i czyta systemowy cache DNS
cd desktop; npm.cmd ci; npm.cmd run build
cd ../website; npm.cmd ci; npm.cmd test; npm.cmd run build -- --base=/asystent/
```

Przed testem na czystym komputerze przeczytaj [procedurę Windows](docs/USER-VALIDATION.md), [architekturę](ARCHITECTURE.md), [ograniczenia](docs/KNOWN-LIMITATIONS.md) i [changelog](CHANGELOG.md).

## Witryna

Źródła są w `website/`, a wspólne ilustracje i obiekty w `media/`. `npm.cmd run dev` uruchamia serwer lokalny, `npm.cmd test` sprawdza linki i zasoby, a `npm.cmd run build -- --base=/asystent/` buduje stronę razem z mediami pod ścieżką repozytorium. `.github/workflows/pages.yml` publikuje zmiany strony i katalogu `media/`; GitHub Pages musi mieć źródło ustawione na GitHub Actions w ustawieniach repozytorium.

Serwer Enterprise w `server/` nie jest częścią tej wersji User i nie jest budowany przez skrypt klienta.
