# Architektura instalatora Sentinel AI

## Dwie osobne warstwy

Windowsowy instalator jest natywną aplikacją WinForms w `installer/Sentinel.Setup`. Nie korzysta z Electron, WebView2, przeglądarki ani serwera Vite. Interfejs kreatora i jego kod są skompilowane do jednego pliku EXE. Ilustracje ekranów są osadzonymi zasobami assembly, a nie plikami pobieranymi obok instalatora.

Zainstalowany produkt ma osobny interfejs: produkcyjny frontend React/Vite działa w spakowanym Electronie. `installer/build-installer.ps1` buduje frontend, przygotowuje produkcyjny katalog Electron `win-unpacked`, pakuje jego zawartość do ZIP i osadza ZIP w instalatorze jako `payload.zip`. Zależności npm i runtime Chromium/Electron są częścią tego payloadu. Silniki .NET są publikowane jako samodzielne aplikacje dla Windows x64. Użytkownik nie potrzebuje Node.js, npm, repozytorium ani osobnej instalacji .NET lub WebView2.

## Przyczyna i zachowanie UI

Źródłem różnic między środowiskami jest architektura kreatora: to UI WinForms, a nie ten sam frontend webowy co w aplikacji. WinForms korzysta z natywnych kontrolek Windows, więc wygląd pól, checkboxów, czcionek i ich skalowanie zależą częściowo od wersji Windows, motywu oraz DPI. Aplikacja zainstalowana używa zaś własnego frontendu HTML/CSS w Electronie. Obie warstwy nie mogą wyglądać identycznie piksel w piksel, bo są innymi technologiami.

Kreator ustawia własne kolory, typografię i płaskie przyciski, używa `AutoScaleMode.Dpi`, a projekt jawnie deklaruje `PerMonitorV2`. Okno jest skalowalne i ma minimalny rozmiar. Test kreatora przechodzi po ekranach, sprawdza ilustracje, nawigację klawiaturą, pola i bezpieczny fokus. Test nie zastępuje wizualnej kontroli na różnych wersjach Windows i DPI.

## Zasoby i ścieżki

Build sprawdza obecność oficjalnej ikony oraz siedmiu ilustracji wymaganych kreatorem przed wyczyszczeniem starego wyniku. Ilustracje są dołączane jako zasoby assembly o stabilnych nazwach `installer-<nazwa>.png`. Payload jest dołączany jako zasób `payload.zip`; jego SHA-256 jest wpisany do metadanych assembly i sprawdzany przed instalacją. Zawartość rozpakowuje się do katalogu wybranego przez użytkownika; ścieżki są traktowane jako ścieżki Windows, w tym zawierające spacje i polskie znaki.

Log diagnostyczny instalatora znajduje się w `%LOCALAPPDATA%\Sentinel AI\Logs\installer.log`. Zawiera informacje o etapach, błędach i brakujących zasobach bez haseł ani tokenów. Jeśli nie uda się załadować ilustracji, kreator zapisuje diagnostykę, pokazuje komunikat z lokalizacją logu i blokuje kontynuację. Kreator udostępnia przycisk „Otwórz log”.

## Ikona pliku EXE

Źródłem ikony jest `desktop/assets/sentinel.ico`. Zawiera obrazy 16, 24, 32, 48, 64, 128 i 256 px. `Sentinel.Setup.csproj` przypisuje ją przez `<ApplicationIcon>`, co osadza zasób ikony w pliku wykonywalnym; nie jest to jedynie obraz w oknie ani ikona skrótu. `--self-test` odczytuje ikonę z uruchomionego EXE. Windows CI uruchamia ten test na zbudowanym pliku. Po zbudowaniu warto dodatkowo skopiować EXE w Eksploratorze do nowego katalogu i sprawdzić ikonę przy wyłączonym widoku miniaturek/cache.

## Testy i ograniczenia

`installer/build-installer.ps1` usuwa poprzedni `artifacts/desktop` po sprawdzeniu wymaganych lokalnych plików i przed rozpoczęciem kompilacji. `scripts/build-user.ps1` czyści również wspólny `artifacts/engine` przed publikacją obu silników. Dzięki temu brak pliku wynikowego oznacza nieudany build zamiast pozostawienia EXE ze starego przebiegu.

Automatyczne testy zawartości i zachowania opisuje [INSTALLER_TESTING.md](INSTALLER_TESTING.md); dokładne komendy budowania są w [INSTALLER_RELEASE.md](INSTALLER_RELEASE.md). Linux nie może potwierdzić wyglądu WinForms, integracji z Eksploratorem, UAC ani instalacji na czystym Windows. Do takich wniosków wymagany jest wynik Windows CI i ręczna walidacja z `USER-VALIDATION.md`.
