# Architektura instalatora Windows

## Dwie warstwy produktu

Windowsowy instalator jest natywną aplikacją WinForms; zainstalowany Sentinel AI używa osobnego frontendu React/Vite uruchamianego w spakowanym Electronie. To różne interfejsy i nie są piksel-w-piksel identyczne. Sam instalator ma spójny własny styl, jednak Windows nadal wpływa na natywne kontrolki, czcionki i skalę DPI. Różnica w całym kreatorze wymaga najpierw sprawdzenia, czy na obu komputerach uruchomiono ten sam EXE (SHA-256).

## Granice pakietu

- Kreator jest natywną aplikacją WinForms w `installer/Sentinel.Setup/Program.cs`. Interfejs nie ładuje HTML, CSS, JavaScriptu, Node.js, Codexa ani plików z katalogu tymczasowego.
- `installer/Sentinel.Setup/Sentinel.Setup.csproj` publikuje `win-x64` jako aplikację samodzielną i jednoplikową (`SelfContained`, `PublishSingleFile`). Wymagany runtime .NET oraz kod kreatora trafiają do EXE.
- `installer/build-installer.ps1` buduje aplikację desktopową, tworzy z jej kompletnego katalogu ZIP, a następnie osadza ZIP jako `payload.zip` w kreatorze. ZIP zawiera również `resources/service` z hostem SCM i silnikiem. Helper instalatora weryfikuje SHA-256 payloadu, po jawnej zgodzie UAC instaluje usługę do `Program Files\Sentinel AI\Service` z chronionym DACL; nie wymaga osobnego pliku obok instalatora.
- Ikona pliku EXE pochodzi z `desktop/assets/sentinel.ico`, wskazanej w `ApplicationIcon`. Kreator odczytuje ikonę z uruchomionego EXE.
- Końcowy plik to `artifacts/desktop/Sentinel.AI.Setup.<wersja>.exe`; obok powstaje plik `.sha256`.

## Wątek interfejsu i przepływ instalacji

- Sprawdzanie wybranego drzewa katalogów, wolnego miejsca i zachowywanych plików może wymagać enumeracji wielu wpisów systemu plików. Kreator uruchamia te operacje w tle; odświeża ekran tylko wynikiem dla aktualnie wybranej ścieżki.
- Właściwa instalacja (weryfikacja payloadu, staging, rozpakowanie, weryfikacja plików, atomowa zamiana katalogu, konfiguracja HKCU, skróty i Native Messaging) działa poza wątkiem WinForms. Na końcu helper z UAC rejestruje lub aktualizuje usługę i instalator czeka na pierwszy cykl. Helper sprawdza heartbeat pipe, gdy działa pod tym samym SID-em co instalujący; przy podaniu poświadczeń odrębnego administratora sprawdzenie pozostawia procesowi UI działającemu jako użytkownik docelowy. Postęp ekstrakcji pochodzi z rzeczywiście zapisanych bajtów; osobny etap komunikatu UAC nie jest sztucznie animowany.
- Deinstalacja najpierw prosi o UAC i usuwa tylko rozpoznaną usługę Sentinel oraz jej pliki; dane ProgramData są zachowane. Przy odmowie UAC zmiany per-user nie są jeszcze wykonywane. Pełny cykl install/repair/update/uninstall przeszedł w Windows CI [41734288659](https://github.com/Matyyyy68/asystent/actions/runs/41734288659), łącznie z widocznym kreatorem i testem headless. Dodano wymuszony rollback błędu helpera po aktywacji payloadu; przeszedł Windows CI [41856785028](https://github.com/Matyyyy68/asystent/actions/runs/41856785028). Test na fizycznym czystym Windows 10/11 pozostaje niewykonany.
- Każda zmiana etapu zapisuje `INSTALL_STAGE` w logu w `%LOCALAPPDATA%\Sentinel AI\Logs\installer.log`. Błąd zapisuje etap i operację, a kreator udostępnia ten log.
- Sekwencja GUI jest serializowana, aby szybkie lub powtórzone kliknięcie nie uruchomiło drugiego równoległego przejścia podczas asynchronicznego preflightu.

## Co może się różnić między komputerami

Pakiet zawiera ten sam interfejs i zasoby, ale system Windows nadal wpływa na skalę i rasteryzację tekstu oraz natywnych kontrolek. Kreator używa `Segoe UI` i `AutoScaleMode.Dpi`, dlatego rozmiar fizyczny elementów może różnić się przy ustawieniu innego skalowania ekranu. Pixel-perfect identyczność na każdym DPI i wydaniu Windows nie jest obietnicą WinForms.

Jeżeli inne urządzenie pokazuje zupełnie inny, systemowy interfejs, w pierwszej kolejności należy porównać SHA-256 i wersję uruchomionego EXE. Dla tej implementacji „brak styli WWW” nie jest możliwy, bo kreator nie zależy od warstwy webowej.

## Zasoby kreatora

Ilustracje stron kreatora są kompilowane jako `EmbeddedResource`: `welcome`, `prepare`, `configure`, `installing`, `complete`, `error`, `system-check` i `rollback-ready`. Brak lub uszkodzenie zasobu zapisuje diagnostykę i blokuje przejście dalej zamiast pokazywać niekompletny interfejs. `--self-test` sprawdza wszystkie zasoby oraz ikonę w opublikowanym pliku.

Build sprawdza źródłowe pliki ikony i ilustracji przed usunięciem poprzednich wyników. Odrzuca niekompletną bibliotekę, a `scripts/build-user.ps1` czyści współdzielony katalog silników przed publikacją obu programów, aby pozostałości poprzedniego buildu nie trafiały do instalatora.

