# Testowanie instalatora Windows

## Automatyczne testy

Windows CI uruchamia `scripts/build-user.ps1 -Installer -AllowDownloads`. Ten pipeline wykonuje testy .NET, Electron i projektu, buduje produkcyjny frontend oraz instalator, a `installer/build-installer.ps1` uruchamia `--self-test` na gotowym EXE. Self-test weryfikuje SHA-256 i zawartość payloadu, ilustracje, osadzoną ikonę EXE oraz symulowane scenariusze instalacji, aktualizacji, awarii i rollbacku.

Workflow CI uruchamia ponadto `--integration-test` (instalacja, weryfikacja, deinstalacja) oraz `--wizard-integration-test`, który automatyzuje widoczny kreator. Wynikiem tych zadań są logi GitHub Actions. Samo istnienie workflow albo wcześniejszy zielony przebieg nie potwierdza stanu aktualnego commita; wynik należy sprawdzić dla commita zawierającego zmiany.

Wyniki bieżącej pracy na Linuxie: `dotnet build installer/Sentinel.Setup/Sentinel.Setup.csproj -c Release -r win-x64 --self-contained true --no-restore` PASS (0 ostrzeżeń, 0 błędów); `node scripts/check-product.cjs` PASS; ikona ICO zawiera rozmiary 16, 24, 32, 48, 64, 128 i 256 px. `npm test` dał 54 PASS i 4 FAIL w `test/lifecycle-log-path.test.cjs`: oczekiwana ścieżka Windows z separatorami `\` jest porównywana z wynikiem `path.join` działającego pod Linuxem, który używa `/`. To ograniczenie testu na obcej platformie; testu na Windows nie zastępuje.

Pełnego EXE nie zbudowano ani nie uruchomiono: dostępny jest Linux i .NET SDK, lecz brakuje PowerShell Core i środowiska Windows do uruchomienia WinForms. Nie wykonano `--self-test`, GUI, instalacji ani kontroli osadzonej ikony finalnego EXE. Nie oznaczaj tych testów jako zaliczonych. Wykonaj build i Windows CI po wypchnięciu zmian.

## Czysty Windows 10/11 x64

1. Pobierz `Sentinel.AI.Setup.<wersja>.exe` i odpowiadający mu `.sha256` z GitHub Release. Sprawdź SHA-256 w PowerShell:

   ```powershell
   $exe = (Resolve-Path .\Sentinel.AI.Setup.<wersja>.exe).Path
   $expected = ((Get-Content "$exe.sha256" -Raw).Trim() -split '\s+')[0]
   $actual = (Get-FileHash $exe -Algorithm SHA256).Hash
   if ($actual -ne $expected) { throw 'SHA-256 does not match' }
   ```

2. Skopiuj EXE do innego katalogu, odłącz dostęp do repozytorium i narzędzi deweloperskich. Nie uruchamiaj Vite ani lokalnego serwera. Sprawdź ikonę pliku w Eksploratorze po zmianie katalogu i odświeżeniu widoku.
3. Uruchom EXE i sprawdź czytelność wszystkich ekranów przy 100%, 150% i 200% skalowaniu. Przejdź instalację z lokalizacją zawierającą spacje i polskie znaki. Zmień opcje skrótu pulpitu, menu Start, autostartu i uruchomienia po instalacji.
4. Sprawdź postęp, przerwanie instalacji, ponowne uruchomienie instalatora (naprawa/aktualizacja), rejestrację w Ustawieniach Windows oraz odinstalowanie. Potwierdź, że historia i dane użytkownika zachowują się zgodnie z komunikatem kreatora.
5. Sprawdź uruchomienie aplikacji, pracę bez internetu oraz logi w `%LOCALAPPDATA%\Sentinel AI\Logs\installer.log`. Nie wyłączaj Defendera ani SmartScreen. Zapisz system Windows, rozdzielczość, skalowanie, wersję, SHA-256, wynik każdego kroku i zredagowane logi.

Pełna walidacja produktu jest w [USER-VALIDATION.md](USER-VALIDATION.md). Nie publikuj jako gotowego wydania, dopóki bieżący Windows CI nie przejdzie i test czystego komputera nie zostanie wykonany lub jawnie oznaczony jako niewykonany.
