# Testy instalatora Windows

## Testy lokalne bez wyświetlania kreatora

Na Windows, po przygotowaniu zablokowanych zależności aplikacji:

```powershell
./installer/build-installer.ps1 -Offline
```

Pełny pipeline wydania uruchamiaj przez `./scripts/build-user.ps1 -Installer -Offline` (lub `-AllowDownloads` w kontrolowanym środowisku przygotowania). Skrypt buduje silniki, frontend i payload, tworzy samodzielne EXE, oblicza SHA-256 i uruchamia `--self-test`. Test sprawdza osadzony payload, wszystkie zasoby ilustracji, ikonę EXE, wybór ścieżki, instalację/aktualizację/deinstalację w folderze tymczasowym i ochronę lokalnych danych. Nie uruchamia zwykłego kreatora dla użytkownika.

## Testy Windows CI

Workflow `.github/workflows/ci.yml` na świeżym runnerze Windows wykonuje:

1. pełny build aplikacji i instalatora oraz testy .NET;
2. test bezokienkowy instalacji, weryfikacji i usunięcia kopii tymczasowej;
3. widoczny test stron kreatora, opcji naprawy i przepływu instalacji/deinstalacji;
4. test E2E rozszerzenia Chrome i Edge w profilach izolowanych.

Testy GUI uruchamia runner CI, a nie komputer użytkownika. Do kontroli dostarczonego pliku porównaj sumę `Get-FileHash .\Sentinel.AI.Setup.<wersja>.exe -Algorithm SHA256` z plikiem `.sha256`.

## Wyniki sprawdzone w tej zmianie

- `.NET`: 403 PASS, 2 SKIP, 0 FAIL.
- Testy aplikacji desktopowej: 58/58 PASS.
- Test biblioteki ilustracji, test strony i buildy produkcyjne strony/aplikacji: PASS. Buildy Vite w tym sandboxie wymagają `--configLoader runner`.
- Kompilacja/publikacja samego projektu instalatora jako jednoplikowego `win-x64` oraz odczyt ikony z PE: PASS; nie uruchamiano EXE. Nie wykonano pełnego świeżego pipeline'u payloadu, `--self-test` ani widocznego GUI na komputerze użytkownika.

## Ograniczenie porównania wizualnego

W treści specyfikacji wspomniano zrzut wadliwego kreatora, ale do repozytorium nie dołączono jego pliku obrazu. CI sprawdza dostępność stanów, zachowanie i prawidłowe zasoby; nie porównuje pikseli z komputerem odbiorcy. Dla zgłoszenia konkretnej różnicy należy zachować SHA-256 testowanego EXE, wersję Windows, skalowanie DPI i zrzut ekranu.
