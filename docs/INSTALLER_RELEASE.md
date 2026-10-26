# Budowanie i wydawanie instalatora

## Wymagania

Użyj Windows x64, PowerShell 7, .NET SDK 10, Node.js 24, npm oraz Git. Tryb `-AllowDownloads` pobiera zależności wskazane przez lockfile; tryb `-Offline` wymaga wcześniej przygotowanych pakietów, Electron runtime i NuGet assets.

## Powtarzalny build

Z katalogu repozytorium uruchom:

```powershell
./scripts/build-user.ps1 -Installer -AllowDownloads
```

Pełny pipeline uruchamia testy, buduje silniki i frontend produkcyjny, sprawdza licencje zależności, pakuje Electron i wywołuje `installer/build-installer.ps1`. Wariant offline to `./scripts/build-user.ps1 -Installer -Offline` i nie wykonuje pobrań. Nie buduj samym `dotnet publish`, bo wtedy nie powstanie kompletny payload.

Build sprawdza ikonę i zasoby, usuwa poprzedni `artifacts/desktop`, publikuje aplikację do `win-unpacked`, tworzy ZIP payloadu, oblicza jego SHA-256 i osadza go wraz z zasobami w samodzielnym EXE. Po publikacji zmienia nazwę pliku na `artifacts/desktop/Sentinel.AI.Setup.<wersja>.exe`, zapisuje obok sidecar SHA-256 i uruchamia `--self-test`. Udany proces kończy się komunikatem `Autotest instalatora: PASS`.

## Weryfikacja i publikacja

1. Sprawdź status `scripts/build-user.ps1 -Installer -AllowDownloads` i Windows CI dla tego samego commita.
2. Zweryfikuj rozmiar, SHA-256, sidecar, pliki produkcyjne oraz test ikony. Wykonaj test na czystym Windows opisany w [INSTALLER_TESTING.md](INSTALLER_TESTING.md).
3. Wersję zmieniaj wyłącznie dla wydania zawierającego istotną, sprawdzoną zmianę. `eng/ProductVersion.props` jest źródłem wersji .NET; kontrola `scripts/check-product.cjs` wykrywa niespójność z pozostałymi metadanymi produktu.
4. Wypchnij commit na `main`, sprawdź zielony CI, a następnie utwórz tag `v<wersja>` zgodny z wersją projektu. Workflow `release-user.yml` ponownie buduje instalator, uruchamia self-test i publikuje prerelease z EXE oraz `.sha256`.
5. Po publikacji pobierz EXE z Release, porównaj hash, uruchom go poza repozytorium i sprawdź publiczny link do pobrania.

Nie przenoś do Release EXE z lokalnego cache ani artefaktu, którego commit, wersja i hash nie zostały potwierdzone. Wynik Windows CI i ręczny test czystej maszyny raportuj oddzielnie.
