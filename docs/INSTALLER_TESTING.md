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
5. przed wydaniem testuje dokładny plik z assetów: self-test, instalację/aktualizację/weryfikację/deinstalację w odizolowanym katalogu oraz widoczny przepływ kreatora na runnerze Windows.

Testy GUI uruchamia runner CI, a nie komputer użytkownika. Do kontroli dostarczonego pliku porównaj sumę `Get-FileHash .\Sentinel.AI.Setup.<wersja>.exe -Algorithm SHA256` z plikiem `.sha256`.

## Wyniki sprawdzone w poprzednim wydaniu

- `.NET`: 403 PASS, 2 SKIP, 0 FAIL.
- Testy aplikacji desktopowej: 58/58 PASS.
- Test biblioteki ilustracji, test strony i buildy produkcyjne strony/aplikacji: PASS. Buildy Vite w tym sandboxie wymagają `--configLoader runner`.
- Kompilacja/publikacja samego projektu instalatora jako jednoplikowego `win-x64` oraz odczyt ikony z PE: PASS; nie uruchamiano EXE. Nie wykonano pełnego świeżego pipeline'u payloadu, `--self-test` ani widocznego GUI na komputerze użytkownika.

## Regresja wydania 0.15.39

Wydanie przenosi rekurencyjne sprawdzenie ścieżki i miejsca z GUI do pracy asynchronicznej, serializuje nawigację i zapisuje etapy. Release run [40942017352](https://github.com/Matyyyy68/asystent/actions/runs/40942017352) PASS na dokładnym artefakcie: pełny build i `--self-test`, instalacja, aktualizacja, weryfikacja, deinstalacja oraz widoczny test kreatora. Release jest prerelease. Jest to świeży hostowany runner Windows, a nie fizycznie czysty komputer odbiorcy bez narzędzi developerskich.

Walidacja lokalnego kodu 0.15.39: build projektu instalatora PASS, 0 ostrzeżeń/błędów; `--wizard-self-test` PASS, w tym kontrolowana blokada sprawdzania miejsca i potwierdzenie, że nawigacja oddaje sterowanie UI; desktop Node 58/58 PASS; .NET 403 PASS, 2 pominięte testy zależne od środowiska, 0 błędów; `website npm test` PASS (103 ilustracje), `website npm run lint` PASS; `node scripts/check-product.cjs` oraz parsowanie workflow PASS. Release asset: `Sentinel.AI.Setup.0.15.39.exe`, 274 317 878 B, SHA-256 `894004BF4C3784917BE342A3658733C9D1383AE0DB0E9D3E522DA59B3F14A803`. Publiczny sidecar zweryfikowano względem digestu GitHub, HTTP HEAD EXE zwrócił 200. Rozszerzona walidacja całego repozytorium w workflow CI 40941791192 nadal trwa.

## Ograniczenie porównania wizualnego

W treści specyfikacji wspomniano zrzut wadliwego kreatora, ale do repozytorium nie dołączono jego pliku obrazu. CI sprawdza dostępność stanów, zachowanie i prawidłowe zasoby; nie porównuje pikseli z komputerem odbiorcy. Dla zgłoszenia konkretnej różnicy należy zachować SHA-256 testowanego EXE, wersję Windows, skalowanie DPI i zrzut ekranu.
