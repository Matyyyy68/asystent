# Wydawanie instalatora Sentinel AI

1. Zaktualizuj jedną wersję produktu w `eng/ProductVersion.props`, `desktop/package.json` i `website/package.json`, jeśli publikujesz nową wersję.
2. Na Windows odtwórz zablokowane zależności, uruchom wszystkie testy i zbuduj kompletny payload oraz instalator poleceniem `./scripts/build-user.ps1 -Installer -Offline`. `-AllowDownloads` jest przeznaczone tylko dla jawnie kontrolowanego przygotowania narzędzi.
3. Sprawdź, że powstał `artifacts/desktop/Sentinel.AI.Setup.<wersja>.exe`, a skrypt zgłosił `Autotest instalatora: PASS`. Nie zmieniaj nazwy pliku bez aktualizacji pliku `.sha256`.
4. Na świeżej maszynie testowej Windows zweryfikuj EXE, sumę SHA-256, powitanie, lokalizację, opcje, instalację, naprawę/aktualizację i deinstalację. Nie wymaga to komputera użytkownika.
5. Do wydania dołącz EXE oraz wygenerowany plik `.sha256`. Umieść ten sam EXE na stronie pobierania i na stronie wydania; nie publikuj osobno payload ZIP ani plików z `bin`, `obj` lub cache.
6. Po opublikowaniu pobierz wydany plik do czystego katalogu i ponownie porównaj SHA-256. To wykrywa pomylenie wersji lub starego artefaktu.

## Podpis cyfrowy

Konfiguracja `desktop/package.json` ma `signExecutable: false`; instalator nie jest podpisywany Authenticode. Dodanie podpisu wymaga certyfikatu wydawcy i osobnej konfiguracji sekretów CI. Nie instaluj certyfikatu głównego ani localhost w systemie użytkownika jako obejścia problemu wyglądu.

## Wygląd

Każde wydanie zawiera osadzony kreator WinForms oraz ikonę Sentinel AI. Rozmiar kontrolek może się skalować wraz z DPI Windows; porównuj artefakty o identycznym SHA-256 przed diagnozowaniem „braku stylów”.
