# Instalator Sentinel AI User 0.2.0

`artifacts/installer/SentinelAI-0.2.0-win-x64-Setup.exe` to samodzielny instalator x64 NSIS 3.11 z polskim kreatorem. Można wybrać User albo Enterprise Client. W tym wydaniu wariant Enterprise Client jest lokalnym trybem awaryjnym bez parowania i synchronizacji; UI sygnalizuje tę granicę. Nie ma instalacji Enterprise Server. Użytkownik uruchamia EXE dwuklikiem. Nie potrzebuje SDK, Python, NSIS ani połączenia z Internetem podczas instalacji.

## Zachowanie

- Instalacja per użytkownik: `%LOCALAPPDATA%\Programs\Sentinel AI\app`, bez UAC i uprawnień administratora.
- Menu Start: aplikacja, pomoc i odinstalowanie; opcjonalny skrót na pulpicie.
- Rejestracja w aplikacjach Windows w HKCU, z wersją i deinstalatorem.
- Zawiera runtime .NET i Windows Desktop dla x64, SQLite oraz teksty licencyjne runtime.
- Kreator pierwszego uruchomienia proponuje `%LOCALAPPDATA%\SentinelAI\Data`; dane użytkownika są poza katalogiem programu.
- App i installer używają mutexu `Local\SentinelAI.Desktop`. Instalator wymaga zamknięcia programu; nie zabija procesu.
- Ponowna instalacja odświeża pliki programu i domyślnie zachowuje wariant. Próba zmiany wariantu przy aktualizacji jest blokowana. Odinstalowanie domyślnie zachowuje historię; osobne pytanie pozwala jawnie usunąć wyłącznie `sentinel.db` i pliki SQLite sidecar ze wskazanego katalogu. Inne pliki nie są kasowane, a katalog jest usuwany tylko jeśli pozostaje pusty.
- Wersja aplikacji i plik EXE mają metadane 0.2.0. Paczka zawiera sumę SHA-256 i manifest każdego pliku.
- Nie ma autostartu, aktualizatora, dodatku przeglądarki ani zmian ustawień zabezpieczeń.

Wymagany jest Windows 10/11 x64. Instalator jest niepodpisany: nie dostarczono certyfikatu podpisywania kodu. Do dystrybucji z rozpoznawanym wydawcą potrzebny jest zaufany certyfikat i podpis po końcowym pakowaniu. Samopodpisany certyfikat nie rozwiązuje problemu zaufania Windows.

## Budowanie przez dewelopera

W środowisku chmurowym:

```bash
bash scripts/build-installer-cloud.sh
```

SDK przygotowuje dotychczasowy `scripts/setup-cloud.sh`. Narzędzia NSIS/7-Zip pobiera `scripts/setup-installer-tools.sh` z repozytorium Debiana na podstawie podpisanego indeksu, bez wyłączania weryfikacji pakietów i bez instalacji systemowej. Kompilator jest rozpakowany do `/workspace/tools/installer/root`.

Na Windows, po zainstalowaniu .NET SDK z global.json, Python 3 i NSIS 3.11+ dostępnego w PATH:

```powershell
python scripts/package-installer.py
```

Skrypt odtwarza zależności w locked-mode, kompiluje Release, wykonuje testy, publikuje do nowego katalogu tymczasowego i pakuje EXE. Nie korzysta ze starych plików publikacji. Usuwa symbole PDB, dołącza pomoc i licencje runtime, generuje manifest odinstalowania oraz SHA-256. Wszystkie błędy kompilacji i testów przerywają pakowanie. Kompilator NSIS traktuje ostrzeżenia jako błędy.

## Weryfikacja

Wykonano:

- kompilację Release: 0 błędów, 0 ostrzeżeń;
- 66 testów aplikacji;
- kontrolę architektury PE x64, sumy EXE i hashy wszystkich plików aplikacji wyodrębnionych z instalatora;
- instalację i ponowną instalację w osobnym profilu Wine 10, kontrolę plików, skrótów i wpisu odinstalowania;
- odinstalowanie i potwierdzenie zachowania syntetycznej historii oraz dodatkowego prywatnego pliku w katalogu programu;
- uruchomienie kreatora na wirtualnym ekranie i wizualną kontrolę polskiej strony powitalnej.

7-Zip nie odtwarza deinstalatora generowanego podczas instalacji NSIS x64; jego istnienie i działanie sprawdzono przez rzeczywistą instalację/odinstalowanie pod Wine. To odrębne sprawdzenie od weryfikacji archiwum.

Wine nie zastępuje natywnego Windows. Uruchomienie nowego kreatora pierwszego startu WPF, integracja UI Automation i komunikat SmartScreen nadal wymagają sprawdzenia na Windows 10/11. Procedura: `docs/WINDOWS-VALIDATION.md`. Testy instalatora nie oznaczają implementacji przyszłych funkcji AI/RAG.
