# Inwentaryzacja deklaracji licencji zależności

Stan na 2026-10-22. .NET: lista pochodzi z plików `project.assets.json` bieżącego checkoutu dla klienta, serwera, instalatora i testów; sprawdzono lokalne metadane NuGet (`.nuspec`). JavaScript: lista par pakiet/wydanie i deklaracji pochodzi z `desktop/package-lock.json` oraz `website/package-lock.json`; obecność na dysku sprawdzono względem odpowiadających im ścieżek w `node_modules`. Wyniki są deklaracjami wydawców, nie opinią prawną ani pełną oceną warunków redystrybucji.

Raport npm można odtworzyć poleceniem `pwsh -File scripts/audit-dependency-licenses.ps1`; skrypt zachowuje wiersze NuGet z istniejącego CSV, wykrywa brakujące i sprzeczne deklaracje oraz odróżnia wpisy lockfile od obecnych lokalnie pakietów.

Zebrano deklaracje dla 313 unikalnych par pakiet/wydanie: 23 NuGet oraz 290 npm zapisanych w lockfile. Wszystkie 290 wpisów lockfile zawierają deklarację licencji; 240 par odpowiada paczkom obecnym lokalnie w `node_modules`, a 50 nie jest zainstalowanych w bieżącym środowisku (m.in. warianty platformowe). CSV oznacza te dwa stany osobno. Raport nie obejmuje treści całych paczek binarnych, narzędzi CI ani transitive system runtimes.

## npm / Electron

| Deklaracja `license` | Liczba pakietów |
|---|---:|
| MIT | 175 |
| ISC | 33 |
| BlueOak-1.0.0 | 8 |
| Apache-2.0 | 7 |
| BSD-3-Clause | 7 |
| BSD-2-Clause | 5 |
| `(WTFPL OR MIT)` | 1 |
| `0BSD` | 1 |
| `Python-2.0` | 1 |
| WTFPL | 1 |
| `WTFPL OR ISC` | 1 |

Deklaracje inne niż MIT/ISC/Apache-2.0/BSD wymagają ręcznego przeglądu warunków, zwłaszcza przy redystrybucji: `chownr@3.0.0`, `isexe@3.1.5` i `4.0.0`, `minimatch@10.2.6`, `minipass@7.1.3`, `sax@1.6.1`, `tar@7.5.22`, `yallist@5.0.0` (BlueOak); `utf8-byte-length@1.0.5` (WTFPL OR MIT); `tslib@2.8.1` (0BSD); `argparse@2.0.1` (Python-2.0); `truncate-utf8-bytes@1.0.2` (WTFPL); `sanitize-filename@1.6.4` (WTFPL OR ISC). Zestaw deklaracji zależności zainstalowanych jest dostępny w [CSV](dependency-license-inventory.csv).

### Zawartość instalatora Windows

Inwentarz 290 wpisów npm łączy aplikację z narzędziami deweloperskimi i buildowymi strony. Porównanie `desktop/package-lock.json` z polem `dev` wykazało cztery zależności npm aplikacji oznaczone jako produkcyjne: `lucide-react@0.468.0` (ISC), `react@19.3.1` (MIT), `react-dom@19.3.1` (MIT) i `scheduler@0.28.0` (MIT). Ich kod trafia do zbudowanego UI. `scripts/build-npm-third-party-notices.mjs` odczytuje bieżący lockfile i pliki licencji pakietów, a instalator dołącza pełne teksty do `resources/ThirdPartyNotices/npm-runtime.txt`; budowa kończy się błędem, jeśli nie może potwierdzić wersji lub znaleźć dokładnie jednego pliku licencji dla zależności runtime.

Electron jest zależnością buildową w npm, lecz jego runtime jest osadzany przez electron-builder. W gotowym katalogu Windows zweryfikowano `LICENSE.electron.txt` i `LICENSES.chromium.html`. Silnik zawiera osobny tekst licencji PdfPig w `resources/engine/THIRD-PARTY-LICENSES/`; nagłówki licencyjne Mozilla Public Suffix List pozostają w danych PSL. Pozostałe pakiety npm z lockfile nie są z tego powodu automatycznie traktowane jako redystrybuowane. Raport zakresu instalatora nadal nie zastępuje przeglądu pełnego self-contained .NET runtime, wszystkich transitive NuGet zależności ani licencji samego produktu.

## MIT

- `Microsoft.CodeCoverage 18.11.0`
- `Microsoft.Data.Sqlite.Core 10.0.13`
- `Microsoft.Data.Sqlite 10.0.13`
- `Microsoft.Extensions.Hosting.WindowsServices 10.0.13`
- `Microsoft.NET.ILLink.Tasks 10.0.10`, `10.0.13`
- `Microsoft.NET.Test.Sdk 18.11.0`
- `Microsoft.TestPlatform.ObjectModel 18.11.0`
- `Microsoft.TestPlatform.TestHost 18.11.0`
- `System.ServiceProcess.ServiceController 10.0.13`

## Apache-2.0

- `PdfPig 0.1.16`
- `SQLitePCLRaw.bundle_e_sqlite3 2.1.13`
- `SQLitePCLRaw.core 2.1.13`
- `SQLitePCLRaw.lib.e_sqlite3 2.1.13`
- `SQLitePCLRaw.provider.e_sqlite3 2.1.13`
- `xunit.analyzers 1.18.0`
- `xunit.assert 2.9.3`
- `xunit.core 2.9.3`
- `xunit.extensibility.core 2.9.3`
- `xunit.extensibility.execution 2.9.3`
- `xunit.runner.visualstudio 4.0.1`
- `xunit 2.9.3`

## Wymaga ręcznej weryfikacji

- `xunit.abstractions 2.0.3` — nuspec wskazuje [plik licencji projektu XUnit](https://raw.githubusercontent.com/xunit/xunit/master/license.txt), a nie wyrażenie SPDX. Plik opisuje Apache-2.0 jako licencję ogólną i zawiera wyjątki MIT dla dwóch importowanych komponentów.

Właściciel nie wskazał jeszcze licencji samego Sentinel AI. Nie dodano pliku `LICENSE`; decyzja produktu i zgodność całego zestawu źródeł/redystrybucji pozostają otwarte. Pozostają ręczny przegląd deklaracji nietypowych, faktycznie redystrybuowanych zależności NuGet/.NET i dołączonych narzędzi. 50 wpisów npm nieobecnych lokalnie wymaga dalszego sprawdzenia tylko wtedy, gdy dany pakiet trafia do konkretnego artefaktu; sam brak katalogu w `node_modules` nie dowodzi redystrybucji.
