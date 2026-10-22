# Inwentaryzacja deklaracji licencji zależności

Stan na 2026-10-22. .NET: lista pochodzi z plików `project.assets.json` bieżącego checkoutu dla klienta, serwera, instalatora i testów; sprawdzono lokalne metadane NuGet (`.nuspec`). JavaScript: sprawdzono `package.json` zainstalowanych zależności w `desktop/node_modules` i `website/node_modules`. Wyniki są deklaracjami wydawców, nie opinią prawną ani pełną oceną warunków redystrybucji.

Zebrano deklaracje dla 263 unikalnych par pakiet/wydanie: 23 NuGet oraz 240 zainstalowanych npm. Lockfile npm zawierają 290 unikalnych par pakiet/wydanie; 50 nie jest zainstalowanych w bieżących folderach `node_modules` (m.in. warianty platformowe) i ich deklaracje nie są w tym raporcie zweryfikowane. Wszystkie 240 zainstalowanych pakietów npm mają pole licencji w manifeście. Raport nie obejmuje treści całych paczek binarnych, narzędzi CI ani transitive system runtimes.

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

Właściciel nie wskazał jeszcze licencji samego Sentinel AI. Nie dodano pliku `LICENSE`; decyzja produktu i zgodność całego zestawu źródeł/redystrybucji pozostają otwarte. Pozostają ręczny przegląd deklaracji nietypowych, 49 npm pakietów zapisanych w lockfile, ale nieobecnych lokalnie, oraz dołączonych narzędzi.
