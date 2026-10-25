# Inwentaryzacja deklaracji licencji zależności

Stan na 2026-10-25. JavaScript: inwentarz odświeżono z bieżących `desktop/package-lock.json` i `website/package-lock.json`; obecność na dysku sprawdzono względem ścieżek w `node_modules`. W porównaniu z wcześniejszym CSV zmieniły się tylko wersje `electron` 44.9.1 i `fast-uri` 3.1.9; liczebność oraz deklaracje licencji pozostały takie same. .NET: 23 wiersze zachowano z audytu 2026-10-22, który pochodzi z `project.assets.json` bieżącego checkoutu dla klienta, serwera, instalatora i testów oraz lokalnych metadanych NuGet (`.nuspec`). Wyniki są deklaracjami wydawców, nie opinią prawną ani pełną oceną warunków redystrybucji.

**Kontrola lokalnego artefaktu Windows (2026-10-25):** ponownie sprawdzono już istniejący, nieuruchamiany instalator `artifacts/desktop/Sentinel.AI.Setup.0.15.38.exe` (287 632 761 B; SHA-256 `42A0741A8AB21E73BD0EE2EEB12E1ABC36AAF3683A79EDBB112905E0E4B7B256`); sidecar `.sha256` zgadza się z obliczonym hashem. Odczyt `resources/app.asar` wykazał cztery spakowane pakiety npm: `lucide-react`, `react`, `react-dom` i `scheduler`; `resources/ThirdPartyNotices/npm-runtime.txt` zawiera ich dokładne wersje i pełne deklarowane teksty licencji. W katalogu `win-unpacked` potwierdzono też `nuget-runtime.txt`, notices .NET, licencję PdfPig oraz pliki licencji Electron i Chromium. Ten przegląd potwierdza obecność wskazanych notices w lokalnym artefakcie, ale nie ocenia prawnie ich treści ani całej zawartości binarnej SDK, Chromium i runtime.

Raport npm można odtworzyć poleceniem `pwsh -File scripts/audit-dependency-licenses.ps1`; skrypt zachowuje wiersze NuGet z istniejącego CSV, wykrywa brakujące i sprzeczne deklaracje w lockfile, a dla lokalnych pakietów porównuje wersję i deklarację licencji z dokładnym `package.json` wskazanym przez wpis lockfile. Raport wskazuje też status zależności deweloperskiej i odróżnia wpisy lockfile od obecnych lokalnie pakietów. Jeśli tę samą parę pakiet/wydanie używa wiele lockfile, oznaczenie runtime ma pierwszeństwo przed dev-only. Podczas pakowania Windows `scripts/audit-packaged-npm-licenses.mjs` porównuje rzeczywiste moduły w `app.asar` z runtime'owymi wpisami lockfile, manifestami wersji/licencji i tekstami notices; `scripts/test-audit-packaged-npm-licenses.mjs` pokrywa brak tekstu licencji, niezgodny zestaw modułów, wersję i pakiet scoped zagnieżdżony w archiwum.

Zebrano deklaracje dla 313 unikalnych par pakiet/wydanie: 23 NuGet oraz 290 npm zapisanych w lockfile. Wszystkie 290 wpisów lockfile zawierają deklarację licencji; 240 par odpowiada paczkom obecnym lokalnie w `node_modules`, a 50 jest nieobecnych. Lockfile oznacza wszystkie 50 nieobecnych jako dev-only; nie znaleziono brakującej lokalnie zależności oznaczonej jako runtime. Wspólna inwentaryzacja klasyfikuje 4 pary jako runtime i 286 jako dev-only. CSV zawiera te stany osobno. Raport nie obejmuje treści całych paczek binarnych, narzędzi CI ani transitive system runtimes.

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

Wszystkie 13 zainstalowanych lokalnie npm z deklaracjami spoza MIT/ISC/Apache-2.0/BSD są w lockfile oznaczone jako dev-only; żadna z czterech par runtime nie ma nietypowej deklaracji. Lista pakietów wymagających dalszego sprawdzenia, jeśli konkretny artefakt redystrybuuje narzędzia buildowe: `chownr@3.0.0`, `isexe@3.1.5` i `4.0.0`, `minimatch@10.2.6`, `minipass@7.1.3`, `sax@1.6.1`, `tar@7.5.22`, `yallist@5.0.0` (BlueOak); `utf8-byte-length@1.0.5` (WTFPL OR MIT); `tslib@2.8.1` (0BSD); `argparse@2.0.1` (Python-2.0); `truncate-utf8-bytes@1.0.2` (WTFPL); `sanitize-filename@1.6.4` (WTFPL OR ISC). Zestaw deklaracji zależności zainstalowanych i ich status dev/runtime jest dostępny w [CSV](dependency-license-inventory.csv).

**Lokalna kontrola deklaracji nietypowych (2026-10-24):** 13 par wersja/pakiet z CSV porównano z manifestami `package.json` w lokalnych `node_modules`; deklaracje są zgodne, a wszystkie są oznaczone jako dev-only. Dwanaście par ma lokalny plik tekstu licencji (w tym `LICENSE.md`, `LICENSE.txt` albo osobne teksty dla wyboru licencji). `truncate-utf8-bytes@1.0.2` deklaruje `WTFPL`, ale w zainstalowanym pakiecie nie ma osobnego pliku licencji ani tekstu w `README.md`/`AUTHORS`; nie traktuję deklaracji SPDX jako zastępstwa brakującego tekstu. Pakiet pozostaje dev-only i nie jest częścią produkcyjnego payloadu według aktualnej allowlisty runtime. Pełna ocena obowiązków redystrybucji narzędzi developerskich nadal wymaga przeglądu; nie jest to opinia prawna.

**Regresja pakowanego `app.asar` (2026-10-25):** nowy audyt przechodzi na lokalnym katalogu Windows i potwierdza zgodność czterech faktycznie spakowanych pakietów npm z lockfile oraz pełnymi tekstami licencji. Pięć testów skryptu PASS, w tym scoped/nested package oraz negatywne przypadki brakującego tekstu, niezgodnego zestawu i wersji. `installer/build-installer.ps1` uruchamia ten audyt po `electron-builder`; test skryptu jest częścią offline bramki. Nie zbudowano nowego instalatora.

### Zawartość instalatora Windows

Inwentarz 290 wpisów npm łączy aplikację z narzędziami deweloperskimi i buildowymi strony. Porównanie `desktop/package-lock.json` z polem `dev` wykazało cztery zależności npm aplikacji oznaczone jako produkcyjne: `lucide-react@0.468.0` (ISC), `react@19.3.1` (MIT), `react-dom@19.3.1` (MIT) i `scheduler@0.28.0` (MIT). Ich kod trafia do zbudowanego UI. `scripts/build-npm-third-party-notices.mjs` odczytuje bieżący lockfile i pliki licencji pakietów, a instalator dołącza pełne teksty do `resources/ThirdPartyNotices/npm-runtime.txt`; budowa kończy się błędem, jeśli nie może potwierdzić wersji lub znaleźć dokładnie jednego pliku licencji dla zależności runtime.

Electron jest zależnością buildową w npm, lecz jego runtime jest osadzany przez electron-builder. W gotowym katalogu Windows zweryfikowano `LICENSE.electron.txt` i `LICENSES.chromium.html`. Manifest `Sentinel.Engine.deps.json` wskazuje siedem zewnętrznych NuGet pakietów runtime; `scripts/build-nuget-third-party-notices.ps1` dołącza ich dokładne wersje, deklaracje, copyright, URL-e licencji i repozytoria do `resources/engine/THIRD-PARTY-LICENSES/nuget-runtime.txt`. Ten sam skrypt kopiuje `ThirdPartyNotices.txt` z instalacji .NET użytej do zbudowania self-contained Engine do `resources/engine/THIRD-PARTY-LICENSES/dotnet/`; build przerywa się, jeśli manifest, metadane nuspec albo notices są niedostępne. Silnik zawiera też osobny tekst licencji PdfPig; nagłówki licencyjne Mozilla Public Suffix List pozostają w danych PSL. Pozostałe pakiety npm/NuGet z lockfile nie są automatycznie traktowane jako redystrybuowane. Raport instalatora nie jest opinią prawną ani przeglądem całej zawartości SDK i runtime.

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

Właściciel nie wskazał jeszcze licencji samego Sentinel AI. Nie dodano pliku `LICENSE`; decyzja produktu i zgodność całego zestawu źródeł/redystrybucji pozostają otwarte. Pozostaje ręczny przegląd deklaracji nietypowych oraz zakresu obowiązków redystrybucyjnych; build teraz dokumentuje i dołącza deklarowane notices pakietów runtime, ale nie potwierdza prawnej zgodności całego artefaktu. Wszystkie 50 npm wpisów nieobecnych lokalnie są w lockfile oznaczone jako dev-only. Trzeba sprawdzić ich redystrybucję tylko wtedy, gdy konkretny artefakt zawiera je mimo tego oznaczenia.
