# Inwentaryzacja licencji zależności .NET

Stan na 2026-10-22. Lista pochodzi z plików `project.assets.json` bieżącego checkoutu dla klienta, serwera, instalatora i testów. Sprawdzono deklaracje licencji w lokalnych metadanych NuGet (`.nuspec`); to inwentaryzacja metadanych pakietów, nie opinia prawna ani pełna ocena warunków redystrybucji.

Zebrano 23 unikalne pary pakiet/wydanie: 10 deklaruje SPDX `MIT`, 12 deklaruje `Apache-2.0`, a `xunit.abstractions 2.0.3` deklaruje starsze `licenseUrl` zamiast SPDX. Wskazana strona licencji XUnit zawiera ogólną licencję Apache-2.0 oraz MIT dla wymienionych importowanych komponentów; ten pakiet wymaga ręcznej kontroli przed redystrybucją. Raport nie obejmuje zależności npm/Electron, treści całych paczek binarnych, narzędzi CI ani transitive system runtimes.

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

Właściciel nie wskazał jeszcze licencji samego Sentinel AI. Nie dodano pliku `LICENSE`; decyzja produktu i zgodność całego zestawu źródeł/redystrybucji pozostają otwarte. Wymagają też osobnej inwentaryzacji licencje zależności JavaScript i dołączonych narzędzi.
