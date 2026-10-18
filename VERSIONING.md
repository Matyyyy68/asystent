# Wersjonowanie Sentinel AI

Wersja produktu jest utrzymywana w `eng/ProductVersion.props`. Obejmuje aktywne projekty .NET, klienta Windows (Electron), host Native Messaging i instalator. Rozszerzenie przeglądarki ma osobną wersję techniczną w `browser-extension/manifest.json`.

Przy wydaniu zwiększ `VersionPrefix` według Semantic Versioning (`MAJOR.MINOR.PATCH`). Nie wpisuj numeru produktu niezależnie w projektach ani skryptach. Zależności NuGet i npm mają własne wersje.

Walidacja wydania na Windows:

```powershell
dotnet build Sentinel.sln -c Release
dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release
node scripts/check-product.cjs
node scripts/test-engine.cjs
./scripts/build-user.ps1 -Installer
```

Pakiet instalacyjny trafia do `artifacts/desktop`. Skrypt sprawdza wersję, uruchamia testy i buduje renderer, host, silnik oraz instalator NSIS. NSIS nadaje sandboxowi Chromium uprawnienia odczytu i wykonania w katalogu programu, bez rozszerzania ich na dane użytkownika. Instalator nie jest podpisany cyfrowo; przed publiczną dystrybucją wymagany jest proces podpisywania i walidacja instalacji na docelowych systemach Windows.
