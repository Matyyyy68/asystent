# Wersjonowanie Sentinel AI

Wszystkie aplikacje, które są budowane i publikowane z tego repozytorium, używają jednej wersji produktu z `eng/ProductVersion.props`. Obejmuje to klienta Windows, API Enterprise i pliki assembly powiązanych modułów. Installer pobiera tę samą wartość podczas pakowania; nazwa EXE, metadane PE, wpis Windows Uninstall i widoczna wersja klienta muszą się zgadzać.

Przy wydaniu aplikacji zwiększ `VersionPrefix` według Semantic Versioning (`MAJOR.MINOR.PATCH`). Nie wpisuj numeru niezależnie w plikach projektów ani w skryptach. Zależności NuGet mają własne wersje i nadal są przypinane osobno w projektach oraz `packages.lock.json`.

Walidacja wydania:

```bash
dotnet build Sentinel.sln -c Release --no-restore
dotnet test Sentinel.sln -c Release --no-build --no-restore
bash scripts/build-installer-cloud.sh
```

Skrypt budowania odczytuje wersję ze wspólnego pliku i weryfikuje architekturę, sumę EXE, manifest payloadu, runtime oraz licencje. Nie publikuj aplikacji ani instalatora z niezgodnymi numerami wersji.
