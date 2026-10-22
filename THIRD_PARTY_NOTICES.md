# Dane i zależności podmiotów trzecich

## Public Suffix List

Plik `src/Sentinel.Core/Data/public_suffix_list.dat` pochodzi z projektu Public Suffix List:
https://github.com/publicsuffix/list

Snapshot: commit `389359a9055626c9e574dca4360898ba0a627d01`.
Źródło pobrania: https://raw.githubusercontent.com/publicsuffix/list/389359a9055626c9e574dca4360898ba0a627d01/public_suffix_list.dat

Dane są dostępne na warunkach **Mozilla Public License 2.0**. Oryginalne nagłówki licencyjne pozostawiono w pliku. Tekst licencji: https://mozilla.org/MPL/2.0/ . Dane nie zostały zmodyfikowane. Program używa ich offline, uwzględniając sekcje ICANN i PRIVATE. Snapshot wymaga okresowej, świadomej aktualizacji z przeglądem zmian i ponownymi testami; aplikacja nie aktualizuje go automatycznie.

Pozostałe pakiety NuGet i wersje przechodnie są wymienione w plikach `packages.lock.json`. Przy dystrybucji należy zachować wymagane przez ich licencje informacje.

## Pakiet aplikacji Windows

Pakiet Windows zawiera pliki `LICENSE.electron.txt` dla Electron i `LICENSES.chromium.html` dla Chromium, pochodzące z dystrybucji Electron. Silnik .NET dołącza `ThirdPartyNotices.txt` z SDK .NET użytego do publikacji oraz zestaw deklaracji dla siedmiu pakietów runtime NuGet w `resources/engine/THIRD-PARTY-LICENSES/`. Licencja PdfPig znajduje się w `resources/engine/THIRD-PARTY-LICENSES/PdfPig-LICENSE.txt`; plik źródłowy PSL zachowuje nagłówki licencyjne upstream MPL-2.0.

UI aplikacji desktopowej dołącza produkcyjne zależności npm: `lucide-react`, `react`, `react-dom` i `scheduler`. Build instalatora generuje `resources/ThirdPartyNotices/npm-runtime.txt` na podstawie dokładnych wersji z lockfile i tekstów licencji zainstalowanych pakietów. Pakowanie kończy się błędem, gdy wersja zależności nie zgadza się z lockfile albo jej plik licencji jest brakujący lub niejednoznaczny. Zakres i nierozstrzygnięte kwestie opisuje [audyt licencji zależności](docs/DEPENDENCY-LICENSE-AUDIT.md); te informacje nie zastępują decyzji właściciela o licencji Sentinel AI ani przeglądu prawnego.
