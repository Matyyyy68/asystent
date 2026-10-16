# Dane i zależności podmiotów trzecich

## Public Suffix List

Plik `src/Sentinel.Core/Data/public_suffix_list.dat` pochodzi z projektu Public Suffix List:
https://github.com/publicsuffix/list

Snapshot: commit `389359a9055626c9e574dca4360898ba0a627d01`.
Źródło pobrania: https://raw.githubusercontent.com/publicsuffix/list/389359a9055626c9e574dca4360898ba0a627d01/public_suffix_list.dat

Dane są dostępne na warunkach **Mozilla Public License 2.0**. Oryginalne nagłówki licencyjne pozostawiono w pliku. Tekst licencji: https://mozilla.org/MPL/2.0/ . Dane nie zostały zmodyfikowane. Program używa ich offline, uwzględniając sekcje ICANN i PRIVATE. Snapshot wymaga okresowej, świadomej aktualizacji z przeglądem zmian i ponownymi testami; aplikacja nie aktualizuje go automatycznie.

Pozostałe pakiety NuGet i wersje przechodnie są wymienione w plikach `packages.lock.json`. Przy dystrybucji należy zachować wymagane przez ich licencje informacje.
