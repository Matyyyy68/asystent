# Znane ograniczenia — 2026-10-21

Sentinel AI pozostaje prerelease i nie zastępuje Microsoft Defender ani innego produktu ochronnego. Brak ostrzeżenia nie potwierdza bezpieczeństwa; reguły i pomiary testowe nie dowodzą skuteczności na rzeczywistych atakach.

## Wydanie i instalacja

- Publicznym wydaniem pozostaje [v0.15.38](https://github.com/Matyyyy68/asystent/releases/tag/v0.15.38). Bieżący `main` zawiera późniejsze poprawki, w tym automatyczną rotację poświadczeń Enterprise po 90 dniach. Zmiany te nie trafiły jeszcze do opublikowanego instalatora; lokalny build bieżącego kodu nie jest publicznym wydaniem.
- Pełny build i self-test instalatora przechodzą, ale pełnego cyklu GUI, rejestracji Native Messaging, skrótów, autostartu oraz install/update/uninstall nie zweryfikowano na czystym Windows. Kreator v0.15.38 uruchomił się, a izolowaną ścieżkę dało się ustawić; sterowanie przerwało się przed kliknięciem instalacji, więc rzeczywistej instalacji nie wykonano.
- Instalator nie jest podpisany Authenticode, nie ma podpisanego manifestu aktualizacji ani automatycznego updatera. Nie należy traktować lokalnego SHA-256 jako podpisu wydawcy.
- Rozszerzenie Chrome/Edge wymaga ręcznego załadowania. Izolowane testy na fixture `.test` przeszły, ale ręcznego przepływu w zwykłym profilu użytkownika nie zweryfikowano. Ostrzeżenie może pojawić się po rozpoczęciu ładowania strony i nie blokuje nawigacji.

## Analiza i źródła zdarzeń

- Ręczna analiza URL/tekstu używa lokalnych reguł i ograniczonych heurystyk. Korpus regresyjny jest mały i syntetyczny; nie jest reprezentatywnym zbiorem phishingu ani niezależnym pomiarem false positive/negative. Confidence pozostaje puste bez kalibracji.
- Lista CERT Polska wymaga ręcznego pobrania, wygasa po 48 godzinach i dotyczy domen. Brak reputacji IP i pełnych adresów URL malware; URLhaus nie jest podłączony.
- Cache DNS Windows jest próbkowany, a nie odczytywany jako strumień zapytań. DoH, VPN, zapytania po IP oraz wpisy usunięte między próbkami mogą zostać pominięte. Kanał `Microsoft-Windows-DNS-Client/Operational` na maszynie audytu był wyłączony i nie został włączony.
- Procesy są próbkowane lokalnie co około sekundę; opt-in monitoring TCP/UDP również odpyta tabele Windows co około sekundę. Krótkie procesy lub połączenia mogą zakończyć się między próbkami. Tabele są ograniczone do 10 000 procesów, 800 wpisów TCP i 200 UDP; niepełne próbki wstrzymują niepewne alerty. UDP pokazuje lokalny endpoint, nie potwierdza datagramu ani nie ujawnia zdalnego celu. Nie ma gwarantowanego event stream: próby WMI i sesji ETW wymagały dostępu systemowego, którego konto audytu nie miało.
- Nie ma WFP, sterownika jądra, filtrowania ani automatycznego blokowania ruchu. Sentinel nie przechwytuje payloadu HTTPS ani nie instaluje certyfikatu do inspekcji TLS.
- Monitoring Downloads jest opt-in i obejmuje nowe pliki bezpośrednio w tym folderze do 256 MiB; nie skanuje podkatalogów ani plików sprzed włączenia. Porównanie SHA-256 działa lokalnie z listą importowaną przez użytkownika. Nazwy/ścieżki, rozmiary i czasy plików są zapisywane lokalnie bez szyfrowania. Brak dopasowania nie oznacza bezpieczeństwa.
- Ręczny skan pliku liczy SHA-256 i sprawdza status Authenticode. Opcjonalny MalwareBazaar lookup wysyła wyłącznie hash po osobnym kliknięciu i wymaga klucza API; nie został sprawdzony z rzeczywistym kluczem. Warunki komercyjnego użycia zależą od dostawcy.
- Ollama wymaga osobnej instalacji, lokalnego modelu i jawnego włączenia; nie zostało zweryfikowane na rzeczywistym modelu na maszynie audytu. Baza wiedzy używa FTS5, nie embeddingów ani wyszukiwania semantycznego; PDF bez warstwy tekstowej wymagałby OCR, którego nie ma.

## Enterprise, dane i prywatność

- Serwer Enterprise jest osobnym projektem. Wdrożenie poza loopback wymaga HTTPS z certyfikatem zaufanym przez Windows; repozytorium nie dostarcza publicznego serwera ani zaufanego certyfikatu. Instalator serwera nie konfiguruje TLS ani zapory.
- Klient przesyła metadane zdarzeń wyłącznie po jawnej zgodzie. Nie obejmują one treści, pełnych URL-i, zawartości plików, nazw aplikacji ani lokalnych wyjaśnień. Podczas rejestracji serwer otrzymuje kod zaproszenia, nazwę komputera i wersję klienta. Szczegóły opisuje [konfiguracja klienta Enterprise](ENTERPRISE-CLIENT-SETUP.md).
- Polityka klienta Enterprise obsługuje obecnie tryb lokalny i ograniczony interwał. Serwerowa analiza treści oraz rozszerzone statusy zgodności pozostają poza zwykłym przepływem agenta. Urządzenie oczekujące na akceptację wymaga działania administratora.
- Token Enterprise jest chroniony Windows DPAPI; nowszy kod `main` odnawia go automatycznie po 90 dniach przy aktywnej zgodzie i synchronizacji. Ta funkcja nie znajduje się jeszcze w publicznym instalatorze v0.15.38.
- Bazy SQLite nie są szyfrowane. Historia nie zapisuje surowej treści ani pełnych URL-i, ale lokalne metadane, ustawienia i ścieżki monitorowanych plików mogą być dostępne dla konta użytkownika.
- W repozytorium nie ma pliku LICENSE. Właściciel musi wskazać licencję źródeł i warunki redystrybucji; nie zostały ustalone w jego imieniu.

## Ostatnia walidacja źródła

Pełne `scripts/build-user.ps1 -Installer` dla bieżącego kodu przeszło 232/232 testów .NET, testy desktop 10/10, Engine IPC, procesy, Windows DNS/TCP/UDP, produkcyjny build UI, `npm audit` bez podatności oraz self-test instalatora. Self-test obejmuje odrzucenie zmienionego payloadu, preflight braku miejsca i zachowanie poprzedniej instalacji po wstrzykniętym błędzie stagingu; nie używa fizycznie pełnego woluminu. Lokalny, nieopublikowany instalator v0.15.38 ma SHA-256 `E48855782077DD10649991643E1A262E7DB0A97B5B2E25A74FC77CF2861C4AAC`. Test self-test nie zastępuje pełnej interakcji GUI ani zaufanego podpisu wydawcy.
# Process image inspection

Process start monitoring is snapshot-based and may miss processes shorter than the polling interval. Image paths can be unavailable due to Windows access restrictions. Background SHA-256 and Authenticode inspection is limited to 256 MiB and a queue of 33 (including one in-flight item); excess work is marked `QueueFull` and pending work is retried after engine restart. Local hash comparison only reflects a user-imported feed. An absent match is not a clean verdict, and an unsigned file is not by itself malware. Paths and hashes are stored in local history and are omitted from JSON/CSV exports and Enterprise payloads. WMI/ETW event-stream collection is not implemented because the tested account lacked access.
