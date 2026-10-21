# Konfiguracja klienta Sentinel AI Enterprise

Ten poradnik opisuje parowanie aktywnego klienta Windows z wdrożonym serwerem Sentinel AI. Serwer Enterprise jest osobnym projektem i nie znajduje się w instalatorze klienta. Wariant klienta Enterprise włącza się podczas parowania w aplikacji.

## Wymagania

- Windows 10/11 x64 i zainstalowany klient Sentinel AI.
- Dostępny serwer Sentinel AI API pod adresem bazowym HTTPS. Certyfikat serwera musi być zaufany przez Windows; klient nie pomija walidacji TLS. Adres podawany w aplikacji nie może zawierać ścieżki API, zapytania, fragmentu ani danych logowania.
- Jednorazowy kod zaproszenia utworzony przez administratora serwera dla istniejącej grupy.
- Połączenie z serwerem podczas parowania i synchronizacji. Lokalna analiza reguł nadal działa bez serwera.

Administrator serwera może skorzystać z procedury instalacji i konfiguracji w [README serwera](../server/README.md). Przy tworzeniu zaproszenia powinien przekazać użytkownikowi adres bazowy HTTPS i jednorazowy kod innym, bezpiecznym kanałem. Nie umieszczaj kodu zaproszenia w zgłoszeniu publicznym ani w wierszu polecenia.

## Instalacja klienta

Pobierz [opublikowany instalator Sentinel AI v0.15.38](https://github.com/Matyyyy68/asystent/releases/download/v0.15.38/Sentinel.AI.Setup.0.15.38.exe) i porównaj jego SHA-256 z [plikiem kontrolnym](https://github.com/Matyyyy68/asystent/releases/download/v0.15.38/Sentinel.AI.Setup.0.15.38.exe.sha256). Uruchom instalator na koncie użytkownika; standardowa ścieżka to `%LOCALAPPDATA%\Programs\Sentinel AI`. Serwer Enterprise nie jest częścią tego pakietu. Opublikowany pakiet v0.15.38 poprzedza zmianę automatycznej rotacji z bieżącego `main`; nowa rotacja będzie dostępna po przygotowaniu kolejnego wydania.

## Parowanie urządzenia

1. Uruchom Sentinel AI i otwórz **Ustawienia → Połączenie z serwerem Enterprise**.
2. Wpisz bazowy adres HTTPS serwera i jednorazowy kod zaproszenia.
3. Przeczytaj zgodę na ekranie i zaznacz ją tylko wtedy, gdy organizacja ma wysyłać metadane wykryć oraz dostarczać ustawienia polityki.
4. Wybierz **Połącz urządzenie**. Kod zaproszenia jest używany do rejestracji; serwer otrzymuje też nazwę komputera i wersję klienta. Poświadczenie urządzenia klient zapisuje w chronionym magazynie Windows DPAPI.
5. Jeśli zaproszenie wymaga zatwierdzenia, administrator musi zaakceptować urządzenie w panelu serwera. Do tego czasu synchronizacja może być odrzucana przez API.

Po udanym parowaniu ustawienia pokazują serwer, stan zgody, liczbę oczekujących metadanych i ostatni stan synchronizacji. Klient pobiera wspieraną lokalną politykę i synchronizuje metadane w cyklu pracy silnika. Dla błędu sieci kolejka pozostaje lokalnie i jest ponawiana po odzyskaniu serwera.

## Zgoda, dane i rotacja poświadczenia

Przy aktywnej zgodzie klient wysyła do serwera wyłącznie identyfikator zdarzenia, czas, kategorię, poziom ryzyka, kod reguły, wersję schematu, bezpieczną wersję reguł i allowlistowane źródło. Treść analizowanej wiadomości, pełny URL, zawartość plików, nazwy aplikacji i lokalne wyjaśnienia nie należą do payloadu zdarzenia. Samo parowanie bez aktywnej zgody nie wznowi synchronizacji.

Wybranie **Wstrzymaj Enterprise** zatrzymuje heartbeat, pobieranie polityki i wysyłanie zdarzeń oraz usuwa oczekujące metadane z kolejki Enterprise. Lokalna historia pozostaje na komputerze. Ponowne włączenie komunikacji wymaga odrębnego potwierdzenia w ustawieniach.

Poświadczenie jest automatycznie odnawiane po 90 dniach przy następnym cyklu synchronizacji, jeśli zgoda jest aktywna i serwer dostępny. Termin jest widoczny w ustawieniach. Można też użyć przycisku **Odnów poświadczenie**; wymagane jest potwierdzenie operacji. Unieważnienie urządzenia wykonuje administrator serwera.

## Rozwiązywanie problemów

- **Nie można połączyć się z serwerem:** sprawdź adres bazowy, dostępność API i zaufanie certyfikatu HTTPS w Windows. Nie instaluj nieznanego certyfikatu głównego, aby ominąć błąd.
- **Urządzenie oczekuje na zatwierdzenie:** poproś administratora o sprawdzenie listy urządzeń oczekujących i zatwierdzenie właściwego urządzenia.
- **Synchronizacja nie powiodła się:** wpisy pozostają w lokalnej kolejce przy błędzie łączności. Sprawdź stan serwera i wróć do aplikacji po przywróceniu połączenia.
- **Brak poświadczenia:** urządzenie mogło zostać usunięte z magazynu DPAPI albo unieważnione po stronie serwera; administrator powinien wystawić nowe zaproszenie.

## Ograniczenia wdrożenia

Projekt nie dostarcza publicznego serwera Enterprise ani zaufanego certyfikatu dla wdrożenia. Konfiguracja TLS dla dostępu spoza loopback wymaga przygotowania przez administratora; instalator serwera nie tworzy certyfikatu ani reguł zapory. Polityka agenta wspiera obecnie tryb lokalny oraz ograniczony interwał. Analiza treści po stronie serwera nie jest częścią zwykłej synchronizacji metadanych i wymaga osobnej, jawnej konfiguracji serwera oraz zgody.

Pełna instalacja i odinstalowanie klienta przez interfejs graficzny nie zostały jeszcze zweryfikowane na czystym Windows. Lokalny build i autotest instalatora nie zastępują takiego testu.
