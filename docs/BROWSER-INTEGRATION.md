# Integracja przeglądarek Edge i Chrome

Rozszerzenie Manifest V3 jest dostarczane w repozytorium, lecz nie jest opublikowane w sklepach. Użytkownik ładuje je ręcznie jako rozpakowane. Firefox nie jest obsługiwany.

## Przepływ

```text
Edge / Chrome MV3
  ├─ webNavigation.onBeforeNavigate + onCommitted (główna nawigacja HTTP/HTTPS)
  └─ downloads.onCreated (źródło pobrania HTTP/HTTPS po rozpoczęciu pobierania)
      └─ Native Messaging: com.sentinelai.urlcheck
          └─ Sentinel.UrlHost.exe (ramkowane komunikaty UTF-8)
              └─ lokalny Sentinel.Engine i baza reputacji domen
```

Nie ma lokalnego serwera HTTP ani otwartego portu. Przeglądarka uruchamia hosta jako proces bieżącego użytkownika. Host sprawdza dozwolony identyfikator rozszerzenia i zapisuje lokalny marker kontaktu w `%LOCALAPPDATA%\SentinelAI`. Instalator rejestruje hosta dla Edge i Chrome w HKCU.

Rozszerzenie przesyła adres strony lub źródła pobrania wyłącznie do hosta lokalnego. Host porównuje dokładną domenę z lokalną, świeżą listą CERT Polska, jeśli taka baza jest dostępna. Ścieżka, query i fragment URL nie są wysyłane do zewnętrznej usługi ani zapisywane w historii. Nazwa pliku, ścieżka lokalna i referrer pobrania nie są przesyłane przez rozszerzenie. Przy dopasowaniu pobrania rozszerzenie otwiera osobną kartę z ostrzeżeniem. Przycisk „Zatrzymaj pobieranie” anuluje przypisany transfer po kliknięciu; jeśli plik zdążył się pobrać, użytkownik usuwa go ręcznie. Rozszerzenie nie analizuje treści pobranego pliku. Nowa zgoda `downloads` pozwala przeglądarce przekazywać metadane pobrania do rozszerzenia; wysłanie adresu do hosta nadal wymaga opt-in `integrationEnabled`. Rozszerzenie można wyłączyć w ustawieniach Sentinel AI; diagnostyka pokazuje stan rejestracji i ostatni kontakt.

## Włączenie rozszerzenia

Otwórz `edge://extensions` albo `chrome://extensions`, włącz **Tryb dewelopera**, wybierz **Załaduj rozpakowane** i wskaż katalog rozszerzenia w repozytorium albo w zainstalowanym pakiecie. W diagnostyce Sentinel AI sprawdź stan hosta i ostatni kontakt.

## Granice ochrony

- Zdarzenie `onBeforeNavigate` rozpoczyna się w toku nawigacji. Rozszerzenie może wyświetlić ostrzeżenie po sprawdzeniu domeny, lecz nie zapewnia synchronicznego blokowania przed załadowaniem strony.
- Dopasowanie do aktywnej listy CERT jest dokładnym dopasowaniem domeny. Lista musi mieć mniej niż 48 godzin; pobieranie ma limit rozmiaru i nie podąża za przekierowaniami.
- Brak dopasowania nie potwierdza bezpieczeństwa. Heurystyka ani dopasowanie listy nie stanowią gwarancji wykrycia lub blokowania zagrożeń.
- Zdarzenie `downloads.onCreated` pojawia się, gdy pobieranie już się rozpoczyna; ostrzeżenie może więc pojawić się po rozpoczęciu transferu. Użytkownik może z niego ręcznie anulować transfer; anulowanie może się nie udać, jeśli pobieranie zdążyło się zakończyć. Rozszerzenie nie usuwa ukończonych plików i nie analizuje ich treści. Osobny, opt-in monitor Downloads w Sentinel sprawdza nowe pliki lokalnie według własnego planu.
- Rozszerzenie nie analizuje pełnego ruchu, adresów IP ani iframe'ów i nie obsługuje Firefoksa.

## Testy i budowa

Aktualny E2E używa testowego hosta Native Messaging z produkcyjnym `UrlRequestProcessor`. Skrypt `scripts/test-chrome-extension-e2e.cjs` wymaga jawnej zgody w CLI, ponieważ uruchamia przeglądarkę i tymczasowo zapisuje własną rejestrację Native Messaging w HKCU. Dla lokalnego testu użyj `--allow-visible-browser`; w izolowanym CI używany jest `--allow-headless-browser`. Standardowy przebieg nie zapisuje plików pobierania. Dodatkowy przełącznik `--allow-local-download-fixtures` zezwala na zapis małych odpowiedzi wyłącznie w tymczasowym profilu; CI uruchamia je na runnerze i usuwa cały profil po teście. Test tworzy osobny profil, kopię manifestu ograniczoną do `*.test`, blokuje zewnętrzny DNS, sprawdza `status`, `analyze`, ostrzeżenie z redakcją, przekierowanie HTTP 302, pominięcie iframe, `history.pushState`, izolację dwóch kart oraz ostrzeżenia dla pobrań inicjowanych nawigacją i linkiem. E2E nie analizuje treści pobranego pliku ani nie usuwa ukończonego transferu. Testy nie obejmują pełnej instalacji/aktualizacji/deinstalacji ani hosta produkcyjnego z profilem i historią.

`node scripts/check-product.cjs` sprawdza Manifest V3, identyfikator rozszerzenia, uprawnienia i składnię JavaScript. Testy .NET znajdują się w `tests/Sentinel.Tests`; `node scripts/test-engine.cjs` sprawdza protokół i przepływ do lokalnej bazy. `./scripts/build-user.ps1 -Installer` buduje pakiet Windows. Pełny test instalacji i interakcji z kartami wymaga interaktywnego Windows z Edge lub Chrome.

Oficjalny Chrome od wersji 137 ignoruje przełącznik `--load-extension`; do testu rozpakowanego dodatku użyj osobnego profilu, trybu dewelopera i przycisku **Załaduj rozpakowane** w `chrome://extensions` ([informacja o wydaniu Chrome 137](https://support.google.com/chrome/a/answer/7679408?hl=en)). W teście bieżącego Chrome 155 przełącznik rzeczywiście nie załadował rozszerzenia, więc sam wynik nawigacji do lokalnego fixture nie jest E2E rozszerzenia.

Weryfikacja E2E 2026-10-20: Chrome 155.0.8059.85 i Edge 155.0.4283.62 przeszły test na osobnych profilach tymczasowych. Test ładował rozszerzenie przez CDP, kierował domenę `paypal.com.evil.test` do lokalnego fixture, uruchamiał opublikowany host Native Messaging i potwierdzał treść ostrzeżenia. Proxy odrzucało ruch poza loopback, a `LOCALAPPDATA` wskazywało katalog testowy; po teście usunięto profile, manifest i tymczasowy wpis rejestru. Nie jest to test ręcznej instalacji ani dowód blokowania nawigacji.

**Chrome E2E 2026-10-23:** w odizolowanym profilu Chrome 155 załadowano kopię rozszerzenia przez CDP `Extensions.loadUnpacked`. `host_permissions` kopii ograniczono do `*.test`; reguła Chrome kierowała te nazwy na loopback i odrzucała rozwiązywanie wszystkich pozostałych nazw. Lokalny fixture przyjął nawigację testową, a tymczasowy mock Native Messaging odebrał `status` i `analyze`. CDP potwierdził przekierowanie do `warning.html`, nagłówek „Sprawdź ten adres przed kontynuowaniem” i kontrolowany opis wskaźnika. Test zakończył się kodem 0; profil, mock, procesy i wpis HKCU usunięto. To potwierdza przepływ rozszerzenie → Native Messaging → ekran ostrzeżenia przy mockowanej analizie; nie weryfikuje analizy przez rzeczywisty Sentinel Engine, instalatora GUI ani blokowania przed rozpoczęciem nawigacji. Wcześniejsze nieudane podejścia 2026-10-23 wynikały z błędnych argumentów startowych, a potem z ograniczeń CUA i ignorowania `--load-extension` w Chrome 155.

Lokalne odtworzenie na Windows wymaga świadomego uruchomienia `node scripts/test-chrome-extension-e2e.cjs chrome --allow-visible-browser` albo wariantu `edge`. Użyj `--allow-local-download-fixtures`, jeśli w profilu testowym mają powstać małe pliki pobrania. Wymaga wybranej przeglądarki, Node.js 24 i .NET SDK 10. CI uruchamia oba warianty z `--allow-headless-browser --allow-local-download-fixtures` na jednorazowym Windows runnerze; nie otwiera przeglądarki na komputerze dewelopera. Test odmawia nadpisania istniejącej rejestracji Native Messaging, używa osobnego profilu i krótkotrwałego klucza HKCU, ogranicza host permissions kopii rozszerzenia do `*.test`, mapuje je na loopback, blokuje zewnętrzny DNS i sprząta po sobie. Testowy host używa produkcyjnego `UrlRequestProcessor`, ale nie inicjalizuje profilu Sentinel, historii zdarzeń ani powiadomień; nie jest to pełna instalacja hosta ani rozszerzenia.
