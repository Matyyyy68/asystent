# Integracja przeglądarek Edge i Chrome

Rozszerzenie Manifest V3 jest dostarczane w repozytorium, lecz nie jest opublikowane w sklepach. Użytkownik ładuje je ręcznie jako rozpakowane. Firefox nie jest obsługiwany.

## Przepływ

```text
Edge / Chrome MV3
  └─ webNavigation.onBeforeNavigate + onCommitted (główna nawigacja HTTP/HTTPS)
      └─ Native Messaging: com.sentinelai.urlcheck
          └─ Sentinel.UrlHost.exe (ramkowane komunikaty UTF-8)
              └─ lokalny Sentinel.Engine i baza reputacji domen
```

Nie ma lokalnego serwera HTTP ani otwartego portu. Przeglądarka uruchamia hosta jako proces bieżącego użytkownika. Host sprawdza dozwolony identyfikator rozszerzenia i zapisuje lokalny marker kontaktu w `%LOCALAPPDATA%\SentinelAI`. Instalator rejestruje hosta dla Edge i Chrome w HKCU.

Rozszerzenie przesyła adres odwiedzanej strony wyłącznie do hosta lokalnego. Host porównuje dokładną domenę z lokalną, świeżą listą CERT Polska, jeśli taka baza jest dostępna. Ścieżka, query i fragment URL nie są wysyłane do zewnętrznej usługi ani zapisywane w historii. Historia zawiera kategorię, ryzyko, sygnały i zalecenia. Rozszerzenie można wyłączyć w ustawieniach Sentinel AI; diagnostyka pokazuje stan rejestracji i ostatni kontakt.

## Włączenie rozszerzenia

Otwórz `edge://extensions` albo `chrome://extensions`, włącz **Tryb dewelopera**, wybierz **Załaduj rozpakowane** i wskaż katalog rozszerzenia w repozytorium albo w zainstalowanym pakiecie. W diagnostyce Sentinel AI sprawdź stan hosta i ostatni kontakt.

## Granice ochrony

- Zdarzenie `onBeforeNavigate` rozpoczyna się w toku nawigacji. Rozszerzenie może wyświetlić ostrzeżenie po sprawdzeniu domeny, lecz nie zapewnia synchronicznego blokowania przed załadowaniem strony.
- Dopasowanie do aktywnej listy CERT jest dokładnym dopasowaniem domeny. Lista musi mieć mniej niż 48 godzin; pobieranie ma limit rozmiaru i nie podąża za przekierowaniami.
- Brak dopasowania nie potwierdza bezpieczeństwa. Heurystyka ani dopasowanie listy nie stanowią gwarancji wykrycia lub blokowania zagrożeń.
- Nie analizujemy pełnego ruchu, adresów IP, iframe'ów ani pobranych plików. Nie obsługujemy Firefoksa.

## Testy i budowa

Aktualny E2E używa testowego hosta Native Messaging z produkcyjnym `UrlRequestProcessor`. Skrypt `scripts/test-chrome-extension-e2e.cjs` przyjmuje `chrome` (domyślnie) lub `edge`; w obu wariantach tworzy osobny profil, kopię manifestu ograniczoną do `*.test`, blokuje zewnętrzne DNS, sprawdza `status`, `analyze`, ostrzeżenie z redakcją, przekierowanie HTTP 302 do podejrzanej domeny, pominięcie iframe, `history.pushState` oraz dwa jednoczesne ostrzeżenia, gdzie zamknięcie jednej karty nie wpływa na drugą. Po zakończeniu usuwa profil i tylko własny wpis HKCU. Ostatni wynik 2026-10-24: Chrome 155.0.8059.86 PASS oraz Edge 155.0.4283.62 PASS. To nie testuje pełnej instalacji/aktualizacji/deinstalacji ani hosta produkcyjnego z profilem i historią; pobieranie nie jest objęte E2E.

`node scripts/check-product.cjs` sprawdza Manifest V3, identyfikator rozszerzenia, uprawnienia i składnię JavaScript. Testy .NET znajdują się w `tests/Sentinel.Tests`; `node scripts/test-engine.cjs` sprawdza protokół i przepływ do lokalnej bazy. `./scripts/build-user.ps1 -Installer` buduje pakiet Windows. Pełny test instalacji i interakcji z kartami wymaga interaktywnego Windows z Edge lub Chrome.

Oficjalny Chrome od wersji 137 ignoruje przełącznik `--load-extension`; do testu rozpakowanego dodatku użyj osobnego profilu, trybu dewelopera i przycisku **Załaduj rozpakowane** w `chrome://extensions` ([informacja o wydaniu Chrome 137](https://support.google.com/chrome/a/answer/7679408?hl=en)). W teście bieżącego Chrome 155 przełącznik rzeczywiście nie załadował rozszerzenia, więc sam wynik nawigacji do lokalnego fixture nie jest E2E rozszerzenia.

Weryfikacja E2E 2026-10-20: Chrome 155.0.8059.85 i Edge 155.0.4283.62 przeszły test na osobnych profilach tymczasowych. Test ładował rozszerzenie przez CDP, kierował domenę `paypal.com.evil.test` do lokalnego fixture, uruchamiał opublikowany host Native Messaging i potwierdzał treść ostrzeżenia. Proxy odrzucało ruch poza loopback, a `LOCALAPPDATA` wskazywało katalog testowy; po teście usunięto profile, manifest i tymczasowy wpis rejestru. Nie jest to test ręcznej instalacji ani dowód blokowania nawigacji.

**Chrome E2E 2026-10-23:** w odizolowanym profilu Chrome 155 załadowano kopię rozszerzenia przez CDP `Extensions.loadUnpacked`. `host_permissions` kopii ograniczono do `*.test`; reguła Chrome kierowała te nazwy na loopback i odrzucała rozwiązywanie wszystkich pozostałych nazw. Lokalny fixture przyjął nawigację testową, a tymczasowy mock Native Messaging odebrał `status` i `analyze`. CDP potwierdził przekierowanie do `warning.html`, nagłówek „Sprawdź ten adres przed kontynuowaniem” i kontrolowany opis wskaźnika. Test zakończył się kodem 0; profil, mock, procesy i wpis HKCU usunięto. To potwierdza przepływ rozszerzenie → Native Messaging → ekran ostrzeżenia przy mockowanej analizie; nie weryfikuje analizy przez rzeczywisty Sentinel Engine, instalatora GUI ani blokowania przed rozpoczęciem nawigacji. Wcześniejsze nieudane podejścia 2026-10-23 wynikały z błędnych argumentów startowych, a potem z ograniczeń CUA i ignorowania `--load-extension` w Chrome 155.

Odtworzenie na Windows: `node scripts/test-chrome-extension-e2e.cjs chrome` albo `node scripts/test-chrome-extension-e2e.cjs edge` (bez argumentu wybiera Chrome). Wymaga wybranej przeglądarki, Node.js 24 i .NET SDK 10. Test odmawia nadpisania istniejącej rejestracji Native Messaging tej przeglądarki, używa osobnego profilu i krótkotrwałego klucza HKCU, ogranicza host permissions kopii rozszerzenia do `*.test`, mapuje je na loopback, blokuje zewnętrzny DNS i sprząta po sobie. Testowy host używa produkcyjnego `UrlRequestProcessor`, ale nie inicjalizuje profilu Sentinel, historii zdarzeń ani powiadomień; nie jest to pełna instalacja hosta ani rozszerzenia.
