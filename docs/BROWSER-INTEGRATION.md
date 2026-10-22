# Integracja przeglądarek Edge i Chrome

Rozszerzenie Manifest V3 jest dostarczane w repozytorium, lecz nie jest opublikowane w sklepach. Użytkownik ładuje je ręcznie jako rozpakowane. Firefox nie jest obsługiwany.

## Przepływ

```text
Edge / Chrome MV3
  └─ webNavigation.onBeforeNavigate (główna nawigacja HTTP/HTTPS)
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

`node scripts/check-product.cjs` sprawdza Manifest V3, identyfikator rozszerzenia, uprawnienia i składnię JavaScript. Testy .NET znajdują się w `tests/Sentinel.Tests`; `node scripts/test-engine.cjs` sprawdza protokół i przepływ do lokalnej bazy. `./scripts/build-user.ps1 -Installer` buduje pakiet Windows. Pełny test instalacji i interakcji z kartami wymaga interaktywnego Windows z Edge lub Chrome.

Oficjalny Chrome od wersji 137 ignoruje przełącznik `--load-extension`; do testu rozpakowanego dodatku użyj osobnego profilu, trybu dewelopera i przycisku **Załaduj rozpakowane** w `chrome://extensions` ([informacja o wydaniu Chrome 137](https://support.google.com/chrome/a/answer/7679408?hl=en)). W teście bieżącego Chrome 155 przełącznik rzeczywiście nie załadował rozszerzenia, więc sam wynik nawigacji do lokalnego fixture nie jest E2E rozszerzenia.

Weryfikacja E2E 2026-10-20: Chrome 155.0.8059.85 i Edge 155.0.4283.62 przeszły test na osobnych profilach tymczasowych. Test ładował rozszerzenie przez CDP, kierował domenę `paypal.com.evil.test` do lokalnego fixture, uruchamiał opublikowany host Native Messaging i potwierdzał treść ostrzeżenia. Proxy odrzucało ruch poza loopback, a `LOCALAPPDATA` wskazywało katalog testowy; po teście usunięto profile, manifest i tymczasowy wpis rejestru. Nie jest to test ręcznej instalacji ani dowód blokowania nawigacji.
