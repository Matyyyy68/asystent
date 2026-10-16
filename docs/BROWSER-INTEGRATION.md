# Integracja przeglądarek Edge i Chrome

Status: pierwszy etap dostarczony w 0.13.0. Rozszerzenie nie zostało opublikowane w sklepach Edge Add-ons ani Chrome Web Store; użytkownik włącza je ręcznie jako rozpakowane. Firefox nie jest obsługiwany.

## Przepływ

```text
Edge / Chrome MV3
  └─ webNavigation.onBeforeNavigate (tylko główna nawigacja HTTP/HTTPS)
      └─ Native Messaging: com.sentinelai.urlcheck
          └─ Sentinel.UrlHost.exe (stdin/stdout, ramki UTF-8 z 4-bajtową długością LE)
              └─ Sentinel.Core: UrlAnalyzer + ThreatAnalysisEngine + offline Public Suffix List
```

Nie ma lokalnego serwera HTTP ani otwartego portu. Chrome i Edge uruchamiają hosta jako proces bieżącego użytkownika, a manifest hosta dopuszcza wyłącznie identyfikator tego rozszerzenia. Instalator tworzy manifest Native Messaging i wpisy HKCU obu przeglądarek; deinstalator je usuwa.

Rozszerzenie wysyła pełny adres tylko do hosta na tym samym komputerze. Analizator wykorzystuje domenę i cechy URL, ale nie odpytuje DNS i nie otwiera celu. Ścieżka, query, fragment, pełna domena i adres URL nie trafiają do historii. Historia zapisuje wyłącznie kategorię, poziom ryzyka, stałe opisy sygnałów i zalecenia. Browser event używa `LocalStore.AddLocalOnlyAsync`, więc nie trafia do kolejki Enterprise. Gdy Sentinel AI jest uruchomiony, host powiadamia aplikację przez lokalny named pipe ograniczony do bieżącego użytkownika; aplikacja odświeża historię, a przy wysokim ryzyku może pokazać balonik zasobnika. Gdy aplikacja jest zamknięta, rozszerzenie nadal wyświetla ostrzeżenie i host zapisuje historię, jeśli wcześniej skonfigurowano katalog danych.

Marker `browser-integration.json` w `%LOCALAPPDATA%\SentinelAI` zawiera wyłącznie czas ostatniego kontaktu z rozszerzeniem. Główny ekran odróżnia oczekiwanie na połączenie, ostatni kontakt i niedawny kontakt; sam fakt zainstalowania hosta nie jest przedstawiany jako aktywna integracja.

## Włączenie rozszerzenia

Po instalacji otwórz `edge://extensions` albo `chrome://extensions`, włącz **Tryb dewelopera**, wybierz **Załaduj rozpakowane** i wskaż `%LOCALAPPDATA%\Programs\Sentinel AI\app\BrowserExtension`. W wyskakującym panelu rozszerzenia status potwierdza połączenie z hostem. Ta ręczna aktywacja jest tymczasową ścieżką testową; publikacja w sklepach wymaga procesu wydawcy i weryfikacji na Windows.

## Granice ochrony

- Zdarzenie `onBeforeNavigate` rozpoczyna się w toku nawigacji, a MV3 nie udostępnia temu rozszerzeniu gwarantowanego, synchronicznego punktu blokowania przed odpowiedzią Native Messaging. Po wykryciu umiarkowanego lub wyższego ryzyka rozszerzenie próbuje zastąpić bieżącą kartę stroną ostrzeżenia; strona docelowa może zacząć się ładować wcześniej. To ostrzeżenie z próbą przerwania nawigacji, nie gwarantowana blokada.
- Kliknięcie **Otwórz mimo ostrzeżenia** jawnie zezwala na jedną kontynuację tej karty. Wynik nie jest potwierdzeniem, że strona jest złośliwa; brak sygnałów nie potwierdza bezpieczeństwa.
- Silnik wykorzystuje wyłącznie lokalne heurystyki URL i wersjonowane reguły. Nie ma zasilonej reputacji URL, feedu URLhaus/PhishTank ani daty aktualizacji wskaźników. Nie przedstawiamy heurystyk jako znanych zagrożeń.
- Błąd hosta lub przekroczenie 3 sekund pozostawia przeglądarkę działającą i nie wyświetla strony blokującej.
- Nie analizujemy iframe'ów, przekierowań ani pobranych plików. Nie obsługujemy Firefoksa.

## Testy i budowa

`python3 scripts/check-browser-extension.py` sprawdza Manifest V3, identyfikator klucza, dopasowanie originu hosta, ograniczony zestaw uprawnień i składnię JavaScript (jeśli jest Node.js). Testy .NET w `tests/Sentinel.Tests/BrowserIntegrationTests.cs` sprawdzają ramkowanie, rozmiary komunikatów, wyniki analizy, prywatność odpowiedzi i zapis local-only do SQLite. Końcowa aktywacja rozszerzenia, rejestracja HKCU i interakcja z kartą wymagają testu na interaktywnym Windows z Edge/Chrome.

Pełny instalator buduje `bash scripts/build-installer-cloud.sh`. W jego katalogu `app` host oraz rozszerzenie są samodzielnymi komponentami payloadu. Natywna ścieżka rejestru Windows nie jest wykonywana na Linuksie.
