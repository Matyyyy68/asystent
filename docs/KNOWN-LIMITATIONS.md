# Znane ograniczenia — 2026-10-18

- To wersja rozwojowa. Własny instalator sprawdza SHA-256, instaluje per-user, nadaje Chromium wymagane uprawnienie odczytu i wykonania dla AppContainer, rejestruje host, zapisuje log oraz ma automatyczny test ekstrakcji i uruchomienia aplikacji. Pełny cykl GUI, autostart po logowaniu i działanie rozszerzenia nadal wymagają ręcznej walidacji na czystym Windows.
- Instalator nie używa MSI ani NSIS. Polityki organizacji mogą ograniczyć uruchamianie niepodpisanych aplikacji, zmianę ACL lub rejestrację hosta przeglądarki.
- DNS to próbkowany cache Windows, nie strumień zapytań. DoH, VPN, wpisy cache usunięte między próbkami i połączenia po IP mogą zostać pominięte. Nie ma PID ani pełnego URL. TCP pokazuje tylko metadane bieżących połączeń i nie jest oceniane reputacyjnie.
- WFP, blokowanie ruchu i filtr jądra nie są wdrożone. Nie modyfikujemy ustawień DNS. Ostrzeżenie rozszerzenia może nastąpić już po rozpoczęciu ładowania strony.
- Lista CERT Polska zawiera domeny powiązane z phishingiem i oszustwami; jest dostępna po ręcznej aktualizacji. Po 48 h jest uznawana za wygasłą. URLhaus wymaga własnego Auth-Key i kontroli zasad użycia; nie jest podłączony. Nie ma bazy reputacji IP, pełnych URL malware ani plików.
- Weryfikacja pliku na żądanie liczy SHA-256; nie klasyfikuje zagrożenia. Brak monitorowania poczty, SMS, formularzy i pobranych plików. Nie ma automatycznego AI w nowym kliencie.
- Dane SQLite nie są szyfrowane. Host Native Messaging Chrome/Edge jest lokalny, ale konfigurację sklepu rozszerzeń trzeba przeprowadzić ręcznie. Diagnostyka „kontakt” nie oznacza stałego połączenia.
- Powiadomienia dotyczą wyłącznie dopasowań DNS do listy; ręczna analiza wymaga przeczytania wyniku w UI. Kreator pierwszego uruchomienia zapisuje priorytet i sprawdza status silnika, ale nie mierzy CPU/RAM ani miejsca na dysku. Nie ma bezpiecznego autoupdate aplikacji/modelu.
- Zachowany kod WPF jest w `legacy/` do czasu przeniesienia wartościowych funkcji. Stare skrypty instalatora w `legacy/installer/` i `legacy/scripts/` są historyczne i nie budują nowego klienta. Nie uruchamiaj ich dla wydania 0.14.
- W repozytorium nie ma pliku LICENSE. Przed publiczną dystrybucją właściciel musi ustalić licencję kodu i warunki redystrybucji pakietu; witryna nie oferuje niezweryfikowanego pliku.
- `npm audit --omit=dev` dla desktop/ zgłaszał zero podatności. W narzędziach deweloperskich npm nadal zgłasza osiem umiarkowanych podatności pośrednich. Przed wydaniem ponowić audit i aktualizację.
