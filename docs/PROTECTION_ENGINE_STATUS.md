# Sentinel Protection Engine — stan weryfikacji

Data audytu: 2026-11-08  
Zakres: bieżący stan gałęzi `codex/sentinel-wmi-process-events`. Cały cel nadal **IN PROGRESS**.

## Dowody wykonania

Pełny Windows CI dla commita [`605ed33`](https://github.com/Matyyyy68/asystent/commit/605ed338cadb67108a5bbfd656c6b049c78b7dd7) zakończył się PASS w [run 42426389929](https://github.com/Matyyyy68/asystent/actions/runs/42426389929). Przeszły kompilacja i testy .NET, pomiar Engine, kontrola zasobów, testy usługi SCM, aplikacji Electron, przekierowanego katalogu Downloads i jego 120-sekundowy soak, E2E rozszerzenia, instalator headless i widoczny kreator oraz Enterprise API. Nowe testy pokrywają parser zdarzeń Defendera, ochronę prywatności pól i trwałość kursora po ponownym otwarciu bazy. To testy syntetycznego XML i izolowanego runnera; nie wymuszano rzeczywistego wykrycia Defendera, a fizyczny restart czystego Windows nadal nie był sprawdzony.

## Zaimplementowane i zweryfikowane

- Silnik działa niezależnie od okna aplikacji jako usługa SCM; monitoruje stan kolekcji i podejmuje ograniczone próby restartu.
- Po instalacji kreator sprawdza w Windows SCM reset licznika 24 h, dwa ponowne uruchomienia z opóźnieniem 60 s i flagę odzyskiwania przy niecrashowym zatrzymaniu. Windows CI 42412202567 i 42413895883 przeszły instalację headless i GUI. Izolowany test SCM zakończył proces usługi i potwierdził automatyczny restart oraz świeży collect Engine; harmonogram testowy ma krótki delay, produkcyjny pozostaje 60 s.
- Zdarzenia procesów pochodzą z WMI, gdy dostępne; snapshot PID stanowi jawny fallback.
- Engine odczytuje wybrane zdarzenia Microsoft Defender Operational (1116–1119, 5007, 5008), zapisuje osobny kursor i utrwala zdarzenia lokalnie z deterministycznym ID. Parser dopuszcza wyłącznie nazwę/poziom wykrycia, kategorię i nazwę/status działania; nie utrwala ścieżki pliku, konta ani wartości starej/nowej konfiguracji.
- Kolekcja obejmuje wybrane zdarzenia procesu, Downloads, obserwacje TCP/UDP/DNS oraz wybrane ustawienia trwałości i zabezpieczeń systemu.
- Zdarzenia są normalizowane i korelowane w ograniczonym zakresie przez PID, hash, identyfikatory i okna czasu; historia jest lokalna.
- Ocena ryzyka opiera się na lokalnych regułach. Niezweryfikowany feed ani odpowiedź AI same nie podnoszą liczbowego ryzyka.
- Centralna decyzja odpowiedzi jest zapisywana dla nowych zdarzeń. Powiadomienia historii respektują tę politykę.
- UI może odczytać stan usługi i przeglądać jej historię; pipe stosuje ACL i ograniczenia protokołu.
- Kwarantanna wymaga jawnego działania użytkownika. Rekomendacje nie twierdzą, że ruch lub proces został zablokowany.
- RiskEngine odrzuca ponad 1024 surowe wejścia albo ponad 256 unikalnych wskaźników; regresje limitów przeszły w pełnym .NET CI. Limity nie są miarą wydajności urządzeń.
- Główny status ochrony uwzględnia świeżość podstawowego CERT Polska domain feedu: brak lub przeterminowana baza obniża status do `LIMITED_PROTECTION`. Regresje dla brakującego, nieaktualnego i aktualnego feedu przechodzą w pełnym .NET CI 565/565.
- Nawet gdy dostępne sensory działają, status pozostaje `LIMITED_PROTECTION` i jawnie wskazuje ograniczenia: Pobrane bez pełnego monitoringu systemu plików, WMI zamiast kernel ETW, migawki zamiast pełnego strumienia sieciowego, cache zamiast pełnego strumienia DNS i brak WFP/blokowania. Regresja komunikatu przeszła w Windows CI 42419784238.

## Częściowe / brakujące

- WMI nie jest pełnym kernel ETW i może utracić zdarzenia; pełny strumień ETW nie jest wdrożony.
- Integracja Defender Operational nie jest aktywną ochroną antywirusową ani silnikiem kwarantanny. Dostęp do kanału zależy od konfiguracji/ACL Windows; brak testu z rzeczywistym alarmem Defendera na fizycznym urządzeniu.
- Brak kolektora WFP i ogólnego blokowania procesu lub sieci. Pełny file-system monitoring nie jest wdrożony; monitorowanie plików obejmuje Downloads i wybrane ścieżki.
- Migawki sieci mogą pominąć krótkotrwałe przepływy; obserwacja UDP nie dowodzi wysłania datagramu.
- Agent i Service utrzymują oddzielne bazy. Przekazywanie wybranych zdarzeń istnieje, lecz unifikacja incydentów i deduplikacja zdarzeń o różnych ID są niepełne.
- Heurystyki nie są skalibrowanym prawdopodobieństwem. Brakuje niezależnego, reprezentatywnego holdoutu phishingu.
- Brakuje podpisanych feedów i zaufanego, podpisanego mechanizmu automatycznych aktualizacji.
- Licencja produktu nadal wymaga decyzji właściciela. Nie przeprowadzono pełnego cyklu instalacji i restartu na czystym fizycznym Windows.

## Stan dostarczenia

PR [#1](https://github.com/Matyyyy68/asystent/pull/1) pozostaje otwarty i niescalony. Nowsze commity `main` zostały dołączone do gałęzi PR w merge commicie `19f90f1`; zmiany zachowano w UI, workflow CI i lockfile. GitHub potwierdził `mergeable: true`, a pełny Windows CI dla połączonego stanu zakończył się PASS. Samo scalenie PR nadal nie nastąpiło.