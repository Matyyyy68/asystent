# Doświadczenie użytkownika

## Zwykły przepływ

1. Użytkownik klika „ZAINSTALUJ”; lokalizacja i opcje pozostają w obszarze zaawansowanym.
2. Po instalacji UI uruchamia się domyślnie; instalator także próbuje uruchomić agenta od razu i rejestruje go do startu przy logowaniu.
3. Zanim pojawi się zwykły interfejs, UI pokazuje osobny ekran pierwszego sprawdzenia i czeka na wynik `collect`; przy błędzie pozwala ponowić próbę.
4. Agent kontynuuje cykle lokalnie niezależnie od otwartego okna.
5. Ekran główny pokazuje stan ochrony, najważniejsze wykrycia i czas ostatniego udanego cyklu monitorowania z silnika. Szczegółowe statusy monitorów i Windows Security Center są zwinięte pod „Szczegóły monitorowania”. Nie deklaruje pełnego skanu.
6. Zdarzenia wymagające uwagi można zobaczyć w historii. Narzędzia techniczne są dostępne po rozwinięciu „Narzędzia zaawansowane”.
7. Lista zdarzeń używa polskich etykiet ryzyka i statusu. Szczegóły źródła, wersji reguł i dowodów są domyślnie zwinięte; zdarzenie można oznaczyć jako sprawdzone lub fałszywy alarm. Dla nowego pliku z Downloads dopasowanego do lokalnej listy hashy można jawnie zatwierdzić przeniesienie wybranego, ponownie zweryfikowanego pliku do kwarantanny i później go przywrócić.
8. Menu ikony Sentinel przy zegarze zawiera skrót „Ostatnie alerty” oraz ręczne „Sprawdź aktualizacje”. Sprawdzenie pyta publiczne GitHub API o stabilne wydanie; jeśli jest nowsze, użytkownik może otworzyć jego oficjalną stronę. Sentinel nie pobiera i nie instaluje aktualizacji automatycznie.
9. Pierwszy cykl odczytuje też lokalnie wyłącznie nazwę, wersję i wydawcę aplikacji z wpisów deinstalacji rejestru Windows. Lista pojawia się dopiero na żądanie w zwiniętych szczegółach monitorowania; nie jest przesyłana ani zapisywana w historii.\r\n10. Nowe profile odświeżają automatycznie co 24 godziny stały feed domen CERT Polska przez HTTPS. Zapytanie nie wysyła analizowanych adresów. Gdy feed jest aktualny, ponowne pobranie nie jest wykonywane.

## Co się zmieniło

Poprzedni ekran pierwszego uruchomienia wymagał wyboru profilu DNS i ręcznego zastosowania ustawień. Usunięto ten wybór z głównej ścieżki. Nawigacja podstawowa obejmuje przegląd i zdarzenia; pozostałe istniejące sekcje są zwinięte.

## Granice

Pierwsze sprawdzenie wywołuje istniejące źródła zbierania i czyta metadane z wpisów zainstalowanych aplikacji, nie skanuje całego systemu. Spis aplikacji nie jest kontrolą CVE, aktualności komponentów ani stanu sygnatur Defendera. Nowe profile uruchamiają lokalne monitorowanie procesów, Downloads, trwałości i TCP/UDP; stare zapisane preferencje nie są nadpisywane. Wykrycia zależą od dostępności źródeł, uprawnień i lokalnych list reputacji. Kwarantanna dotyczy tylko plików z Downloads o SHA-256 pasującym do lokalnej listy; dopasowanie nie jest potwierdzonym werdyktem malware. Operacja wymaga osobnego potwierdzenia, nie nadpisuje przywracanego pliku i może być niedostępna, jeśli folder danych i Downloads są na różnych woluminach. Błąd albo brak pierwszego odczytu cache DNS obniża status ochrony. Po błędzie interfejs komunikuje niepowodzenie i pozwala ponowić próbę. Pełny interaktywny test instalatora przechodzi na izolowanym Windows runnerze CI; widok użytkownika nie był ręcznie testowany na fizycznym komputerze odbiorcy.

Z menu kontekstowego pliku można wybrać „Sprawdź w Sentinel AI”. Dostępna analiza jest lokalna i ograniczona do SHA-256 oraz statusu podpisu cyfrowego. Nie uruchamia, nie blokuje i nie usuwa pliku. Szczegóły i ograniczenia są w [WINDOWS_MONITORING.md](WINDOWS_MONITORING.md).
