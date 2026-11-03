# Doświadczenie użytkownika

## Zwykły przepływ

1. Użytkownik klika „ZAINSTALUJ”; lokalizacja i opcje pozostają w obszarze zaawansowanym.
2. Po instalacji UI uruchamia się domyślnie; instalator także próbuje uruchomić agenta od razu i rejestruje go do startu przy logowaniu.
3. Zanim pojawi się zwykły interfejs, UI pokazuje osobny ekran pierwszego sprawdzenia i czeka na wynik `collect`; przy błędzie pozwala ponowić próbę.
4. Agent kontynuuje cykle lokalnie niezależnie od otwartego okna.
5. Ekran główny pokazuje stan ochrony, najważniejsze wykrycia i czas ostatniego udanego cyklu monitorowania z silnika. Szczegółowe statusy monitorów i Windows Security Center są zwinięte pod „Szczegóły monitorowania”. Nie deklaruje pełnego skanu.
6. Zdarzenia wymagające uwagi można zobaczyć w historii. Narzędzia techniczne są dostępne po rozwinięciu „Narzędzia zaawansowane”.

## Co się zmieniło

Poprzedni ekran pierwszego uruchomienia wymagał wyboru profilu DNS i ręcznego zastosowania ustawień. Usunięto ten wybór z głównej ścieżki. Nawigacja podstawowa obejmuje przegląd i zdarzenia; pozostałe istniejące sekcje są zwinięte.

## Granice

Pierwsze sprawdzenie wywołuje istniejące źródła zbierania, nie skanowanie całego systemu. Nowe profile uruchamiają lokalne monitorowanie procesów, Downloads, trwałości i TCP/UDP; stare zapisane preferencje nie są nadpisywane. Wykrycia zależą od dostępności źródeł, uprawnień i lokalnych list reputacji. Po błędzie interfejs komunikuje niepowodzenie i pozwala ponowić próbę. Interaktywny test nowego widoku w Windows nie został jeszcze wykonany.

Z menu kontekstowego pliku można wybrać „Sprawdź w Sentinel AI”. Dostępna analiza jest lokalna i ograniczona do SHA-256 oraz statusu podpisu cyfrowego. Nie uruchamia, nie blokuje i nie usuwa pliku. Szczegóły i ograniczenia są w [WINDOWS_MONITORING.md](WINDOWS_MONITORING.md).
