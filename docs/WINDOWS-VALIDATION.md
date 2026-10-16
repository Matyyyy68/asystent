# Natywna walidacja Windows — procedura jeszcze niewykonana na hoście Linux

Wymagany interaktywny Windows 10/11 x64, konto zwykłego użytkownika i .NET SDK z global.json. Nie uruchamiaj testu na rzeczywistych danych logowania. Użyj syntetycznego pliku TXT i Notatnika. Warianty edytora/stron różnie eksponują UI Automation: brak odczytu jest ograniczeniem, nie dowodem bezpieczeństwa.

1. Wykonaj komendy restore/build/test/run z README. Sprawdź, czy pierwsze uruchomienie pozwala wybrać lokalny katalog, a rezygnacja bezpiecznie zamyka aplikację. Nie podawaj katalogu współdzielonego. Ponowny start ma odczytać zapisane ustawienia.
2. Domyślny wskaźnik powinien pokazywać pauzę. Przycisk odczytu okna w pauzie nie powinien uruchamiać zbierania. Analiza ręcznie wklejonego tekstu ma być dostępna.
3. Wklej „Pilnie: blokada konta. Zaloguj się” i wpisz w osobnym polu URL `https://paypal.com.evil.test/login`. Sprawdź wysokie ostrzeżenie, zalecenia, niepewności i zapis historii. Pola wejściowe mają zostać wyczyszczone.
4. Przeanalizuj zwykłą notatkę i `https://accounts.google.com`. Nie powinno wystąpić ostrzeżenie o podszywaniu się pod markę; wynik nie może obiecywać bezpieczeństwa.
5. Włącz analizę okien. Odczyt ręczny daje 3 sekundy na przełączenie się do innej aplikacji. Treść w kontrolkach edycyjnych Notatnika może zostać celowo pominięta. Dla próby statycznego tekstu użyj np. lokalnej strony HTML z syntetycznymi etykietami i przyciskiem „Pilnie — zaloguj się”. Sama etykieta URL nie powinna powodować uznania adresu za ustalony cel.
6. W lokalnym pliku HTML dodaj formularz z input/password i syntetycznymi wartościami. Provider nie powinien odczytywać wartości formularzy. Przejrzyj historię i eksport JSON: nie mogą zawierać wartości, URL, tytułu ani pełnej treści. Nie traktuj pozytywnego wyniku dla jednej przeglądarki jako gwarancji wszystkich implementacji accessibility.
7. Zapisz wykluczenie procesu testowanej przeglądarki. Odczyt ma zgłosić wykluczenie, bez ekstrakcji. Powtórz dla fragmentu tytułu, wykluczenia przeglądarek i znanych komunikatorów. Wyłączenie odczytu statycznego tekstu ma zwrócić ocenę z informacją o braku tekstu.
8. Zapisz tryb analizy przy zmianie okna i odstęp 10 s. Przełączaj okna: odczyty powinny następować wyłącznie przy zdarzeniu i z ograniczeniem częstotliwości. Zmiana strony w tym samym oknie nie jest obsługiwanym źródłem zdarzeń nawigacji. Wstrzymanie ma zatrzymać nowe odczyty i anulować oczekujący ręczny odczyt.
9. Zamknij aplikację. Nie powinien pozostawać działający agent ani hook. Włączone ustawienia mogą zostać odtworzone po ponownym pokazaniu głównego okna; wskaźnik musi odpowiadać trybowi.
10. Sprawdź oznaczanie fałszywego alarmu, retencję, eksport, kopię i usuwanie z potwierdzeniem. Po restarcie dane mają odpowiadać zapisowi. Nie nadpisuj istniejącej bazy bez kopii. Odmowa zapisu i uszkodzona baza mają skutkować czytelnym błędem bez resetu.
11. Wykonaj publikację self-contained z README. Przenieś cały katalog na testowy Windows x64 bez zainstalowanego .NET i sprawdź start. Publikacja nie instaluje autostartu, usługi ani rozszerzenia.

Do raportu zapisz wersję Windows, aplikację źródłową, tryb UIA i wynik każdego kroku. Nie zapisuj danych poufnych ani zrzutów zawierających prawdziwe formularze.
