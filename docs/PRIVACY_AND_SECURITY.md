# Prywatność i bezpieczeństwo

Domyślny silnik oraz historia pracują lokalnie. W nowym profilu procesy, Downloads, wybrane zmiany trwałości Windows i metadane połączeń TCP/UDP są monitorowane lokalnie bez przesyłania. Istniejące zapisane preferencje użytkownika pozostają zachowane. SQLite nie jest szyfrowana; zależnie od monitora mogą być lokalnie zapisywane nazwy/identyfikatory procesów, ścieżki, rozmiary, czasy, hashe i metadane zdarzeń. Zbieranie tekstu aktywnego okna oraz automatyczne pobieranie list zewnętrznych pozostają domyślnie wyłączone. Eksporty oraz Enterprise mają osobne filtrowanie. Wysyłanie metadanych do Enterprise wymaga jawnej zgody; ręczne wysłanie treści do Enterprise wymaga osobnego natywnego potwierdzenia. MalwareBazaar lookup wysyła hash po osobnym działaniu i wymaga klucza.

Sentinel nie zbiera haseł, nie rejestruje klawiatury, nie nagrywa ekranu i nie odszyfrowuje HTTPS. Nie wyłącza Microsoft Defender. Nie usuwa plików automatycznie na podstawie niepewnego wyniku. Usługa z uprawnieniami SYSTEM nie istnieje.

Odczyt Windows Security Center jest lokalny i tylko do odczytu; zgłasza zagregowany stan kategorii antywirusa/zapory, nie nazwę konkretnego produktu.

Zakres, retencję i ograniczenia każdego źródła opisuje [monitorowanie Windows](WINDOWS_MONITORING.md) oraz [znane ograniczenia](KNOWN-LIMITATIONS.md).
