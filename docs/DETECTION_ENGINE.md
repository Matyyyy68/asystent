# Detection Engine

Silnik analizuje ręcznie przekazany tekst/adres regułami lokalnymi, korzysta z lokalnych list reputacji, zbiera wybrane snapshoty systemu i zapisuje zdarzenia w SQLite. Zdarzenia mają źródło, kategorię, ryzyko, wyjaśnienie, rekomendację, status oraz dostępne dowody/kody reguł. Zdarzenia domenowe i procesowe mogą być grupowane po lokalnych identyfikatorach korelacji.

Nowe PID-y z procesu snapshotu są korelowane z jednym udokumentowanym snapshotem Toolhelp. Reguła `process.behavior.office-spawned-script-host` oznacza uruchomienie interpretera/skryptu przez proces Office jako umiarkowane ryzyko wymagające sprawdzenia. Wyjaśnienie zawiera nazwy i PID-y zaobserwowanej relacji. Krótkie procesy oraz rodzice zakończeni przed snapshotem mogą zostać pominięci; heurystyka nie dowodzi ataku, a Sentinel nie zatrzymuje procesu.

Analiza AI przez lokalną Ollama jest opcjonalna i wymaga ręcznej konfiguracji; brak modelu nie wyłącza reguł. Wynik modelu nie jest skalibrowanym prawdopodobieństwem. Monitorowanie procesów i zmian nie jest równoważne detekcji zachowania malware. Nie ma zintegrowanej blokady wykonania ani WFP. Dla nowego pliku z Downloads, który pasuje do ręcznie zaimportowanej listy SHA-256, użytkownik może jawnie uruchomić odwracalne przeniesienie do lokalnej kwarantanny; hash jest weryfikowany ponownie przed i po przeniesieniu. To dopasowanie nie potwierdza złośliwości, nie obejmuje innych plików/źródeł, a Sentinel nie wykonuje tej akcji automatycznie. Użytkownik nie powinien otrzymać komunikatu o zablokowanym zagrożeniu bez potwierdzonej blokady.

Brak dopasowania reputacji, brak alertu lub podpis Authenticode nie dowodzą bezpieczeństwa/złośliwości. Każda automatyczna reakcja o nieodwracalnym skutku pozostaje poza zakresem.
