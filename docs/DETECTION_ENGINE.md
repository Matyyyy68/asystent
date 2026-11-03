# Detection Engine

Silnik analizuje ręcznie przekazany tekst/adres regułami lokalnymi, korzysta z lokalnych list reputacji, zbiera wybrane snapshoty systemu i zapisuje zdarzenia w SQLite. Zdarzenia mają źródło, kategorię, ryzyko, wyjaśnienie, rekomendację, status oraz dostępne dowody/kody reguł. Zdarzenia domenowe i procesowe mogą być grupowane po lokalnych identyfikatorach korelacji.

Analiza AI przez lokalną Ollama jest opcjonalna i wymaga ręcznej konfiguracji; brak modelu nie wyłącza reguł. Wynik modelu nie jest skalibrowanym prawdopodobieństwem. Monitorowanie procesów i zmian nie jest równoważne detekcji zachowania malware. Nie ma zintegrowanej blokady wykonania, kwarantanny ani WFP. Użytkownik nie powinien otrzymać komunikatu o zablokowanym zagrożeniu bez potwierdzonej blokady.

Brak dopasowania reputacji, brak alertu lub podpis Authenticode nie dowodzą bezpieczeństwa/złośliwości. Każda automatyczna reakcja o nieodwracalnym skutku pozostaje poza zakresem.
