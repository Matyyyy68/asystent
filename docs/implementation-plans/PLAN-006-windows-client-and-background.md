# PLAN-006 — klient Windows i działanie w tle

1. **Cel:** zapewnić czytelny stan modułów, bezpieczny tray/autostart i diagnozowalne błędy.
2. **Stan obecny:** Electron ma single-instance lock, tray, hide-on-close, autostart API i cykliczny DNS. Diagnostyka pokazuje bieżący working set, pamięć prywatną i skumulowany czas CPU procesu silnika; powtarzalny skrypt mierzy 6 próbek co 5 sekund. Build/self-test działa; realny restart Windows i GUI nie były walidowane.
3. **Braki:** wyjątki stderr są ignorowane, kolektor ogranicza stan do tooltipa, brak service recovery/heartbeat oraz testów po restarcie.
4. **Decyzje:** pozostawić desktop per-user bez Windows service na tym etapie; logować kody błędów z redakcją; nie dublować autostartu rejestrem i Electronem.
5. **Zależności:** schema event, installer, Windows profile.
6. **Etapy:** (a) structured diagnostic errors; (b) retry/backoff engine; (c) zweryfikować autostart w installed app; (d) accessibility + error states; (e) soak/resource tests.
7. **Pliki:** Electron main, Engine, UI, validation docs, installer smoke tests.
8. **Prywatność:** log bez treści/URL; state/tray bez szczegółowych nawyków.
9. **Testy:** engine crash/restart, autostart true/false po reboot, tray/minimize/exit, dostępność i resource profile. Bieżący 30 s profil jednej sesji: working set 43,4–45,3 MiB, średnie CPU 0,124% po normalizacji do wszystkich logicznych procesorów; nie zastępuje soak testu.
10. **Akceptacja:** błędy w UI/logu, stan „ready” zgodny z procesem, exit zatrzymuje child, brak podwójnej instancji.
11. **Ryzyka:** polityki Windows blokują autostart/notify; test wymaga sesji GUI/restartu.
12. **Status:** `IN_PROGRESS` — implementacja kodowa istnieje, a bieżące metryki/benchmark są testowane; realny test zainstalowanego klienta po restarcie Windows nadal oczekuje.

