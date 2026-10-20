# PLAN-006 — klient Windows i działanie w tle

1. **Cel:** zapewnić czytelny stan modułów, bezpieczny tray/autostart i diagnozowalne błędy.
2. **Stan obecny:** Electron ma single-instance lock, tray, hide-on-close, autostart API i cykliczny DNS. Diagnostyka pokazuje bieżący working set, pamięć prywatną i skumulowany czas CPU procesu silnika. `EngineClient` ponawia uruchomienie silnika z wykładniczym opóźnieniem do 30 s po błędzie startu, wyjściu procesu, błędzie stdin lub niepoprawnej odpowiedzi; odrzuca oczekujące IPC i czyści retry przy zamknięciu. Surowe stderr nie jest logowane; stan zapisuje tylko, czy silnik coś wypisał. Build/self-test działa; realny restart Windows i GUI nie były walidowane.
3. **Braki:** stan diagnostyczny engine nie jest prezentowany szczegółowo w rendererze ani pakiecie diagnostycznym; brak service recovery/heartbeat oraz testów po restarcie.
4. **Decyzje:** pozostawić desktop per-user bez Windows service na tym etapie; logować kody błędów z redakcją; nie dublować autostartu rejestrem i Electronem.
5. **Zależności:** schema event, installer, Windows profile.
6. **Etapy:** (a) structured diagnostic errors — częściowo, przyczyny ograniczone do kodu/exit; (b) retry/backoff engine — wdrożone i testowane; (c) zweryfikować autostart w installed app; (d) accessibility + error states; (e) soak/resource tests.
7. **Pliki:** Electron main, Engine, UI, validation docs, installer smoke tests.
8. **Prywatność:** log bez treści/URL; state/tray bez szczegółowych nawyków.
9. **Testy:** Node testy 3/3 sprawdzają odpowiedź IPC po starcie, restart po wyjściu, odrzucenie oczekujących żądań, zatrzymanie retry przy zamknięciu oraz brak ujawniania stderr; są wykonywane przez `scripts/build-user.ps1`, a desktop lint/build PASS. Pozostają realny crash/restart GUI, autostart true/false po reboot, tray/minimize/exit, dostępność i resource profile. Bieżący 30 s profil jednej sesji: working set 43,4–45,3 MiB, średnie CPU 0,124% po normalizacji do wszystkich logicznych procesorów; nie zastępuje soak testu.
10. **Akceptacja:** błędy w UI/logu, stan „ready” zgodny z procesem, exit zatrzymuje child, brak podwójnej instancji.
11. **Ryzyka:** polityki Windows blokują autostart/notify; test wymaga sesji GUI/restartu.
12. **Status:** `IN_PROGRESS` — kandydat v0.15.26: tray/autostart istnieją; supervisor silnika automatycznie ponawia start i przechodzi 3/3 testów Node, pełny lokalny Windows build/self-test PASS. Szczegółowy stan awarii w UI, CI, realny test zainstalowanego klienta po restarcie Windows i długotrwały soak nadal oczekują.

