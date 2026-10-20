# PLAN-008 — instalator, naprawa i updater

1. **Cel:** cykl install/update/rollback/uninstall bez utraty danych i z weryfikowalnym artefaktem.
2. **Stan obecny:** `installer/Sentinel.Setup` wykonuje staging, per-user, hash payloadu, ACL, log, cancel, preservation plików i self-test. Self-test 0.15.12 ujawnił powtarzalne odrzucenie `chrome_100_percent.pak`; przyczyną był odczyt długości przed opróżnieniem bufora `FileStream`. Dodano `Flush()` przed weryfikacją rozmiaru oraz asercje wskaźnika danych i nagłówków obu baz SQLite po smoke teście. Pełny lokalny build i self-test 0.15.13–0.15.15 przechodzą. Czysty Windows pełny cykl nie został wykonany.
3. **Braki:** naprawa z GUI, podpis cyfrowy, autoupdate i rollback wersji; hand-tested shortcut/autostart/hosts/uninstall.
4. **Decyzje:** nie aktualizować po cichu; podpisany manifest + hash przed update; zachować dane; nie robić self-update z uruchomionego pliku bez atomowego helpera.
5. **Zależności:** certyfikat Authenticode, release workflow, schema version, czysty Windows VM.
6. **Etapy:** (a) czysta instalacja/GUI; (b) update/cancel/rollback; (c) repair; (d) signed CI asset; (e) updater opt-in; (f) uninstall/data checks.
7. **Pliki:** `installer/`, build/release workflows, user validation docs, changelog.
8. **Prywatność:** log lokalny; brak telemetry; nie zmieniać sieci/Defendera.
9. **Testy:** `npm run package` tworzy nowy instalator, weryfikuje payload hash, ekstrakcję, ACL Chromium, uruchomienie renderer → IPC → silnik .NET → SQLite oraz nagłówki `sentinel.db`/`knowledge.db` — lokalnie PASS dla 0.15.13–0.15.15. Pełen cykl na snapshot VM, awaria host registration, disk full, cancellation i hash mismatch pozostają niewykonane.
10. **Akceptacja:** install/update/rollback/uninstall przechodzą na czystym Windows; zachowane dane; signature valid; brak admina jeśli nie wymaga.
11. **Ryzyka:** brak signing certificate blokuje zaufany update; SmartScreen; polityki firmowe.
12. **Status:** `IN_PROGRESS` — poprawka ekstrakcji, test baz po smoke instalacji oraz Windows CI/self-test/release v0.15.14 PASS; lokalny build/self-test kandydata 0.15.15 także PASS. Najnowszy harness sprawdza izolowane ścieżki pod `%LOCALAPPDATA%\Programs` i `%LOCALAPPDATA%`. Pełen cykl GUI/update/rollback/uninstall w clean-room pending.

