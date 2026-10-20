# PLAN-008 — instalator, naprawa i updater

1. **Cel:** cykl install/update/rollback/uninstall bez utraty danych i z weryfikowalnym artefaktem.
2. **Stan obecny:** `installer/Sentinel.Setup` wykonuje staging, per-user, hash payloadu, ACL, log, cancel, preservation plików i self-test. Self-test 0.15.12 ujawnił powtarzalne odrzucenie `chrome_100_percent.pak`; przyczyną był odczyt długości przed opróżnieniem bufora `FileStream`. Dodano `Flush()` przed weryfikacją rozmiaru oraz asercje wskaźnika danych i nagłówków obu baz SQLite po smoke teście. Lokalny build/self-test v0.15.32 PASS; GitHub installer/release workflow `39472689007` PASS. Opublikowany asset ma 262539381 B, SHA-256 `efda654ec6e03cdcc5f9d865fb8adccff4665ecc3f8e346d4bb0ed9eadbcc396` i sidecar. Czysty Windows pełny cykl nie został wykonany.
3. **Braki:** naprawa z GUI, podpis cyfrowy, autoupdate i rollback wersji; hand-tested shortcut/autostart/hosts/uninstall.
4. **Decyzje:** nie aktualizować po cichu; podpisany manifest + hash przed update; zachować dane; nie robić self-update z uruchomionego pliku bez atomowego helpera.
5. **Zależności:** certyfikat Authenticode, release workflow, schema version, czysty Windows VM.
6. **Etapy:** (a) czysta instalacja/GUI; (b) update/cancel/rollback; (c) repair; (d) signed CI asset; (e) updater opt-in; (f) uninstall/data checks.
7. **Pliki:** `installer/`, build/release workflows, user validation docs, changelog.
8. **Prywatność:** log lokalny; brak telemetry; nie zmieniać sieci/Defendera.
9. **Testy:** `npm run package` tworzy nowy instalator, weryfikuje payload hash, ekstrakcję, ACL Chromium, uruchomienie renderer → IPC → silnik .NET → SQLite oraz nagłówki `sentinel.db`/`knowledge.db` — lokalnie PASS dla 0.15.13–0.15.20. Windows installer release/self-test `39441965987` PASS; opublikowany instalator ma 262521973 B i SHA-256 `0c2236a48806817fb2fd8fcdf1e7f3b2c62128042860ec11ce387edb77a87f1d`. Pełen cykl na snapshot VM, awaria host registration, disk full, cancellation i hash mismatch pozostają niewykonane.
10. **Akceptacja:** install/update/rollback/uninstall przechodzą na czystym Windows; zachowane dane; signature valid; brak admina jeśli nie wymaga.
11. **Ryzyka:** brak signing certificate blokuje zaufany update; SmartScreen; polityki firmowe.
12. **Status:** `IN_PROGRESS` — lokalny build i self-test v0.15.32 oraz GitHub installer workflow `39472689007` PASS. Opublikowany instalator v0.15.32 ma 262539381 B i SHA-256 `efda654ec6e03cdcc5f9d865fb8adccff4665ecc3f8e346d4bb0ed9eadbcc396`. Harness sprawdza izolowane ścieżki pod `%LOCALAPPDATA%\Programs` i `%LOCALAPPDATA%`. Pełen cykl GUI/update/rollback/uninstall w clean-room pozostaje do wykonania.

