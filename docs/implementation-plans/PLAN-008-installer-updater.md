# PLAN-008 — instalator, naprawa i updater

1. **Cel:** cykl install/update/rollback/uninstall bez utraty danych i z weryfikowalnym artefaktem.
2. **Stan obecny:** `installer/Sentinel.Setup` wykonuje staging, per-user, hash payloadu, ACL, log, cancel, preservation plików i self-test. Build plus `--self-test` passed; czysty Windows pełny cykl nie wykonany.
3. **Braki:** naprawa z GUI, podpis cyfrowy, autoupdate i rollback wersji; hand-tested shortcut/autostart/hosts/uninstall.
4. **Decyzje:** nie aktualizować po cichu; podpisany manifest + hash przed update; zachować dane; nie robić self-update z uruchomionego pliku bez atomowego helpera.
5. **Zależności:** certyfikat Authenticode, release workflow, schema version, czysty Windows VM.
6. **Etapy:** (a) czysta instalacja/GUI; (b) update/cancel/rollback; (c) repair; (d) signed CI asset; (e) updater opt-in; (f) uninstall/data checks.
7. **Pliki:** `installer/`, build/release workflows, user validation docs, changelog.
8. **Prywatność:** log lokalny; brak telemetry; nie zmieniać sieci/Defendera.
9. **Testy:** pełen cykl na snapshot VM, awaria host registration, disk full, cancellation, hash mismatch, signature.
10. **Akceptacja:** install/update/rollback/uninstall przechodzą na czystym Windows; zachowane dane; signature valid; brak admina jeśli nie wymaga.
11. **Ryzyka:** brak signing certificate blokuje zaufany update; SmartScreen; polityki firmowe.
12. **Status:** `IN_PROGRESS` — smoke install PASS, system clean-room pending.

