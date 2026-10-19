# PLAN-009 — witryna, dokumentacja i wydanie

1. **Cel:** publikowane opisy, download i docs dokładnie odpowiadają testowanym możliwościom.
2. **Stan obecny:** `website/` statyczne; test/lint/build przechodzi; tekst jasno mówi o wersji rozwojowej, DNS cache, braku blokowania i AI. GitHub Actions dla Pages i wydania `v0.15.5` zakończyły wdrożenie/publikację sukcesem; API potwierdza prerelease i asset instalatora z rozmiarem oraz SHA-256. Z tego środowiska nie udało się niezależnie otworzyć live strony ani pobrać treści pliku `.sha256`.
3. **Braki:** live link checks/availability, dokument licencji, Enterprise install docs/clean Windows docs.
4. **Decyzje:** każda obietnica ma test/evidence; status live zależy od CI i ustawień Pages; nie wymyślać licencji.
5. **Zależności:** GitHub Pages, tag/release asset, decyzja właściciela.
6. **Etapy:** (a) workflow Pages i asset/tag/hash potwierdzone przez CI/API; live-check poza środowiskiem pozostaje; (b) test wszystkich zewnętrznych linków w CI; (c) dokumentacja runtime; (d) decyzja licencyjna; (e) release checklist.
7. **Pliki:** `website/`, `README.md`, `docs/`, `.github/workflows/`.
8. **Prywatność:** strona nie deklaruje telemetrii; standardowe logi hostingu; produkt bez chmury.
9. **Testy:** anchors/assets, Vite build, link check, release hash, accessible checks.
10. **Akceptacja:** live asset tag/hash istnieje; marketing jest zgodny z ograniczeniami; licencja opisana przez właściciela.
11. **Ryzyka:** host Pages inaccessible/disabled, release missing, dependency licenses.
12. **Status:** `IN_PROGRESS` — prerelease `v0.15.5`, asset installer i digest SHA-256 potwierdzone przez GitHub API; Pages workflow PASS. Niezależny live-check URL/sidecar, zewnętrzne linki, licencja i czysty Windows pozostają.

