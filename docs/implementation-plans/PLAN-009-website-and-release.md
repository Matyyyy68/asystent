# PLAN-009 — witryna, dokumentacja i wydanie

1. **Cel:** publikowane opisy, download i docs dokładnie odpowiadają testowanym możliwościom.
2. **Stan obecny:** `website/` statyczne; tekst jasno mówi o wersji rozwojowej, DNS cache, braku blokowania i AI. GitHub Actions opublikował prerelease `v0.15.19` (262521461 B, SHA-256 `3826706412de6803397de93a39767400ecceb70b9876180d1e10d80f680be25b`). HTML/linki wskazują v0.15.19, a test zgodności URL-i z wersją pakietu chroni przed rozjazdem. Website test/lint/build PASS; Pages deployment commita `52a629c` zakończył się sukcesem w runie `39439950410`. Live HTTP check nieosiągalny w tej sesji z powodu blokady połączeń sieciowych sandboxa.
3. **Braki:** automatyczne sprawdzanie dostępności zewnętrznych linków w CI, dokument licencji, Enterprise install docs/clean Windows docs.
4. **Decyzje:** każda obietnica ma test/evidence; status live zależy od CI i ustawień Pages; nie wymyślać licencji.
5. **Zależności:** GitHub Pages, tag/release asset, decyzja właściciela.
6. **Etapy:** (a) workflow Pages i asset/tag/hash potwierdzone przez CI/API oraz live-check HTTP 200; (b) test wszystkich zewnętrznych linków w CI; (c) dokumentacja runtime; (d) decyzja licencyjna; (e) release checklist.
7. **Pliki:** `website/`, `README.md`, `docs/`, `.github/workflows/`.
8. **Prywatność:** strona nie deklaruje telemetrii; standardowe logi hostingu; produkt bez chmury.
9. **Testy:** anchors/assets, Vite build, link check, release hash, accessible checks.
10. **Akceptacja:** live asset tag/hash istnieje; marketing jest zgodny z ograniczeniami; licencja opisana przez właściciela.
11. **Ryzyka:** host Pages inaccessible/disabled, release missing, dependency licenses.
12. **Status:** `IN_PROGRESS` — prerelease `v0.15.19`, instalator, digest i sidecar potwierdzone; website test/lint/build PASS, Pages deployment zakończony sukcesem (Actions run `39439950410`). Windows validation `39439950267` oraz installer build/self-test/release `39440093224` PASS. Bezpośredni live-check z tej sesji zablokowała sieć sandboxa. Automatyczne sprawdzanie zewnętrznych linków, licencja i test czystego Windows pozostają.

