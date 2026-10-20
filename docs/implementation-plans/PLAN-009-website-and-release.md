# PLAN-009 — witryna, dokumentacja i wydanie

1. **Cel:** publikowane opisy, download i docs dokładnie odpowiadają testowanym możliwościom.
2. **Stan obecny:** `website/` statyczne; tekst jasno mówi o wersji rozwojowej, DNS cache, braku blokowania i AI. GitHub Actions opublikował prerelease `v0.15.20` (262521973 B, SHA-256 `0c2236a48806817fb2fd8fcdf1e7f3b2c62128042860ec11ce387edb77a87f1d`). HTML/linki wskazują v0.15.20, a test zgodności URL-i z wersją pakietu chroni przed rozjazdem. Website test/lint/build PASS; Pages deployment commita `c170550` zakończył się sukcesem w runie `39441943558`. Live HTTP check nieosiągalny w tej sesji z powodu blokady połączeń sieciowych sandboxa.
3. **Braki:** automatyczne sprawdzanie dostępności zewnętrznych linków w CI, dokument licencji, Enterprise install docs/clean Windows docs.
4. **Decyzje:** każda obietnica ma test/evidence; status live zależy od CI i ustawień Pages; nie wymyślać licencji.
5. **Zależności:** GitHub Pages, tag/release asset, decyzja właściciela.
6. **Etapy:** (a) workflow Pages i asset/tag/hash potwierdzone przez CI/API oraz live-check HTTP 200; (b) test wszystkich zewnętrznych linków w CI; (c) dokumentacja runtime; (d) decyzja licencyjna; (e) release checklist.
7. **Pliki:** `website/`, `README.md`, `docs/`, `.github/workflows/`.
8. **Prywatność:** strona nie deklaruje telemetrii; standardowe logi hostingu; produkt bez chmury.
9. **Testy:** anchors/assets, Vite build, link check, release hash, accessible checks.
10. **Akceptacja:** live asset tag/hash istnieje; marketing jest zgodny z ograniczeniami; licencja opisana przez właściciela.
11. **Ryzyka:** host Pages inaccessible/disabled, release missing, dependency licenses.
12. **Status:** `IN_PROGRESS` — prerelease `v0.15.20`, instalator, digest i sidecar potwierdzone; website test/lint/build PASS, Pages deployment zakończony sukcesem (Actions run `39441943558`). Windows validation `39441943631` oraz installer build/self-test/release `39441965987` PASS. Bezpośredni live-check z tej sesji zablokowała sieć sandboxa. Automatyczne sprawdzanie zewnętrznych linków, licencja i test czystego Windows pozostają.

