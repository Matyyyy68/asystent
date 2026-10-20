# PLAN-009 — witryna, dokumentacja i wydanie

1. **Cel:** publikowane opisy, download i docs dokładnie odpowiadają testowanym możliwościom.
2. **Stan obecny:** `website/` statyczne; tekst jasno mówi o wersji rozwojowej, DNS cache, braku blokowania i AI. Tag `v0.15.25` opublikowany; Pages workflow `39455405535` PASS, installer/release workflow `39455410177` PASS i release asset/digest są dostępne. HTML/linki wskazują v0.15.25, a test zgodności URL-i z wersją pakietu chroni przed rozjazdem. Website test/lint/build PASS. Live HTTP check nieosiągalny w tej sesji z powodu ograniczenia środowiska.
3. **Braki:** automatyczne sprawdzanie dostępności zewnętrznych linków w CI, dokument licencji, Enterprise install docs/clean Windows docs.
4. **Decyzje:** każda obietnica ma test/evidence; status live zależy od CI i ustawień Pages; nie wymyślać licencji.
5. **Zależności:** GitHub Pages, tag/release asset, decyzja właściciela.
6. **Etapy:** (a) workflow Pages i asset/tag/hash potwierdzone przez CI/API oraz live-check HTTP 200; (b) test wszystkich zewnętrznych linków w CI; (c) dokumentacja runtime; (d) decyzja licencyjna; (e) release checklist.
7. **Pliki:** `website/`, `README.md`, `docs/`, `.github/workflows/`.
8. **Prywatność:** strona nie deklaruje telemetrii; standardowe logi hostingu; produkt bez chmury.
9. **Testy:** anchors/assets, Vite build, link check, release hash, accessible checks.
10. **Akceptacja:** live asset tag/hash istnieje; marketing jest zgodny z ograniczeniami; licencja opisana przez właściciela.
11. **Ryzyka:** host Pages inaccessible/disabled, release missing, dependency licenses.
12. **Status:** `IN_PROGRESS` — v0.15.25, Windows validation `39455405422`, installer build/self-test/release `39455410177` i Pages deployment `39455405535` PASS. Asset i digest są opublikowane. Website test/lint/build PASS. Bezpośredni live-check z tej sesji nie został wykonany. Automatyczne sprawdzanie zewnętrznych linków, licencja i test czystego Windows pozostają.

