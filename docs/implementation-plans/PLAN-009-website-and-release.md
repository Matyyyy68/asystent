# PLAN-009 — witryna, dokumentacja i wydanie

1. **Cel:** publikowane opisy, download i docs dokładnie odpowiadają testowanym możliwościom.
2. **Stan obecny:** `website/` statyczne; tekst jasno mówi o wersji rozwojowej, DNS cache, braku blokowania i AI. GitHub Actions opublikował prerelease `v0.15.13` i potwierdził asset/hash. Audyt wykrył, że HTML wskazywał v0.15.3; linki poprawiono i dodano test zgodności URL-i z wersją pakietu. Pages workflow dla `fdb22a0` PASS; live URL zwrócił HTTP 200 z instalatorem, checksumą i notkami v0.15.13.
3. **Braki:** automatyczne sprawdzanie dostępności zewnętrznych linków w CI, dokument licencji, Enterprise install docs/clean Windows docs.
4. **Decyzje:** każda obietnica ma test/evidence; status live zależy od CI i ustawień Pages; nie wymyślać licencji.
5. **Zależności:** GitHub Pages, tag/release asset, decyzja właściciela.
6. **Etapy:** (a) workflow Pages i asset/tag/hash potwierdzone przez CI/API oraz live-check HTTP 200; (b) test wszystkich zewnętrznych linków w CI; (c) dokumentacja runtime; (d) decyzja licencyjna; (e) release checklist.
7. **Pliki:** `website/`, `README.md`, `docs/`, `.github/workflows/`.
8. **Prywatność:** strona nie deklaruje telemetrii; standardowe logi hostingu; produkt bez chmury.
9. **Testy:** anchors/assets, Vite build, link check, release hash, accessible checks.
10. **Akceptacja:** live asset tag/hash istnieje; marketing jest zgodny z ograniczeniami; licencja opisana przez właściciela.
11. **Ryzyka:** host Pages inaccessible/disabled, release missing, dependency licenses.
12. **Status:** `IN_PROGRESS` — prerelease `v0.15.13`, instalator i digest potwierdzone przez GitHub API; testy/lint/build oraz Pages deploy PASS, live URL HTTP 200 zawiera aktualne linki i test blokuje rozjazd wersji. Automatyczne sprawdzanie zewnętrznych linków, licencja i test czystego Windows pozostają.

