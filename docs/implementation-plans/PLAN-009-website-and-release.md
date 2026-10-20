# PLAN-009 — witryna, dokumentacja i wydanie

1. **Cel:** publikowane opisy, download i docs dokładnie odpowiadają testowanym możliwościom.
2. **Stan obecny:** `website/` statyczne; tekst jasno mówi o wersji rozwojowej, DNS cache, braku blokowania i AI. GitHub Actions opublikował prerelease `v0.15.15` (262509685 B, SHA-256 `2735afde7a3ee51044eab8afbc5c96567686836c27ce2e364bf2c147e96b1beb`). Audyt wykrył, że HTML wskazywał v0.15.13 mimo nowszych wydań; linki zostały zaktualizowane do v0.15.15, a test zgodności URL-i z wersją pakietu chroni przed rozjazdem. Deployment i live URL tej aktualizacji jeszcze nie zostały sprawdzone.
3. **Braki:** automatyczne sprawdzanie dostępności zewnętrznych linków w CI, dokument licencji, Enterprise install docs/clean Windows docs.
4. **Decyzje:** każda obietnica ma test/evidence; status live zależy od CI i ustawień Pages; nie wymyślać licencji.
5. **Zależności:** GitHub Pages, tag/release asset, decyzja właściciela.
6. **Etapy:** (a) workflow Pages i asset/tag/hash potwierdzone przez CI/API oraz live-check HTTP 200; (b) test wszystkich zewnętrznych linków w CI; (c) dokumentacja runtime; (d) decyzja licencyjna; (e) release checklist.
7. **Pliki:** `website/`, `README.md`, `docs/`, `.github/workflows/`.
8. **Prywatność:** strona nie deklaruje telemetrii; standardowe logi hostingu; produkt bez chmury.
9. **Testy:** anchors/assets, Vite build, link check, release hash, accessible checks.
10. **Akceptacja:** live asset tag/hash istnieje; marketing jest zgodny z ograniczeniami; licencja opisana przez właściciela.
11. **Ryzyka:** host Pages inaccessible/disabled, release missing, dependency licenses.
12. **Status:** `IN_PROGRESS` — prerelease `v0.15.15`, instalator i digest potwierdzone przez GitHub API; nowe linki v0.15.15 wymagają testów/lint/build, Pages deploy oraz live-check. Automatyczne sprawdzanie zewnętrznych linków, licencja i test czystego Windows pozostają.

