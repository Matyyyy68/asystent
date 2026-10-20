# PLAN-009 — witryna, dokumentacja i wydanie

1. **Cel:** publikowane opisy, download i docs dokładnie odpowiadają testowanym możliwościom.
2. **Stan obecny:** `website/` statyczne; tekst jasno mówi o wersji rozwojowej, DNS cache, braku blokowania i AI. GitHub Actions opublikował prerelease `v0.15.16` (262514293 B, SHA-256 `abff53d5f71d4f7edb30f9b939d48e6f81900d99c3dc5680353f22115322f7c6`). HTML/linki zostały zaktualizowane z v0.15.13 przez v0.15.15 do v0.15.16, a test zgodności URL-i z wersją pakietu chroni przed rozjazdem. Test/lint/build lokalnie PASS; Pages deployment dla commita `8da118e` zakończył się sukcesem w runie `39429650994`. Live HTTP check nieosiągalny w tej sesji z powodu blokady połączeń sieciowych sandboxa.
3. **Braki:** automatyczne sprawdzanie dostępności zewnętrznych linków w CI, dokument licencji, Enterprise install docs/clean Windows docs.
4. **Decyzje:** każda obietnica ma test/evidence; status live zależy od CI i ustawień Pages; nie wymyślać licencji.
5. **Zależności:** GitHub Pages, tag/release asset, decyzja właściciela.
6. **Etapy:** (a) workflow Pages i asset/tag/hash potwierdzone przez CI/API oraz live-check HTTP 200; (b) test wszystkich zewnętrznych linków w CI; (c) dokumentacja runtime; (d) decyzja licencyjna; (e) release checklist.
7. **Pliki:** `website/`, `README.md`, `docs/`, `.github/workflows/`.
8. **Prywatność:** strona nie deklaruje telemetrii; standardowe logi hostingu; produkt bez chmury.
9. **Testy:** anchors/assets, Vite build, link check, release hash, accessible checks.
10. **Akceptacja:** live asset tag/hash istnieje; marketing jest zgodny z ograniczeniami; licencja opisana przez właściciela.
11. **Ryzyka:** host Pages inaccessible/disabled, release missing, dependency licenses.
12. **Status:** `IN_PROGRESS` — prerelease `v0.15.16`, instalator i digest potwierdzone przez GitHub API; test/lint/build lokalnie PASS, Pages deployment dla v0.15.16 zakończony sukcesem (Actions run `39429650994`). Dodano walidację aplikacji na Windows dla push/PR; pełny `scripts/build-user.ps1` PASS w runie `39430405871`. Bezpośredni live-check z tej sesji zablokowała sieć sandboxa. Automatyczne sprawdzanie zewnętrznych linków, licencja i test czystego Windows pozostają.

