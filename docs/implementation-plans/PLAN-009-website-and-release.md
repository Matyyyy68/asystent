# PLAN-009 — witryna, dokumentacja i wydanie

1. **Cel:** publikowane opisy, download i docs dokładnie odpowiadają testowanym możliwościom.
2. **Stan obecny:** `website/` statyczne; tekst jasno mówi o wersji rozwojowej, DNS cache i braku blokowania. Tag `v0.15.38` opublikowany. Windows CI `39489166139`, Pages `39489165920` i installer/release workflow `39489181456` PASS; asset/digest są dostępne. Wersja pakietu i linki strony wskazują v0.15.38. FAQ opisuje opcjonalne Ollama i wynik odizolowanych testów Chrome/Edge. Po poprawce website test/lint/build PASS; deployment Pages dla zmian FAQ oczekuje na push.
3. **Braki:** automatyczne sprawdzanie dostępności zewnętrznych linków w CI, dokument licencji, Enterprise install docs/clean Windows docs.
4. **Decyzje:** każda obietnica ma test/evidence; status live zależy od CI i ustawień Pages; nie wymyślać licencji.
5. **Zależności:** GitHub Pages, tag/release asset, decyzja właściciela.
6. **Etapy:** (a) workflow Pages i asset/tag/hash potwierdzone przez CI/API oraz live-check HTTP 200; (b) test wszystkich zewnętrznych linków w CI; (c) dokumentacja runtime; (d) decyzja licencyjna; (e) release checklist.
7. **Pliki:** `website/`, `README.md`, `docs/`, `.github/workflows/`.
8. **Prywatność:** strona nie deklaruje telemetrii; standardowe logi hostingu; produkt bez chmury.
9. **Testy:** anchors/assets, Vite build, link check, release hash, accessible checks.
10. **Akceptacja:** live asset tag/hash istnieje; marketing jest zgodny z ograniczeniami; licencja opisana przez właściciela.
11. **Ryzyka:** host Pages inaccessible/disabled, release missing, dependency licenses.
12. **Status:** `IN_PROGRESS` — v0.15.38: installer build/self-test/release `39489181456` PASS; asset (262559349 B, SHA-256 `bb34834eb654e450728f95093d500715b5f6ef5ab9f7825c32d146b9fb2c4cd8`) i sidecar są opublikowane. Website test/lint/build `PASS` po aktualizacji FAQ; Pages `39489165920` PASS dla poprzedniego stanu, a wdrożenie najnowszej zmiany czeka na push. Automatyczne sprawdzanie wszystkich zewnętrznych linków, licencja, live URL i test czystego Windows pozostają.

