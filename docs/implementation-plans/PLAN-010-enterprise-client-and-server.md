# PLAN-010 — Enterprise API, agent i testy operacyjne

1. **Cel:** agent Enterprise działa w aktywnym kliencie jako jawnie sparowany wariant, z minimalnym eksportem metadanych i lokalnym egzekwowaniem polityki.
2. **Stan obecny:** backend ma SQLite/RBAC/sesje/polityki/audyt/consent-gated Ollama/FTS5; serwerowe testy 19/19 i API smoke PASS. Electron ma teraz HTTPS pairing z jednorazowym invite, zgodę na metadane, token chroniony DPAPI CurrentUser, heartbeat, pobieranie polityki local i idempotentną kolejkę offline metadanych ograniczoną do 10 000 rekordów.
3. **Braki:** live TLS E2E z realnym serwerem, UI zatwierdzenia i revoke, rotacja tokenu w kliencie, polityki poza local/10–300 s, service install/restart i podpisane aktualizacje.
4. **Decyzje:** pairing jest możliwy z ekranu ustawień po HTTPS i świadomej zgodzie. Zdarzenie Enterprise v1 wysyła tylko ID/czas/kategorię/ryzyko/kod reguły/schemaVersion/allowlistowane źródło/bezpieczną wersję reguły; treść, pełny URL, nazwa aplikacji i wyjaśnienie zostają lokalne. Wyłączenie zgody zatrzymuje również heartbeat i pobieranie polityki oraz usuwa oczekujące metadane. Klient nie udostępnia kontekstu do analizy serwerowej. Nieobsługiwany tryb polityki jest odrzucany z heartbeat `configuration_invalid`.
5. **Zależności:** certyfikat CA/serwer Enterprise dla live testu, interaktywna sesja Windows z profilem DPAPI, Windows Server VM i certyfikat podpisu dla aktualizacji.
6. **Etapy:** (a) API schema i limity — wdrożone/testowane; (b) pairing, DPAPI i IPC consent — wdrożone, DPAPI test przeszedł poza sandboxem; (c) kolejka offline i deduplikacja — wdrożone/testy SQLite; (d) polityka lokalna/heartbeat — wdrożone; (e) wyłączenie zgody usuwa oczekujące metadane i blokuje wysłanie kolejki przywróconej z backupu — wdrożone/testowane; (f) TLS E2E, approval/revoke/rotation — pozostałe; (g) testy restartu i przeciążenia — pozostałe.
7. **Pliki:** `server/`, `src/Sentinel.Core/Enterprise/`, `src/Sentinel.Engine/Program.cs`, `desktop/src/main.tsx`, `desktop/electron/main.cjs`.
8. **Prywatność:** lokalny token DPAPI CurrentUser; kolejka metadanych w lokalnej SQLite tylko po zgodzie; brak tekstu, URL, nazw plików, promptów lub wyjaśnień; HTTPS obowiązkowe.
9. **Testy:** mock client, consent gate IPC, profil/queue gate i minimalny payload SQLite; pełne zestawy przechodzą 163 testy klienta i 19 testów serwera. Do wykonania: live TLS, rotate/revoke, offline/restart, test operacyjny serwera.
10. **Akceptacja:** pairing, restart klienta, pobranie polityki, heartbeat, batch z deduplikacją, offline retry, revoke i dowód braku wysyłki treści; nieosiągnięte do czasu live E2E.
11. **Ryzyka:** dystrybucja certyfikatów, dostępność serwera, approval wymagający portalu admina, DPAPI zależne od profilu zalogowanego użytkownika.
12. **Status:** `IN_PROGRESS` — aktywne ścieżki klienta są wdrożone i testowane; operacyjny E2E z prawdziwym TLS oraz revoke nadal wymagają środowiska serwera i pozostają do wykonania.

