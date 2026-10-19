# PLAN-005 — lokalne AI i baza wiedzy

1. **Cel:** aktywna aplikacja używa opcjonalnie istniejącego Ollama provider i lokalnej FTS5 KB po jawnym kliknięciu.
2. **Stan obecny:** `AIProviders.cs` ma loopback allowlist, limity, prompt-injection guard, JSON validation i fallback; `LocalKnowledgeBase` importuje TXT/MD/DOCX. Engine/UI raportują AI wyłączone i nie wystawiają KB.
3. **Braki:** API/UI wyboru modelu/opt-in/testu, KB import/search/delete, kontrola errorów, dokładne cytowania, wzmianka, że model jest nieskalibrowany.
4. **Decyzje:** wyłącznie loopback; model nigdy nie uruchamia narzędzi; analiza pozostaje regułowa przy awarii; import wybierany przez usera; nie claimować embedding/RAG semantycznego.
5. **Zależności:** endpointy allowlist w Electron, ustawienia `LocalStore`, API KB, Ollama zainstalowane.
6. **Etapy:** (a) engine metody `aiModels/aiTest`; (b) ustawienia endpoint/model i opt-in; (c) analysis orchestrator; (d) `chooseKnowledgeFile/list/search/delete`; (e) UI status i uncertainty; (f) smoke/mock.
7. **Pliki:** `Sentinel.Engine/Program.cs`, `desktop/electron/main.cjs`, preload typy, `desktop/src/main.tsx`, Core tests.
8. **Prywatność:** dane zostają na loopback; tylko treść podana do analizy; osobne potwierdzenie modelu; redakcja; KB tylko lokalna.
9. **Testy:** mock HTTP test (response/timeout/invalid/schema), provider settings, KB import/delete/limit, IPC allowlist, brak Ollama i fallback.
10. **Akceptacja:** UI nie nazywa AI aktywnym bez modelu; `UseLocalAI=false` domyślnie; wynik ma niepewność/source; bez chmury.
11. **Ryzyka:** lokalny model może halucynować; model może mieć obciążenie/odmowę; FTS5 nie jest semantyczne.
12. **Status:** `IN_PROGRESS` — aktywny klient ma lokalny import TXT/MD/DOCX, listę, wyszukiwanie FTS5 z nazwą źródła i numerem fragmentu oraz usuwanie przez ograniczone IPC. UI może sprawdzić modele Ollama pod loopbackiem i jawnie włączyć provider; silnik używa AnalysisOrchestrator, a awaria wraca do reguł. Treści nie wchodzą do event history. Brak testów integracyjnych UI i weryfikacji na rzeczywiście zainstalowanym Ollama/modelu.

