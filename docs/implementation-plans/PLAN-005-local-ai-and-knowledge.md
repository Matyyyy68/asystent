# PLAN-005 — lokalne AI i baza wiedzy

1. **Cel:** aktywna aplikacja używa opcjonalnie istniejącego Ollama provider i lokalnej FTS5 KB po jawnym kliknięciu.
2. **Stan obecny:** `AIProviders.cs` ma loopback allowlist, limity, prompt-injection guard, JSON validation i fallback; `LocalKnowledgeBase` importuje TXT/MD/DOCX. Aktywne Engine/UI udostępniają listę modeli, jawne opt-in, import/search/delete KB, a `AnalysisOrchestrator` przekazuje trafienia FTS5 do modelu jako niezaufany kontekst.
3. **Braki:** embeddingi i semantyczny ranking, pomiar trafności źródeł, testy UI i weryfikacja rzeczywistego modelu; provenance źródeł w odpowiedzi modelu jest ograniczone do nazw w niepewnościach, nie do cytatów powiązanych z twierdzeniami.
4. **Decyzje:** wyłącznie loopback; model nigdy nie uruchamia narzędzi; analiza pozostaje regułowa przy awarii; import wybierany przez usera; nie claimować embedding/RAG semantycznego.
5. **Zależności:** endpointy allowlist w Electron, ustawienia `LocalStore`, API KB, Ollama zainstalowane.
6. **Etapy:** (a)–(f) — metody engine, ustawienia loopback/model/opt-in, orchestrator, IPC KB, UI status/uncertainty i testy mock — wdrożone. Dalej: (g) testy UI, (h) jawna ocena jakości wyszukiwania/cytowań, (i) weryfikacja na rzeczywistym modelu lokalnym.
7. **Pliki:** `Sentinel.Engine/Program.cs`, `desktop/electron/main.cjs`, preload typy, `desktop/src/main.tsx`, Core tests.
8. **Prywatność:** dane zostają na loopback; tylko treść podana do analizy; osobne potwierdzenie modelu; redakcja; KB tylko lokalna.
9. **Testy:** mock HTTP test (response/timeout/invalid/schema), provider settings, KB import/delete/limit, IPC allowlist, brak Ollama i fallback.
10. **Akceptacja:** UI nie nazywa AI aktywnym bez opt-in; `UseLocalAI=false` domyślnie; mock potwierdza loopback request, nieufny kontekst i fallback; odpowiedź zawiera niepewność, a trafione źródła są nazwane, lecz nie ma cytowania twierdzenie–źródło. Nie używa chmury.
11. **Ryzyka:** lokalny model może halucynować; model może mieć obciążenie/odmowę; FTS5 nie jest semantyczne.
12. **Status:** `IN_PROGRESS` — aktywny klient ma lokalny import TXT/MD/DOCX, listę, wyszukiwanie FTS5 z nazwą źródła i numerem fragmentu oraz usuwanie przez ograniczone IPC. UI może sprawdzić modele Ollama pod loopbackiem i jawnie włączyć provider; `AnalysisOrchestrator` pobiera do pięciu dopasowanych leksykalnie fragmentów i przekazuje je jako niezaufane źródła. Test integracyjny potwierdza ten przepływ. Treści nie wchodzą do event history. Brak semantycznego rankingu/embeddingów, oceny jakości, testów UI i weryfikacji na rzeczywiście zainstalowanym Ollama/modelu.

