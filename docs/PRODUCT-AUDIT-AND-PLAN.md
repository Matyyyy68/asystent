> Dokument historyczny wersji WPF 0.13. Aktualny klient i instrukcje: README.md oraz docs/USER-VALIDATION.md.

# Audyt wariantów User i Enterprise

Stan audytu: 2026-10-16, commit bazowy `b5f38cb`.

Aktualizacja stanu 2026-10-24: od czasu audytu bazowego dodano w kliencie pełne, opcjonalne wyszukiwanie semantyczne wszystkich fragmentów przez lokalny model embeddingowy Ollama, niezależnie od kandydatów FTS5. FTS5 pozostaje trybem domyślnym i ścieżką awaryjną. Panel Enterprise otrzymał osobną akcję semantyczną dla administratorów bezpieczeństwa/systemu, wymagającą jawnego potwierdzenia przesłania fragmentów do lokalnego Ollama. Testy syntetyczne i loopback API E2E z atrapą modelu przechodzą; nie wykonano walidacji na działającym modelu ani reprezentatywnej bazie. Równoległe wyszukiwanie, import, usuwanie i przywracanie są serializowane w ramach instancji `LocalKnowledgeBase`, z testami regresyjnymi na wyścigi cache i osierocone wektory. Poniższe historyczne tabele opisują stan z 2026-10-16; aktualny status luk i walidacji znajduje się w [IMPLEMENTATION_GAP_ANALYSIS.md](IMPLEMENTATION_GAP_ANALYSIS.md), [PROJECT_PROGRESS.md](PROJECT_PROGRESS.md) i [KNOWN-LIMITATIONS.md](KNOWN-LIMITATIONS.md).

Uzupełnienie stanu klienta po wydaniu 0.13.0: pierwszy przepływ Edge/Chrome przez rozszerzenie MV3, host Native Messaging, lokalne heurystyki URL, lokalne zdarzenia i status kontaktu opisano w [BROWSER-INTEGRATION.md](BROWSER-INTEGRATION.md). Integracja nie ma jeszcze feedu reputacji, gwarantowanej blokady ani dystrybucji sklepowej; nie oznacza to ukończenia docelowej ochrony przeglądania.

## Co działa

| Obszar | Stan i granica |
| --- | --- |
| `Sentinel.Core` | Wspólny, niezależny od Windows rdzeń: regułowa analiza PL/EN, offline PSL/URL, maskowanie, ograniczony kolektor, SQLite/retencja/eksport/kopia. Nie wymaga HTTP, serwera ani konta. |
| Aktywny klient desktopowy | `desktop/`: React/TypeScript w Electronie x64, sandboxowany preload i ograniczone IPC; osobny proces .NET 10 (`Sentinel.Engine`) wykonuje analizę i zapis SQLite. WPF pozostał w `legacy/` i nie należy do wspieranego buildu. Nie jest filtrem sieciowym, antywirusem ani monitoringiem ekranowym. |
| LocalStore / wiedza lokalna | Historia i ustawienia pozostają w `sentinel.db`; osobny `knowledge.db` ma wersjonowane FTS5, import TXT/MD/DOCX oraz tekstowych PDF (limit 10 MB, 500 stron, 2 mln znaków; bez OCR), fragmentację, wyszukiwanie, usuwanie i kopię. Dodatkowo opcjonalne wyszukiwanie semantyczne przeszukuje embeddingi wszystkich fragmentów; jego jakość i działanie z rzeczywistym modelem wymagają dalszej weryfikacji. |
| Server API | ASP.NET Core + SQLite, HTTPS poza loopback, bootstrap administratora, sesje/role/audyt, zaproszenia i tożsamości urządzeń, heartbeat, grupy/polityki, ograniczone zdarzenia, centralne FTS5 i loopback Ollama z endpointem analizy wymagającym zgody. Hostuje panel admin. |
| Installer | Klient User: własny kreator WinForms x64 (`installer/Sentinel.Setup`), pojedynczy EXE z osadzonym payloadem, instalacja per-user, weryfikacja i zachowanie danych. Enterprise Server: osobny pakiet NSIS/self-contained x64, skrypty usługi Windows, bootstrap i kontrola `/readyz`; brak kreatora TLS/firewall i natywnego testu wdrożenia na Windows Server. |

## Braki wykryte w kodzie

- Klient i serwer mają provider Ollama loopback; serwer udostępnia konfigurację, wykrywanie modeli, syntetyczny test i endpoint analizy agenta. Ollama musi być wcześniej zainstalowane; nie ma katalogu kompatybilnych modeli, aktualizatora ani procesu pobierania. Nie można wiarygodnie dobierać modelu na podstawie GPU/RAM/backendu.
- Lokalne i centralne bazy wiedzy obsługują import TXT/MD/DOCX oraz tekstowych PDF (limit 10 MB, 500 stron, 2 mln znaków; bez OCR) przez wspólny `LocalKnowledgeBase` i FTS5. Panel serwera pozwala importować, wyszukiwać i usuwać dokumenty. Opcjonalne wyszukiwanie semantyczne embeddingami obejmuje wszystkie fragmenty; ma testy jednostkowe i loopback E2E z atrapą Ollama, lecz nie zostało sprawdzone z rzeczywistym modelem ani reprezentatywną bazą. Centralne wersjonowanie źródeł i przywracanie kopii pozostają brakujące. Administrator systemu może pobrać audytowaną kopię bazy SQLite, której integralność jest sprawdzana przy tworzeniu.
- Klient Enterprise paruje się przez HTTPS, przechowuje token w DPAPI, pobiera wersjonowaną politykę, synchronizuje minimalne metadane w tle z retry/backoff/jitter i stosuje interwał analizy, wykluczenia aplikacji oraz poziom powiadomień. Po zastosowaniu ustawień raportuje wersję polityki globalnej, grupowej i urządzenia; panel porównuje je z aktualnym stanem. Tryb serwerowy nie wysyła treści bez jawnej zgody. Nadal brakuje automatycznej analizy serwerowej; panel otrzymał ograniczoną diagnostykę procesu i bazy dla administratora systemu, bez logów i ustawień wdrożenia.
- Przywracanie serwerowej bazy działa jako narzędzie offline `scripts/restore-server-backup.py`: wymaga jawnych flag potwierdzenia zatrzymania i podmiany, waliduje schemat/integralność, robi kopię aktualnej bazy, a następnie podmienia plik atomowo. Operator musi zatrzymać proces serwera przed wywołaniem.
- API przyjmuje politykę i metadane, a analizę kontekstu wyłącznie po jawnym potwierdzeniu agenta i zezwoleniu polityki. Zaproszenia mogą wymagać ręcznej akceptacji, a odrzucenie urządzenia unieważnia token. Rotacja poświadczeń jest dwuetapowa: nowy token jest najpierw przygotowywany, a stary działa do pierwszego uwierzytelnionego użycia nowego. Raportowanie zgodności wersji polityki oraz ograniczony, tylko dla administratora systemu endpoint diagnostyczny są wdrożone; pełne logi hosta, konfiguracja wdrożenia i certyfikaty pozostają poza panelem.
- API integruje Windows Service Control Manager; instalator tworzy usługę na wirtualnym koncie serwisowym, ACL katalogu danych, restart po awarii i interaktywny bootstrap administratora. Brakuje kreatora TLS/firewall, natywnego testu usługi na Windows Server i bezpiecznej konfiguracji dostępu z LAN.
- Instalator klienta jest własnym kreatorem WinForms, a pakiet serwera Enterprise korzysta z NSIS i skryptów usługi Windows; instalatora klienta nie należy opisywać jako NSIS. Brakuje kreatora TLS/firewall i natywnego scenariusza wdrożenia na Windows Server.
- Sprzęt jest odczytywany lokalnie przez standardowe API/registry; adaptery raportują nazwę, ale nie VRAM/backend/sterownik. NPU jest jawnie unknown. Nie skanujemy plików, skrzynek, cookies ani historii przeglądarki. Inne programy ochronne są wykrywane heurystycznie wyłącznie z rejestru uninstall i lista nie jest pełna.
- Nie istnieje tryb/priorytet, który mógłby bezpiecznie zmienić poziom modelowej analizy. Obecne rekomendowanie wybiera wyłącznie zaimplementowaną analizę lokalną i nie wymyśla profilu modelu.

## Architektura i reguły konfiguracji

`Sentinel.Core` pozostaje wspólny dla User i EnterpriseClient. Instalacyjna tożsamość znajduje się oddzielnie od preferencji w tabeli `installation_profile`, jest walidowana i ustawiana wyłącznie przy pierwszej inicjalizacji. Aktualizacja nie nadpisuje wariantu wartością z argumentów instalatora. Adres Enterprise, jeśli podany, musi być HTTPS, bez userinfo, query i ścieżki. Hasła, kody zaproszeń i sekrety nie są argumentami procesu ani profilem instalacji.

`ConfigurationRecommendationEngine` jest deterministyczny i opiera się tylko na istniejących funkcjach. Dla User zaleca lokalne reguły i FTS5 offline, z opcjonalnym, uprzednio zainstalowanym Ollama loopback. Model AI nie jest wymagany do podstawowej analizy. Dla EnterpriseClient lokalne reguły pozostają trybem awaryjnym; klient egzekwuje bezpieczne ograniczenia polityki i przekazuje minimalne metadane w tle. Adapter GPU nie jest utożsamiany ze zgodnością modelu. UI pokazuje lokalne modele i testuje rzeczywiste zapytanie, ale nie dobiera modelu sprzętowo ani go nie pobiera.

## Plan wdrożenia

1. **Zaimplementowano:** profile wariantu, diagnostykę, deterministyczną konfigurację, osobną bazę FTS5 dla TXT/MD/DOCX i tekstowych PDF, lokalny Ollama provider z walidacją odpowiedzi i fallback regułowy, opcjonalny reranking embeddingami oraz testy.
2. **Następne:** OCR zeskanowanych PDF, lokalny runtime wbudowany lub katalog kompatybilności modeli, wiarygodne wymagania pamięci oraz pełne wyszukiwanie semantyczne poza kandydatami FTS5.
3. **Częściowo wdrożone:** parowanie Enterprise przez HTTPS, token DPAPI, pobieranie i egzekwowanie ograniczonej polityki, lokalna kolejka, synchronizacja w tle z retry/backoff/jitter, ręczna akceptacja i rotacja poświadczeń oraz raport zgodności wersji zastosowanej polityki. **Następne:** UI agenta do jawnej analizy serwerowej i diagnostyka hosta.
4. **Częściowo wdrożone:** serwerowy loopback Ollama, centralne FTS5 dla TXT/MD/DOCX i tekstowych PDF, limity czasu, test modelu, analiza agenta z bramką zgody i tworzenie/przywracanie kopii bazy. **Następne:** OCR i embeddingi poza kandydatami FTS5, limity współbieżności oraz wersje źródeł/zgodności.
5. **Częściowo wdrożone:** graficzny instalator Windows Server, API jako Windows Service, self-contained pakiet oraz kopie/odtwarzanie. **Następne:** kreator TLS/firewall, aktualizacja/rollback wersji oraz natywne scenariusze Windows Server.

Etapów 2–5 nie oznaczamy jako dostarczonych, dopóki nie ma rzeczywistych komponentów, testów scenariuszy oraz binariów, które je zawierają.
