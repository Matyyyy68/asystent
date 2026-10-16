# Audyt wariantów User i Enterprise

Stan audytu: 2026-10-16, commit bazowy `b5f38cb`.

## Co działa

| Obszar | Stan i granica |
| --- | --- |
| `Sentinel.Core` | Wspólny, niezależny od Windows rdzeń: regułowa analiza PL/EN, offline PSL/URL, maskowanie, ograniczony kolektor, SQLite/retencja/eksport/kopia. Nie wymaga HTTP, serwera ani konta. |
| `Sentinel.Desktop` | WPF x64 dla Windows 10/11; tray, ręczna analiza i opcjonalna analiza przy zmianie aktywnego okna. Nie jest filtrem sieciowym, antywirusem ani monitoringiem ekranowym. |
| LocalStore / wiedza lokalna | Historia i ustawienia pozostają w `sentinel.db`; osobny `knowledge.db` ma wersjonowane FTS5, import TXT/MD/DOCX, fragmentację, wyszukiwanie testowe, usuwanie i kopię. To lokalne wyszukiwanie pełnotekstowe, bez embeddingów. |
| Server API | ASP.NET Core + SQLite, HTTPS poza loopback, bootstrap administratora, sesje/role/audyt, zaproszenia i tożsamości urządzeń, heartbeat, grupy/polityki, ograniczone zdarzenia, centralne FTS5 i loopback Ollama z endpointem analizy wymagającym zgody. Hostuje panel admin. |
| Installer | NSIS x64, samodzielna instalacja per-user Windows 10/11, runtime w paczce, mutex, hash payloadu, wybór profilu User/EnterpriseClient i re-install. Odinstalowanie pyta o usunięcie znanych plików bazy. Nie instaluje Enterprise Server ani usługi. |

## Braki wykryte w kodzie

- Klient i serwer mają provider Ollama loopback; serwer udostępnia konfigurację, wykrywanie modeli, syntetyczny test i endpoint analizy agenta. Ollama musi być wcześniej zainstalowane; nie ma katalogu kompatybilnych modeli, aktualizatora ani procesu pobierania. Nie można wiarygodnie dobierać modelu na podstawie GPU/RAM/backendu.
- Lokalne i centralne bazy wiedzy obsługują import TXT/MD/DOCX oraz FTS5. Panel serwera pozwala importować, wyszukiwać i usuwać dokumenty. Nie obsługują PDF ani embeddingów/semantycznego wyszukiwania; centralne wersjonowanie źródeł i przywracanie kopii pozostają brakujące. Administrator systemu może pobrać audytowaną kopię bazy SQLite, której integralność jest sprawdzana przy tworzeniu.
- Klient Enterprise paruje się przez HTTPS, przechowuje token w DPAPI, pobiera wersjonowaną politykę, synchronizuje minimalne metadane w tle z retry/backoff/jitter i stosuje interwał analizy, wykluczenia aplikacji oraz poziom powiadomień. Tryb serwerowy nie wysyła treści bez jawnej zgody. Nadal brakuje automatycznej analizy serwerowej, wyboru kategorii zdarzeń oraz centralnego statusu zgodności.
- Przywracanie serwerowej bazy działa jako narzędzie offline `scripts/restore-server-backup.py`: wymaga jawnych flag potwierdzenia zatrzymania i podmiany, waliduje schemat/integralność, robi kopię aktualnej bazy, a następnie podmienia plik atomowo. Operator musi zatrzymać proces serwera przed wywołaniem.
- API przyjmuje politykę i metadane, a analizę kontekstu wyłącznie po jawnym potwierdzeniu agenta i zezwoleniu polityki. Nie ma ręcznej akceptacji, rotacji poświadczeń, przywracania kopii, raportowania wersji zgodności ani API diagnostyki hosta.
- Brak usługi Windows, ACL/configuration bootstrap serwera i instalatora Enterprise Server. API uruchamia się jako proces konsolowy; jego aktualny bootstrap hasła nie jest mechanizmem produkcyjnego instalatora usługi.
- Instalator ma strony MUI NSIS ze zmienioną paletą/tekstem i wyborem profilu; nie jest aplikacją WPF. Instalacja Enterprise Server/usługi i jej bootstrap są nadal niedostępne.
- Sprzęt jest odczytywany lokalnie przez standardowe API/registry; adaptery raportują nazwę, ale nie VRAM/backend/sterownik. NPU jest jawnie unknown. Nie skanujemy plików, skrzynek, cookies ani historii przeglądarki. Inne programy ochronne są wykrywane heurystycznie wyłącznie z rejestru uninstall i lista nie jest pełna.
- Nie istnieje tryb/priorytet, który mógłby bezpiecznie zmienić poziom modelowej analizy. Obecne rekomendowanie wybiera wyłącznie zaimplementowaną analizę lokalną i nie wymyśla profilu modelu.

## Architektura i reguły konfiguracji

`Sentinel.Core` pozostaje wspólny dla User i EnterpriseClient. Instalacyjna tożsamość znajduje się oddzielnie od preferencji w tabeli `installation_profile`, jest walidowana i ustawiana wyłącznie przy pierwszej inicjalizacji. Aktualizacja nie nadpisuje wariantu wartością z argumentów instalatora. Adres Enterprise, jeśli podany, musi być HTTPS, bez userinfo, query i ścieżki. Hasła, kody zaproszeń i sekrety nie są argumentami procesu ani profilem instalacji.

`ConfigurationRecommendationEngine` jest deterministyczny i opiera się tylko na istniejących funkcjach. Dla User zaleca lokalne reguły i FTS5 offline, z opcjonalnym, uprzednio zainstalowanym Ollama loopback. Model AI nie jest wymagany do podstawowej analizy. Dla EnterpriseClient lokalne reguły pozostają trybem awaryjnym; klient egzekwuje bezpieczne ograniczenia polityki i przekazuje minimalne metadane w tle. Adapter GPU nie jest utożsamiany ze zgodnością modelu. UI pokazuje lokalne modele i testuje rzeczywiste zapytanie, ale nie dobiera modelu sprzętowo ani go nie pobiera.

## Plan wdrożenia

1. **Zaimplementowano:** profile wariantu, diagnostykę, deterministyczną konfigurację, osobną lokalną bazę FTS5 dla TXT/MD/DOCX, lokalny Ollama provider z walidacją odpowiedzi i fallback regułowy, testy i dokumentację.
2. **Następne:** PDF, lokalny runtime wbudowany lub katalog kompatybilności modeli, wiarygodne wymagania pamięci oraz wyszukiwanie semantyczne/embeddingi.
3. **Częściowo wdrożone:** parowanie Enterprise przez HTTPS, token DPAPI, pobieranie i egzekwowanie ograniczonej polityki, lokalna kolejka oraz synchronizacja metadanych i heartbeat w tle z retry/backoff/jitter. **Następne:** jawna zgoda na analizę serwerową z UI agenta, kategorie zdarzeń, diagnostyka i rotacja.
4. **Częściowo wdrożone:** serwerowy loopback Ollama, centralne FTS5, limity czasu, test modelu, analiza agenta z bramką zgody i tworzenie/przywracanie kopii bazy. **Następne:** limity współbieżności, PDF/embeddingi, rotacja i wersje/zgodność.
5. **Następne:** Enterprise Server/service package; dla obecnego instalatora pozostaje dopracowanie pełnego własnego wizardu, wymagań, postępu, naprawy i natywnych scenariuszy Windows. Wymaga bezpiecznego bootstrapu sekretów usługi.

Etapów 2–5 nie oznaczamy jako dostarczonych, dopóki nie ma rzeczywistych komponentów, testów scenariuszy oraz binariów, które je zawierają.
