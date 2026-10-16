# Audyt wariantów User i Enterprise

Stan audytu: 2026-10-16, commit bazowy `b5f38cb`.

## Co działa

| Obszar | Stan i granica |
| --- | --- |
| `Sentinel.Core` | Wspólny, niezależny od Windows rdzeń: regułowa analiza PL/EN, offline PSL/URL, maskowanie, ograniczony kolektor, SQLite/retencja/eksport/kopia. Nie wymaga HTTP, serwera ani konta. |
| `Sentinel.Desktop` | WPF x64 dla Windows 10/11; tray, ręczna analiza i opcjonalna analiza przy zmianie aktywnego okna. Nie jest filtrem sieciowym, antywirusem ani monitoringiem ekranowym. |
| LocalStore | SQLite v1 → v2 zachowuje ustawienia i historię. FTS5 istnieje jako pusty schemat; nie ma importu, embeddingów ani wyszukiwania RAG. |
| Server API | ASP.NET Core + SQLite, HTTPS poza loopback, bootstrap administratora, sesje/role/audyt, zaproszenia i tożsamości urządzeń, heartbeat, grupy/polityki oraz ograniczone zdarzenia. Hostuje panel admin. |
| Installer | NSIS x64, samodzielna instalacja per-user Windows 10/11, runtime w paczce, mutex, hash payloadu, wybór profilu User/EnterpriseClient i re-install. Odinstalowanie pyta o usunięcie znanych plików bazy. Nie instaluje Enterprise Server ani usługi. |

## Braki wykryte w kodzie

- Nie ma lokalnego ani serwerowego `IAIProvider`, katalogu kompatybilnych modeli, backendu inferencji, katalogu modeli, aktualizatora ani procesu pobierania. Nie można zatem dobierać modelu na podstawie GPU/RAM/backendu ani podawać rozmiaru wiarygodnego modelu.
- Nie ma importu dokumentów, parsera, embeddingów ani indeksu RAG. Tabela FTS5 nie jest działającą bazą wiedzy.
- Klient nie rejestruje się w Enterprise, nie przechowuje poświadczenia urządzenia, nie pobiera polityki, nie ma offline queue i nie wysyła metadanych zdarzeń.
- API przyjmuje politykę i metadane, ale nie ma ręcznej akceptacji, rotacji poświadczeń, backup/restore, raportowania wersji zgodności ani API diagnostyki hosta.
- Brak usługi Windows, ACL/configuration bootstrap serwera i instalatora Enterprise Server. API uruchamia się jako proces konsolowy; jego aktualny bootstrap hasła nie jest mechanizmem produkcyjnego instalatora usługi.
- Instalator ma strony MUI NSIS ze zmienioną paletą/tekstem i wyborem profilu; nie jest aplikacją WPF. Instalacja Enterprise Server/usługi i jej bootstrap są nadal niedostępne.
- Sprzęt jest odczytywany lokalnie przez standardowe API/registry; adaptery raportują nazwę, ale nie VRAM/backend/sterownik. NPU jest jawnie unknown. Nie skanujemy plików, skrzynek, cookies ani historii przeglądarki. Inne programy ochronne są wykrywane heurystycznie wyłącznie z rejestru uninstall i lista nie jest pełna.
- Nie istnieje tryb/priorytet, który mógłby bezpiecznie zmienić poziom modelowej analizy. Obecne rekomendowanie wybiera wyłącznie zaimplementowaną analizę lokalną i nie wymyśla profilu modelu.

## Architektura i reguły konfiguracji

`Sentinel.Core` pozostaje wspólny dla User i EnterpriseClient. Instalacyjna tożsamość znajduje się oddzielnie od preferencji w tabeli `installation_profile`, jest walidowana i ustawiana wyłącznie przy pierwszej inicjalizacji. Aktualizacja nie nadpisuje wariantu wartością z argumentów instalatora. Adres Enterprise, jeśli podany, musi być HTTPS, bez userinfo, query i ścieżki. Hasła, kody zaproszeń i sekrety nie są argumentami procesu ani profilem instalacji.

`ConfigurationRecommendationEngine` jest deterministyczny i opiera się tylko na istniejącym katalogu funkcji. Dla User zaleca lokalne reguły + SQLite, z analizą podstawową offline. Dla EnterpriseClient zachowuje lokalne reguły jako tryb awaryjny i jawnie oznacza brak rejestracji/synchronizacji. Adaptery GPU nie są utożsamiane ze zgodnością obliczeniową. Dopóki brak modelu/backendu, UI nie oferuje fikcyjnych poziomów modelu ani pobierania.

## Plan wdrożenia

1. **Zaimplementowano teraz:** profil wariantu, walidację adresu, migrację SQLite v1→v2, lokalny odczyt sprzętu Windows, rekomendację deterministyczną, samo-test reguł, testy round-trip i dokumentację manualną.
2. **Następne:** prawdziwy katalog/model runtime i prywatny lokalny RAG dla User; przetestowany backend, formaty, wymagania pamięci, źródła i pobieranie za zgodą.
3. **Następne:** agent Enterprise z DPAPI/Credential Manager, HTTPS enrollment, pobieraniem/walidacją polityki, ograniczonym retry queue i jawnie dozwolonymi metadanymi. Lokalne reguły pozostają niezależne od połączenia.
4. **Następne:** serwerowy provider AI i RAG, limity/timeouty/health, indeks źródeł, backup/restore, rotacja, wersje/zgodność.
5. **Następne:** Enterprise Server/service package; dla obecnego instalatora pozostaje dopracowanie pełnego własnego wizardu, wymagań, postępu, naprawy i natywnych scenariuszy Windows. Wymaga bezpiecznego bootstrapu sekretów usługi.

Etapów 2–5 nie oznaczamy jako dostarczonych, dopóki nie ma rzeczywistych komponentów, testów scenariuszy oraz binariów, które je zawierają.
