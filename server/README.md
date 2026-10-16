# Sentinel AI Server — etapy A, B1, B2a i B2b (częściowo)

Wersja API i aplikacji jest wspólna z klientem i pochodzi z `eng/ProductVersion.props`; endpoint `/readyz` zwraca wersję uruchomionego serwera.

Serwer jest odrębnym projektem w `server/`; istniejący klient WPF i jego reguły pozostają bez zmian. Wymagany jest .NET SDK 10.0.402.

Panel `/admin/` ma centralną bazę FTS5 i konfigurację/test lokalnego Ollama na loopback serwera. Zainstalowane modele są wykrywane z API Ollama; instalator nie pobiera modeli. Administrator systemu może wykonać syntetyczny test. Analiza agentów wymaga jednocześnie polityki `includeContext=true`, providera `ollama` i potwierdzenia w żądaniu; surowy kontekst nie jest utrwalany na serwerze. Bez skonfigurowanego modelu serwer zwraca analizę regułową.

## Uruchomienie lokalne

Z katalogu głównego repozytorium:

```powershell
$env:Sentinel__DataDirectory = "$env:ProgramData\SentinelAI\Server"
dotnet run --project server/src/Sentinel.Server.Api/Sentinel.Server.Api.csproj
```

Bez zmiennych konfiguracyjnych API nasłuchuje wyłącznie na `http://127.0.0.1:5080`. Katalog danych domyślnie znajduje się w `%ProgramData%\SentinelAI\Server` na Windows i `/var/lib/sentinel-ai/server` na Linux. Konto procesu musi mieć prawo zapisu do tego katalogu. Lokalny serwer nie ma jeszcze instalatora ani usługi Windows.

Przy pierwszym uruchomieniu ustaw `Sentinel__BootstrapAdminUsername` (3–64 znaki ASCII: litery, cyfry, `.`, `_`, `@`, `-`) i `Sentinel__BootstrapAdminPassword` (14–128 znaków). Pierwszy administrator dostaje rolę `SystemAdministrator`; kolejne starty nie zmieniają ani nie resetują konta. Po pierwszym uruchomieniu usuń hasło ze stałego środowiska/kontenera/usługi. Proces usuwa je ze swojego środowiska po udanym bootstrapie. Jeśli zmienne bootstrapu są niepoprawne, serwer nie uruchomi się. Nie ma domyślnego hasła.

Logowanie: `POST /api/v1/admin/auth/login` z `{ "username": "…", "password": "…" }`; odpowiedź zawiera token bearer ważny 12 godzin. Hasła są haszowane PBKDF2-HMAC-SHA256 z osobną losową solą. Logowanie ma limit 5 prób na 15 minut z jednego adresu IP. `PUT /api/v1/admin/auth/password` wymaga bieżącego i nowego hasła; unieważnia wszystkie sesje tego konta. `POST /api/v1/admin/auth/logout` unieważnia bieżącą sesję. Tokeny są przechowywane w bazie tylko jako SHA-256.

Role: **SystemAdministrator** może zarządzać kontami/rolami i wszystkimi funkcjami; **SecurityAdministrator** może zarządzać grupami, przypisaniem urządzeń i politykami (bez włączania wysyłania kontekstu), zaproszeniami, odłączać urządzenia i czytać audyt; **Operator** i **ReadOnly** mogą przeglądać urządzenia, grupy oraz efektywną politykę. Każda rola może zarządzać własnym hasłem i sesją. Zmiany kont, udane logowania, zaproszenia, grupy, polityki i odłączenia są zapisywane w audycie. Ostatniego aktywnego administratora systemu nie można wyłączyć ani zdegradować.

Wrażliwa polityka włączająca tryb `server`/`hybrid` lub `includeContext` wymaga jawnego `confirmedSensitiveChange: true` oraz roli `SystemAdministrator`. Polityki globalne, grupowe i urządzenia są dokumentami częściowymi: pole `null` dziedziczy, a podana wartość nadpisuje warstwę niższą; pusta lista jawnie zastępuje listę niższej warstwy pustą listą. Priorytet to urządzenie → grupa → globalnie → bezpieczne wartości domyślne. `expectedVersion` musi zgadzać się z aktualną wersją, inaczej API zwraca konflikt i nie zapisuje zmian. Efektywny endpoint zwraca wersje warstw i źródło każdej wartości.

## API v1

Panel działa pod `http://127.0.0.1:5080/admin/` i jest hostowany przez ten sam proces API. Zawiera dashboard, urządzenia i grupy, zaproszenia, polityki, zdarzenia, konta administratorów, audyt, centralną bazę FTS5 i konfigurację/test lokalnego Ollama. Widoczne działania odpowiadają roli. Token logowania pozostaje wyłącznie w pamięci karty; po odświeżeniu wymagane jest ponowne logowanie. Dostęp sieciowy wymaga HTTPS. Kopie/odtworzenie i aktualizacje serwera nie są zaimplementowane.

- `GET /healthz` — proces działa.
- `GET /readyz` — serwer może otworzyć bazę.
- `POST /api/v1/admin/invitations` — tworzy jednorazowo ujawniony losowy kod rejestracji. JSON: `{ "group": "Testowe", "expiresAt": "<ISO-8601 UTC>", "maximumRegistrations": 1 }`. Maksymalna ważność to 30 dni, limit użyć 1–1000.
- `DELETE /api/v1/admin/invitations/{id}` — unieważnia zaproszenie.
- `GET /api/v1/admin/devices` — lista bez sekretów, z `isOnline` wyliczanym z heartbeat w ostatnich 2 minutach.
- `GET /api/v1/admin/groups`, `POST /api/v1/admin/groups` — lista i tworzenie grup. Zaproszenie może wskazywać wyłącznie istniejącą grupę.
- `PUT /api/v1/admin/devices/{id}/group` — przypisuje urządzenie do istniejącej grupy.
- `GET/PUT /api/v1/admin/policies/global`, `GET/PUT /api/v1/admin/groups/{id}/policy`, `PUT /api/v1/admin/devices/{id}/policy` — czytanie i wersjonowane ustawianie polityk. `GET /api/v1/admin/devices/{id}/policy` zwraca efektywną politykę, wersje i źródła pól.
- `GET /api/v1/admin/devices/{id}/policy/override` — dokument nadpisania polityki urządzenia i jego wersja do edycji w panelu.
- `DELETE /api/v1/admin/devices/{id}` — odcina i unieważnia tożsamość urządzenia (Administrator systemu/bezpieczeństwa).
- `GET /api/v1/admin/users`, `POST /api/v1/admin/users`, `PUT /api/v1/admin/users/{id}/disabled`, `PUT /api/v1/admin/users/{id}/role` — zarządzanie kontami (Administrator systemu).
- `GET /api/v1/admin/audit?limit=100` — ostatnie wpisy dziennika (Administrator systemu/bezpieczeństwa).
- `GET /api/v1/admin/auth/me`, `POST /api/v1/admin/auth/logout`, `PUT /api/v1/admin/auth/password` — bieżące konto, koniec sesji i zmiana własnego hasła.
- `POST /api/v1/agents/enroll` — JSON `{ "invitationCode": "…", "deviceName": "PC-01", "clientVersion": "<wersja-klienta>" }`; kod urządzenia zwracany jest tylko raz.
- `GET /api/v1/agents/me`, `GET /api/v1/agents/configuration` oraz `POST /api/v1/agents/heartbeat` — wymagają nagłówka `Authorization: Bearer <poświadczenie urządzenia>`. Endpoint konfiguracji zwraca efektywną politykę, wersje źródeł i pochodzenie wartości.
- `POST /api/v1/agents/analyze` — wymaga uwierzytelnienia urządzenia, jawnego `contextSharingConfirmed`, polityki `includeContext=true` i `aiProvider=ollama` do użycia modelu. Kontekst przetwarzany jest w pamięci; odpowiedź zawiera sygnały, ograniczenia i źródła FTS5.
- `POST /api/v1/agents/events` — idempotentny batch 1–100 zdarzeń, np. `{ "events": [{ "eventId": "<GUID>", "occurredAt": "<ISO-8601 UTC>", "category": "url", "riskLevel": 3, "ruleCode": "url.suspicious_domain" }] }`. Schemat celowo nie przyjmuje treści, adresów URL, zrzutów ekranu ani danych użytkownika. Powtórzony identyfikator zdarzenia w obrębie urządzenia jest ignorowany.
- `GET /api/v1/admin/events?limit=100&deviceId=…` — historia z ograniczonymi metadanymi zdarzenia.
- `PUT /api/v1/admin/events/{deviceId}/{eventId}/status` z `{ "status": "resolved" }` lub `false_positive` — zmiana statusu (Administrator systemu/bezpieczeństwa), audytowana.

Klient Enterprise ma lokalną trwałą kolejkę, paruje się zaproszeniem, chroni poświadczenie DPAPI i umożliwia ręczne wysłanie heartbeat oraz ograniczonych metadanych. Nie ma jeszcze automatycznej synchronizacji z retry/backoff ani egzekwowania pobranej polityki. Surowego kontekstu użytkownika nie przyjmuje się przez endpoint zdarzeń. Heartbeat przyjmuje wyłącznie jeden z kodów błędu `local_store`, `sync_failed`, `configuration_invalid`, `client_update`; nie przechowuje dowolnych komunikatów, które mogłyby zawierać dane prywatne. Domyślna retencja zdarzeń wynosi 90 dni i można ją ustawić przez `Sentinel:EventRetentionDays` (30–3650 dni); czyszczenie działa cyklicznie i przy przyjęciu zdarzeń. Limit rejestracji wynosi 20 prób/minutę/adres IP. Odpowiedzi API zawierają `X-Correlation-ID`; żądania są ograniczone do 64 KiB.

Do dostępu spoza loopback ustaw HTTPS w Kestrel (`ASPNETCORE_URLS=https://<adres>:<port>` i chroniona konfiguracja certyfikatu Kestrel). Serwer przerwie start, gdy otrzyma zewnętrzny adres HTTP. Certyfikat CA musi zostać zaufany przez klientów; aplikacja nie pomija weryfikacji certyfikatów. Kreator konfiguracji TLS, firewall i test połączenia zostaną dodane w etapie instalatora.

## Kompilacja i testy

```powershell
dotnet restore server/Sentinel.Server.sln --locked-mode
dotnet build server/Sentinel.Server.sln -c Release --no-restore
dotnet test server/tests/Sentinel.Server.Tests/Sentinel.Server.Tests.csproj -c Release --no-restore
python server/scripts/test-api.py
```

Testy jednostkowe używają oddzielnej tymczasowej bazy SQLite i sprawdzają haszowanie haseł, bootstrap, role, sesje, audyt, migrację, zaproszenia, rejestrację/unieważnianie, walidację polityk, priorytety dziedziczenia i wersjonowanie. Skrypt HTTP uruchamia API na losowym porcie loopback z tymczasową bazą i sprawdza logowanie, RBAC, grupy, polityki i cykl życia urządzenia. Dalsze etapy i ograniczenia są w [ARCHITECTURE.md](ARCHITECTURE.md).
