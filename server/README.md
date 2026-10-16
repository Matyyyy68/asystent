# Sentinel AI Server — etapy A, B1 i B2a

Serwer jest odrębnym projektem w `server/`; istniejący klient WPF i jego reguły pozostają bez zmian. Wymagany jest .NET SDK 10.0.402.

## Uruchomienie lokalne

Z katalogu głównego repozytorium:

```powershell
$env:Sentinel__DataDirectory = "$env:ProgramData\SentinelAI\Server"
dotnet run --project server/src/Sentinel.Server.Api/Sentinel.Server.Api.csproj
```

Bez zmiennych konfiguracyjnych API nasłuchuje wyłącznie na `http://127.0.0.1:5080`. Katalog danych domyślnie znajduje się w `%ProgramData%\SentinelAI\Server` na Windows i `/var/lib/sentinel-ai/server` na Linux. Konto procesu musi mieć prawo zapisu do tego katalogu. Lokalny serwer nie ma jeszcze instalatora ani usługi Windows.

Przy pierwszym uruchomieniu ustaw `Sentinel__BootstrapAdminUsername` (3–64 znaki ASCII: litery, cyfry, `.`, `_`, `@`, `-`) i `Sentinel__BootstrapAdminPassword` (14–128 znaków). Pierwszy administrator dostaje rolę `SystemAdministrator`; kolejne starty nie zmieniają ani nie resetują konta. Po pierwszym uruchomieniu usuń hasło ze stałego środowiska/kontenera/usługi. Proces usuwa je ze swojego środowiska po udanym bootstrapie. Jeśli zmienne bootstrapu są niepoprawne, serwer nie uruchomi się. Nie ma domyślnego hasła.

Logowanie: `POST /api/v1/admin/auth/login` z `{ "username": "…", "password": "…" }`; odpowiedź zawiera token bearer ważny 12 godzin. Hasła są haszowane PBKDF2-HMAC-SHA256 z osobną losową solą. Logowanie ma limit 5 prób na 15 minut z jednego adresu IP. `PUT /api/v1/admin/auth/password` wymaga bieżącego i nowego hasła; unieważnia wszystkie sesje tego konta. `POST /api/v1/admin/auth/logout` unieważnia bieżącą sesję. Tokeny są przechowywane w bazie tylko jako SHA-256.

Role: **SystemAdministrator** może zarządzać kontami/rolami i wszystkimi funkcjami; **SecurityAdministrator** może zarządzać zaproszeniami, odłączać urządzenia i czytać audyt; **Operator** i **ReadOnly** mogą przeglądać urządzenia. Każda rola może zarządzać własnym hasłem i sesją. Zmiany kont, udane logowania, zaproszenia i odłączenia są zapisywane w audycie. Ostatniego aktywnego administratora systemu nie można wyłączyć ani zdegradować.

## API v1

- `GET /healthz` — proces działa.
- `GET /readyz` — serwer może otworzyć bazę.
- `POST /api/v1/admin/invitations` — tworzy jednorazowo ujawniony losowy kod rejestracji. JSON: `{ "group": "Testowe", "expiresAt": "<ISO-8601 UTC>", "maximumRegistrations": 1 }`. Maksymalna ważność to 30 dni, limit użyć 1–1000.
- `DELETE /api/v1/admin/invitations/{id}` — unieważnia zaproszenie.
- `GET /api/v1/admin/devices` — lista bez sekretów, z `isOnline` wyliczanym z heartbeat w ostatnich 2 minutach.
- `DELETE /api/v1/admin/devices/{id}` — odcina i unieważnia tożsamość urządzenia (Administrator systemu/bezpieczeństwa).
- `GET /api/v1/admin/users`, `POST /api/v1/admin/users`, `PUT /api/v1/admin/users/{id}/disabled`, `PUT /api/v1/admin/users/{id}/role` — zarządzanie kontami (Administrator systemu).
- `GET /api/v1/admin/audit?limit=100` — ostatnie wpisy dziennika (Administrator systemu/bezpieczeństwa).
- `GET /api/v1/admin/auth/me`, `POST /api/v1/admin/auth/logout`, `PUT /api/v1/admin/auth/password` — bieżące konto, koniec sesji i zmiana własnego hasła.
- `POST /api/v1/agents/enroll` — JSON `{ "invitationCode": "…", "deviceName": "PC-01", "clientVersion": "0.2.0" }`; kod urządzenia zwracany jest tylko raz.
- `GET /api/v1/agents/me` oraz `POST /api/v1/agents/heartbeat` — wymagają nagłówka `Authorization: Bearer <poświadczenie urządzenia>`.

API nie przyjmuje jeszcze zdarzeń ani kontekstu użytkownika. Heartbeat przyjmuje wyłącznie jeden z kodów błędu `local_store`, `sync_failed`, `configuration_invalid`, `client_update`; nie przechowuje dowolnych komunikatów, które mogłyby zawierać dane prywatne. Limit rejestracji wynosi 20 prób/minutę/adres IP. Odpowiedzi API zawierają `X-Correlation-ID`; żądania są ograniczone do 64 KiB.

Do dostępu spoza loopback ustaw HTTPS w Kestrel (`ASPNETCORE_URLS=https://<adres>:<port>` i chroniona konfiguracja certyfikatu Kestrel). Serwer przerwie start, gdy otrzyma zewnętrzny adres HTTP. Certyfikat CA musi zostać zaufany przez klientów; aplikacja nie pomija weryfikacji certyfikatów. Kreator konfiguracji TLS, firewall i test połączenia zostaną dodane w etapie instalatora.

## Kompilacja i testy

```powershell
dotnet restore server/Sentinel.Server.sln --locked-mode
dotnet build server/Sentinel.Server.sln -c Release --no-restore
dotnet test server/tests/Sentinel.Server.Tests/Sentinel.Server.Tests.csproj -c Release --no-restore
python server/scripts/test-api.py
```

Testy jednostkowe używają oddzielnej tymczasowej bazy SQLite i sprawdzają haszowanie haseł, bootstrap, role, sesje, audyt, migrację v1→v2, zaproszenia, rejestrację i unieważnianie. Skrypt HTTP uruchamia API na losowym porcie loopback z tymczasową bazą i sprawdza logowanie, RBAC oraz cykl życia urządzenia. Dalsze etapy i ograniczenia są w [ARCHITECTURE.md](ARCHITECTURE.md).
