# Sentinel AI Server — etap A+B1

Serwer jest odrębnym projektem w `server/`; istniejący klient WPF i jego reguły pozostają bez zmian. Wymagany jest .NET SDK 10.0.402.

## Uruchomienie lokalne

Z katalogu głównego repozytorium:

```powershell
$env:Sentinel__DataDirectory = "$env:ProgramData\SentinelAI\Server"
dotnet run --project server/src/Sentinel.Server.Api/Sentinel.Server.Api.csproj
```

Bez zmiennych konfiguracyjnych API nasłuchuje wyłącznie na `http://127.0.0.1:5080`. Katalog danych domyślnie znajduje się w `%ProgramData%\SentinelAI\Server` na Windows i `/var/lib/sentinel-ai/server` na Linux. Konto procesu musi mieć prawo zapisu do tego katalogu. Lokalny serwer nie ma jeszcze instalatora ani usługi Windows.

Operacje administracyjne wymagają osobnego `Sentinel__AdminApiKey` (co najmniej 32 znaki), przekazywanego przez środowisko procesu lub chroniony dostawca konfiguracji. Klucz nie może trafić do repozytorium. To tymczasowa brama operacyjna dla etapu B1; przed zdalnym wdrożeniem musi zostać zastąpiona przez konta, role, lockout i audyt administracyjny.

## API v1

- `GET /healthz` — proces działa.
- `GET /readyz` — serwer może otworzyć bazę.
- `POST /api/v1/admin/invitations` — tworzy jednorazowo ujawniony losowy kod rejestracji. JSON: `{ "group": "Testowe", "expiresAt": "<ISO-8601 UTC>", "maximumRegistrations": 1 }`. Maksymalna ważność to 30 dni, limit użyć 1–1000.
- `DELETE /api/v1/admin/invitations/{id}` — unieważnia zaproszenie.
- `GET /api/v1/admin/devices` — lista bez sekretów, z `isOnline` wyliczanym z heartbeat w ostatnich 2 minutach.
- `DELETE /api/v1/admin/devices/{id}` — odcina i unieważnia tożsamość urządzenia.
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

Testy jednostkowe używają oddzielnej tymczasowej bazy SQLite i sprawdzają limit oraz ważność zaproszeń, rejestrację, poświadczenia, heartbeat i odwołanie urządzenia. Skrypt HTTP uruchamia API na losowym porcie loopback z tymczasową bazą i sprawdza autoryzację administracyjną oraz cykl życia urządzenia. Dalsze etapy i ograniczenia są w [ARCHITECTURE.md](ARCHITECTURE.md).
