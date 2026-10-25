# Sentinel AI Server — architektura i plan migracji

## Wyniki audytu istniejącego repozytorium

Pierwotny audyt sprzed migracji opisywał klienta WPF/MVVM na .NET 10; ten kod zachowano w `legacy/`. Aktualny klient to React/TypeScript w Electronie (`desktop/`) oraz osobny silnik .NET 10 (`src/Sentinel.Engine`) korzystający z `src/Sentinel.Core`. Regułowy analizator URL i tekstu, ograniczone zbieranie metadanych, filtrowanie prywatności oraz lokalny magazyn SQLite pozostają w aktywnym przepływie. W historii są metadane oceny, nie treść analizowanych wiadomości.

W audycie pierwotnym nie znaleziono klient-serwerowego API, rejestracji urządzeń, zarządzania flotą, centralnych polityk ani kont administratorów; wdrożono je później w etapach B1–B2b. Klient lokalny ma provider Ollama loopback oraz bazę FTS5 dla TXT/MD/DOCX i tekstowych PDF, a także opcjonalne pełne wyszukiwanie semantyczne. Serwer ma centralny import i wyszukiwanie FTS5 dla tych samych formatów, osobną semantyczną akcję administratorską przez lokalne Ollama oraz ograniczony endpoint analizy agenta. Klient ma tray, tryb ukrytego okna, opt-in autostart i synchronizację Enterprise w tle. Instalator serwera Enterprise jest osobnym pakietem NSIS z obsługą usługi Windows.

## Komponenty i granice

```mermaid
flowchart LR
  subgraph Client[Komputer pracownika — istniejący klient]
    UI[React UI / Electron]
    Engine[Sentinel.Engine / JSON Lines IPC]
    Core[Sentinel.Core / analiza lokalna i SQLite]
    Queue[Ograniczona kolejka Enterprise offline]
    UI --> Engine --> Core
    Core --> Queue
  end
  subgraph Server[Serwer firmowy — nowy katalog server/]
    API[Sentinel.Server.Api / REST v1]
    SCore[Sentinel.Server.Core / kontrakty domeny]
    Infra[Sentinel.Server.Infrastructure / SQLite]
    Admin[Hostowany panel administracyjny]
    AI[Loopback Ollama / analiza agenta]
    KB[Centralna baza FTS5]
    API --> SCore --> Infra
    Admin --> API
    API --> AI
    API --> KB
  end
  Queue -->|HTTPS, tożsamość urządzenia, API v1| API
```

Kod serwera jest odseparowany od WPF. Klient ma niewielką implementację transportu REST w `Sentinel.Core` i nie referuje `Server.Core`; kontrakty JSON są walidowane na granicy HTTP. Po ustabilizowaniu schematów można generować klienta z OpenAPI, bez zależności klienta od implementacji serwera.

Serwer używa obecnego celu `net10.0`, zgodnego z istniejącym repozytorium i wspieranym wydaniem LTS .NET. `Sentinel.Server.Api` to ASP.NET Core Minimal API; `Sentinel.Server.Infrastructure` izoluje SQLite. SQLite jest jedynym działającym dostawcą danych w tym etapie. Nie deklarujemy obsługi PostgreSQL ani SQL Server.

## Decyzje bezpieczeństwa

- API ma wersję w ścieżce (`/api/v1`) oraz identyfikator korelacji w `X-Correlation-ID`. Maksymalny rozmiar żądania wynosi 64 KiB; rejestracja jest limitowana do 20 prób na minutę na adres IP.
- Domyślny adres nasłuchiwania to `127.0.0.1:5080`. Serwer odmawia startu dla zewnętrznego adresu HTTP; zdalne nasłuchiwanie wymaga jawnego adresu HTTPS i skonfigurowanego certyfikatu Kestrel. Walidacja TLS pozostaje w systemowym stosie HTTP klienta i nie ma trybu pomijania certyfikatu.
- Pierwsze konto tworzy się jawnie przez `Sentinel__BootstrapAdminUsername` i `Sentinel__BootstrapAdminPassword` przy pierwszym uruchomieniu. Konto otrzymuje rolę `SystemAdministrator`; po udanym bootstrapie proces usuwa hasło ze swojego środowiska. Administrator musi usunąć je również ze stałej konfiguracji usługi. Hasła są haszowane PBKDF2-HMAC-SHA256 z losową solą i 600 000 iteracji. Brak skonfigurowanego konta nie uruchamia domyślnego konta ani znanego hasła.
- Logowanie ma limit pięciu prób na 15 minut na adres IP. Sesje administratorów to losowe tokeny bearer ważne 12 godzin; serwer przechowuje wyłącznie ich SHA-256. Zmiana hasła i wyłączenie konta unieważnia aktywne sesje. Blokada nie może wyłączyć ani zdegradować ostatniego aktywnego administratora systemu.
- RBAC jest egzekwowany na API: Administrator systemu zarządza kontami i wszystkimi operacjami; Administrator bezpieczeństwa może tworzyć/unieważniać zaproszenia, odłączać urządzenia i czytać audyt; Operator i Odczyt mogą przeglądać urządzenia. Każda rola może zarządzać własną sesją i hasłem. Tożsamość użytkownika jest wymagana dla wszystkich endpointów administracyjnych.
- Operacje bootstrapu, logowania, zarządzania kontami, zaproszeniami, sesjami i odłączeniem urządzeń są zapisywane w tym samym magazynie SQLite co zmiana, w tabeli audytu bez haseł, tokenów i treści zdarzeń.
- Kod zaproszenia oraz poświadczenie każdego urządzenia są losowe, różne dla każdego użycia, zwracane tylko przy utworzeniu i przechowywane na serwerze wyłącznie jako SHA-256. Zaproszenie atomowo egzekwuje limit rejestracji i termin ważności. Odwołane urządzenie przestaje się uwierzytelniać. Nie ma wspólnego sekretu agentów.
- Zdarzenia są przyjmowane jako ograniczone metadane bez treści i URL. Endpoint analizy przyjmuje kontekst tylko z uwierzytelnionego agenta, gdy agent jawnie potwierdzi udostępnienie, a efektywna polityka zezwala na nie. Kontekst jest przetwarzany w pamięci, przekazywany wyłącznie do skonfigurowanego loopback Ollama (albo analizowany regułowo) i nie jest zapisywany. Nie wysyłamy ekranów, haseł, tokenów sesyjnych ani treści prywatnych wiadomości.
- `healthz` i `readyz` zwracają jedynie stan i wersję API; nie publikują ścieżki bazy ani sekretów. Dostępność modelu nie jest częścią gotowości, ponieważ działa lokalny fallback regułowy.
- Baza serwera jest w `C:\ProgramData\SentinelAI\Server` na Windows albo w systemowym katalogu danych na innych platformach; można ustawić `Sentinel__DataDirectory`. Nie jest trzymana w katalogu programu ani tymczasowym.

Pakiet serwera zawiera instalację usługi Windows na wirtualnym koncie serwisowym, ograniczone ACL katalogu danych, restart po awarii i jawny bootstrap administratora. Dostępne są narzędzia backup/restore, rotacja poświadczeń urządzeń oraz ręczna akceptacja rejestracji. Pozostają kreator TLS/firewall, weryfikacja wdrożenia na Windows Server, automatyczne aktualizacje i odporna na rozproszony brute force blokada kont.

## Plan migracji i etapowanie

1. **Etap A — audyt i projekt (ukończony):** inwentaryzacja klienta, diagram, uzasadnienie granic, plan migracji, decyzje prywatności i transportu.
2. **Etap B1 — fundament API i urządzeń (zaimplementowany):** host API, SQLite serwera, health/readiness, zaproszenia ograniczone limitem i czasem, rejestracja z unikalnym poświadczeniem, lista/odwołanie urządzeń, uwierzytelniony heartbeat oraz testy trwałości i unieważniania.
3. **Etap B2a — tożsamość administracyjna (zaimplementowany):** bootstrap administratora, PBKDF2, sesje, cztery role, limit logowania, unieważnianie sesji i audyt.
4. **Etap B2b — flota, polityki i historia zdarzeń (częściowo zaimplementowany):** zarządzane grupy, przypisywanie i ręczna akceptacja/odwołanie urządzeń, polityki globalne/grupowe/urządzeń, dziedziczenie, wersjonowanie, walidacja i audyt są zaimplementowane. Uwierzytelniony endpoint agenta zwraca efektywną konfigurację. Po zastosowaniu ustawień klient raportuje wersje polityki globalnej, grupowej i urządzenia; panel porównuje je z bieżącym stanem i pokazuje zgodność, niezgodność lub brak raportu. API przyjmuje minimalne, idempotentne metadane zdarzeń, pozwala zmieniać status incydentu i usuwa stare dane zgodnie z retencją. Diagnostyka hosta pozostaje otwarta.
5. **Etap C — panel (częściowo zaimplementowany):** hostowany panel operacyjny z ochroną żądań przeglądarkowych; dostępne są dashboard, urządzenia, grupy i zaproszenia, polityki, zdarzenia, konta, audyt, konfiguracja/test Ollama oraz centralna baza wiedzy FTS5 dla TXT/MD/DOCX i tekstowych PDF. Administrator bezpieczeństwa/systemu może jawnie uruchomić pełne wyszukiwanie semantyczne przez skonfigurowane lokalne Ollama po potwierdzeniu przesłania fragmentów. Panel wyświetla rzeczywisty stan z API. Brakuje wersjonowania źródeł i administracji hostem; backup/restore działa jako narzędzia offline.
6. **Etap D — klient-serwer (częściowo zaimplementowany):** klient rejestruje się zaproszeniem, chroni poświadczenia DPAPI, pobiera i stosuje walidowaną politykę oraz automatycznie synchronizuje ograniczoną kolejkę w tle z retry/backoff/jitter. Klient pozostaje lokalny i offline, gdy serwer jest niedostępny; wymagania pozostałe opisuje PLAN-010.
7. **Etap E — UX klienta (częściowo zaimplementowany):** tray, jednoznaczny lokalny stan, ukrywanie okna i uruchamianie analizy w tle są dostępne. Pozostają opt-in autostart, systemowe ograniczone powiadomienia i integracja modułów Enterprise.
8. **Etap F — AI i wiedza (częściowo zaimplementowany):** konfiguracja loopback Ollama, rzeczywiste wykrywanie modeli/test syntetyczny, timeouty, walidowany wynik i fallback regułowy; odseparowany import TXT/MD/DOCX oraz tekstowych PDF (do 10 MB, 500 stron i 2 mln znaków, bez OCR), walidacja typów/rozmiaru i wyszukiwanie FTS5 z cytowaniami. Brakuje embeddingów/semantycznego wyszukiwania po całym korpusie, kwot współbieżności i pełnej obsługi retencji/wersji źródeł.
9. **Etap G — wdrożenie operacyjne (częściowo zaimplementowany):** pakiet NSIS self-contained instaluje usługę Windows, bootstrap administratora, ACL danych i restart po awarii; działają backup/restore. Brakuje kreatora TLS/CA/firewall, podpisanych aktualizacji i rollbacku oraz natywnych testów instalacji i usługi na Windows Server.

## Bieżący zakres i uruchomienie

Ten etap dostarcza audyt A, fundament B1, tożsamość B2a, część B2b, panel administracyjny oraz część UX klienta. Działają konta/role/sesje, audyt, rejestracja z zaproszeniem i akceptacją, heartbeat, health/readiness, SQLite, API grup/polityk/minimalnych metadanych zdarzeń, centralna baza FTS5 dla TXT/MD/DOCX i tekstowych PDF, jawne pełne wyszukiwanie semantyczne w kliencie i panelu oraz konfiguracja/test serwerowego Ollama i zgoda polityki dla endpointu analizy agenta. `EnterpriseClient` paruje się przez HTTPS, chroni token DPAPI, pobiera i stosuje efektywną politykę, raportuje jej trzy wersje i synchronizuje metadane w tle z retry/backoff. Panel oznacza politykę jako aktualną, nieaktualną albo nieznaną. Klient zachowuje lokalne reguły i działa offline. PDF nie jest OCR-owany; jakość embeddingów nie została zweryfikowana na rzeczywistym modelu. Brakuje automatycznego doboru sprzętowego, lokalnego modelu w paczce, reprezentatywnej jakości wyszukiwania, diagnostyki hosta oraz kwot współbieżności.

Uruchomienie lokalne (domyślnie loopback):

```powershell
$env:Sentinel__DataDirectory = "$env:ProgramData\SentinelAI\Server"
dotnet run --project server/src/Sentinel.Server.Api/Sentinel.Server.Api.csproj
```

Przy pierwszym uruchomieniu ustaw `Sentinel__BootstrapAdminUsername` i `Sentinel__BootstrapAdminPassword` w środowisku procesu (hasło 14–128 znaków). Aplikacja tworzy konto systemowe tylko jeśli baza nie ma jeszcze administratora; usuń zmienne ze stałej konfiguracji usługi po pierwszym uruchomieniu. Logowanie: `POST /api/v1/admin/auth/login`; użyj zwróconego tokenu w `Authorization: Bearer …`. Sesja trwa 12 godzin. Administrator może zmienić hasło pod `PUT /api/v1/admin/auth/password`. Do LAN skonfiguruj `ASPNETCORE_URLS=https://0.0.0.0:5443` oraz certyfikat Kestrel przez chronioną konfigurację lub magazyn certyfikatów i rozdystrybuuj łańcuch zaufania na klientach. Nie otwieraj portu HTTP do sieci.

Testy: `dotnet test server/tests/Sentinel.Server.Tests/Sentinel.Server.Tests.csproj`. Oprócz testów SQLite są live testy HTTP loopback uploadu/wyszukiwania PDF oraz scenariusze HTTPS agenta: pairing, zgoda, synchronizacja, retry po restarcie API, rotacja i odwołanie. Ograniczone środowisko może zablokować import tymczasowego certyfikatu przez Windows CryptoAPI; instalacja i restart usługi na rzeczywistym Windows Server nadal wymagają testu wdrożeniowego.

## Wdrożeniowe systemy Windows

Docelowa rekomendacja to Windows Server 2022 lub 2025 x64 z aktualnymi poprawkami i .NET 10 Hosting Bundle dla framework-dependent deployment albo paczką self-contained. Server 2019, 2016 i starsze nie są objęte gwarancją tego etapu. Zgodność wersji systemu i runtime należy ponownie zweryfikować przed wydaniem i natywnym testem instalatora; kompilacja na Linux nie jest walidacją usługi Windows.
