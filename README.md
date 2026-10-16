# Sentinel AI

Lokalny klient bezpieczeństwa dla Windows 10/11 x64, .NET 10 LTS, WPF i MVVM. **Dostarczone: Etap 1 i zasadnicza implementacja Etapu 2.** Analiza regułowa oraz magazyn mają testy wykonywane na Linux; natywny odczyt UI Automation wymaga walidacji na interaktywnym Windows. AI, RAG i integracja z przeglądarką nie są jeszcze dostępne.

## Gotowy instalator dla użytkownika

Plik: `artifacts/installer/SentinelAI-0.2.0-win-x64-Setup.exe`.

1. Otwórz instalator dwuklikiem i przejdź przez polski kreator.
2. Po instalacji uruchom Sentinel AI z menu Start lub pulpitu.
3. Przy pierwszym starcie kliknij **Rozpocznij**, aby użyć zalecanego prywatnego folderu danych. Możesz też wybrać inny folder.

Instalator zawiera .NET; nie wymaga administratora, dodatkowych pobrań ani komend. Instaluje program dla bieżącego użytkownika. Odinstalowanie z ustawień Windows zachowuje historię i ustawienia. Krótka instrukcja jest dostępna w menu Start → Sentinel AI → Pomoc oraz w `artifacts/installer/Pierwsze-kroki.html`.

Bieżący EXE nie jest podpisany zaufanym certyfikatem wydawcy. Windows może wyświetlić ostrzeżenie o nieznanym wydawcy. Nie dodano wyłączania zabezpieczeń ani wyjątków antywirusa.

Szczegóły budowania i walidacji: [installer/README.md](installer/README.md).

## Serwer firmowy — pierwszy etap

Repozytorium zawiera teraz odrębny fundament ASP.NET Core w katalogu `server/`: SQLite serwera, health/readiness, zaproszenia ograniczone czasem i limitem, rejestrację urządzeń z indywidualnymi poświadczeniami, heartbeat oraz odwoływanie urządzeń. Instrukcje uruchomienia i endpointy są w [server/README.md](server/README.md); audyt, diagram, granice prywatności, decyzje bezpieczeństwa i plan etapów są w [server/ARCHITECTURE.md](server/ARCHITECTURE.md).

To nie jest jeszcze gotowy serwer produkcyjny. Nie ma panelu administracyjnego, kont i ról administratorów, dystrybucji polityk, synchronizacji zdarzeń, AI/RAG, instalatora usługi Windows ani integracji klienta. Obecny klucz administracyjny przez zmienną środowiskową jest rozwiązaniem przejściowym dla pierwszego etapu.

## Uruchomienie deweloperskie na Windows

Zainstaluj .NET SDK **10.0.402** z oficjalnej dystrybucji Microsoft, następnie w katalogu repozytorium:

```powershell
dotnet restore Sentinel.sln --locked-mode
dotnet build Sentinel.sln -c Release --no-restore
dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj -c Release --no-restore
dotnet run --project src/Sentinel.Desktop/Sentinel.Desktop.csproj -c Release
```

Pierwszy start proponuje prywatny katalog w profilu użytkownika i pozwala wybrać inny lokalny katalog z uprawnieniami zapisu i co najmniej 50 MB wolnego miejsca. Rezygnacja zamyka aplikację. Dane są w `sentinel.db`; lokalizacja w `%LOCALAPPDATA%/SentinelAI/data-path.txt`. Po restarcie konfiguracja i historia pozostają dostępne. Baza nie jest szyfrowana: wybierz prywatny katalog użytkownika, nie udział sieciowy ani katalog współdzielony. Nie wymagamy administratora. Nie próbujemy uzyskiwać dostępu do ekranów UAC ani okien o wyższym poziomie uprawnień.

## Analiza i prywatność

**Pierwsza konfiguracja domyślnie wstrzymuje zbieranie.** Ręczne wklejenie tekstu do analizy jest dostępne także podczas pauzy.

1. W zakładce „Analiza” wklej tekst i opcjonalnie rzeczywisty adres docelowy. Oddzielne pole pozwala podać widoczny tekst linku. Adresów nie odwiedzamy, nie odpytujemy DNS ani reputacji online.
2. Wynik zawiera kategorię, pięciostopniowy poziom ryzyka, opis sygnałów, zalecenia i niepewności. Wklejone pola są czyszczone po rozpoczęciu analizy; nie są zapisywane do bazy. Nie wklejaj haseł ani tokenów. Czyszczenie formularza nie jest gwarancją wyzerowania pamięci zarządzanej.
3. Aby sprawdzić inne okno, jawnie wybierz „Włącz analizę okien”, następnie „Analizuj aktywne okno za 3 sekundy” i przełącz okno. Wskaźnik stanu jest stale widoczny. „Wstrzymaj zbieranie” anuluje oczekujące odczyty.
4. Opcjonalne „Analizuj przy zmianie aktywnego okna” wymaga zapisania ustawień i włączonego zbierania. Nie analizuje każdej klatki ani zmian zawartości strony wewnątrz tego samego okna. Zdarzenia objęte limitem częstotliwości są pomijane, a nie kolejkowane. Można ponowić odczyt ręcznie.
5. Wykluczenia procesów i fragmentów tytułów działają przed odczytem UI Automation. Dodatkowe kategorie obejmują znane przeglądarki oraz komunikatory/klientów poczty rozpoznawane po nazwie procesu. Listy edytuje się, rozdzielając wpisy średnikiem. Dodaj używane aplikacje, jeśli nie znajdują się na liście.

UI Automation czyta wyłącznie dostępne nazwy kontrolek Text, Hyperlink i Button. Pomija poddrzewa oznaczone jako hasła, Edit i ComboBox. Nie odczytuje ValuePattern, TextPattern, naciśnięć klawiszy, ciasteczek, pól formularzy ani zrzutów. Limity: 250 węzłów, 12 poziomów, 16 000 znaków i budżet pracy 2 s; oczekiwanie na dostawcę maksymalnie 3 s. Zablokowany dostawca może nadal zajmować jeden wątek do zakończenia wywołania; aplikacja nie uruchamia wtedy kolejnych pracowników.

Maskowanie statycznych etykiet jest heurystyczne: usuwa m.in. adresy, e-maile, długie numery, identyfikatory i jawne przypisania sekretów. Nie jest niezawodnym klasyfikatorem danych poufnych. Surowa treść i tytuł okna nie trafiają do historii. Tytuł służy tylko do lokalnego wykluczenia okna. Analizowane dane nie są wysyłane do usług zewnętrznych. Nie ma telemetrii.

**URL w zwykłej etykiecie UI Automation nie jest uznawany za rzeczywisty cel.** Do wiarygodnego automatycznego śledzenia nawigacji i przekierowań potrzebne jest przyszłe rozszerzenie przeglądarki. Obecnie URL podaje użytkownik ręcznie. Nie wykrywamy faktycznego pobrania/otwarcia pliku — reguły rozpoznają jedynie ryzykowne prośby i polecenia widoczne w tekście.

## Zakres reguł

- HTTP/HTTPS, IDN/punycode, IP (IPv4/IPv6), porty, userinfo i domena rejestrowalna z lokalnej Public Suffix List, także dla sufiksów prywatnych.
- Wybrane literówki i proste podobieństwa znaków nazw marek, mylące subdomeny i porównanie jawnie podanego tekstu linku z celem. Lista marek i zamienników znaków jest ograniczona; nie jest kompletnym filtrem homografów.
- Presja czasu, groźba blokady, prośby o logowanie/przelew, wyłączenie zabezpieczeń, wykonywanie skryptów i instalację plików; polskie i angielskie frazy.
- Krótka korelacja presji czasu z późniejszą prośbą o logowanie w **tym samym oknie**, maksymalnie 2 min. Przechowuje wyłącznie czas i flagę sygnału, nigdy wcześniejsze wiadomości. Nie potwierdza związku wiadomości z nawigacją między aplikacjami.
- Jawna punktacja; pojedynczy słaby sygnał nie daje wysokiego ryzyka. Wynik nie jest prawdopodobieństwem oszustwa.

Treść nie może zmienić reguł, wywołać poleceń ani uzyskać narzędzi. W tej wersji nie ma modelu interpretującego instrukcje. Fałszywe alarmy i przeoczenia są możliwe; brak ostrzeżenia **nie potwierdza bezpieczeństwa**.

Syntetyczny przykład do ręcznego sprawdzenia:

```text
Pilnie: blokada konta. Zaloguj się, aby potwierdzić dane.
Adres docelowy: https://paypal.com.evil.test/login
```

Wpisz adres w osobnym polu „Rzeczywisty adres docelowy”. Domena `.test` jest przeznaczona do przykładów; program jej nie odwiedza.

## Historia i ustawienia

Zachowane funkcje Etapu 1: SQLite z wersjonowaniem schematu i transakcyjną inicjalizacją, retencja 1–365 dni, do 500 ostatnich zdarzeń w UI, eksport całej historii JSON, spójna kopia SQLite, oznaczanie fałszywego alarmu, usuwanie historii z potwierdzeniem i test powiadomienia. Zapis wyniku obejmuje wyłącznie aplikację, kategorię, ryzyko, opis reguł, niepewności i zalecenia. Analiza bez sygnałów nie dodaje zdarzenia. Zgłoszenie fałszywego alarmu nie wyłącza automatycznie reguły.

Ustawienia zbierania wymagają przycisku „Zapisz ustawienia”; zmiana pauzy zapisuje się natychmiast. Włączone zbieranie i tryb zmian okien są odtwarzane po restarcie dopiero po pokazaniu okna aplikacji. Retencja jest stosowana przy starcie, zapisie ustawień i po ostrzeżeniu. Wyłączone powiadomienia nie ukrywają wyniku analizy na żądanie. Ostrzeżenia są wewnątrz aplikacji; nie ma jeszcze powiadomień systemowych ani zasobnika.

Eksport/kopie nie nadpisują istniejących plików. Uszkodzona baza lub nieznana przyszła wersja schematu powodują błąd bez automatycznego resetu. Aby zmienić katalog danych: zamknij aplikację, wykonaj kopię i popraw `%LOCALAPPDATA%/SentinelAI/data-path.txt`. Zmiana lokalizacji z UI nie jest jeszcze dostępna.

## Kompilacja i publikacja

```powershell
dotnet publish src/Sentinel.Desktop/Sentinel.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:RestoreLockedMode=true -o artifacts/win-x64
```

Uruchom `artifacts/win-x64/Sentinel.Desktop.exe` na Windows, zachowując cały katalog publikacji. To katalog programu z runtime. Gotowy instalator EXE jest dostępny osobno w `artifacts/installer`. Procedura natywnej walidacji: [docs/WINDOWS-VALIDATION.md](docs/WINDOWS-VALIDATION.md).

Linux/Codex: `bash scripts/setup-cloud.sh` odtwarza zależności w locked-mode, kompiluje WPF i uruchamia testy Core. SDK: `/workspace/tools/dotnet/dotnet`. Pobranie SDK jest przypięte i weryfikowane SHA-512. WPF i user32/UI Automation nie mogą zostać uruchomione na Linux. Testy podstawiają źródło okien, ale wykonują rzeczywistą analizę regułową i operacje SQLite. Test offline najpierw sprawdza działanie audytora żądaniem loopback bez danych użytkownika, a następnie sprawdza brak zdarzeń HTTP, DNS i połączeń zarządzanych podczas lokalnej analizy.

## Następne etapy

Etap 3: IAIProvider, rzeczywista integracja lokalnego modelu lub serwera, walidacja odpowiedzi/fallback, import PDF/TXT/MD/DOCX, wyszukiwanie FTS5 i źródła RAG. Tabela FTS5 istnieje, ale import i wyszukiwanie nie są dostępne. Nie podawaj kluczy ani nie pobieraj modeli na potrzeby bieżącej wersji.

Etapy 4–5: rozszerzenie przeglądarki, autostart opt-in, powiadomienia Windows, opcjonalne przechwytywanie okna, bezpieczne przechowywanie przyszłych sekretów, podpisywanie instalatora zaufanym certyfikatem i testy na natywnym Windows. Brak blokowania, usługi systemowej, serwera, ONNX/NPU i aplikacji mobilnych.

Architektura i punktacja: [ARCHITECTURE.md](ARCHITECTURE.md). Źródła wersji: [metadane .NET 10](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json), [NuGet](https://api.nuget.org/v3/index.json). Wersje i hashe pakietów: `packages.lock.json`. Informacje o licencji PSL: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
