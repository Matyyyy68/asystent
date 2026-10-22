# PLAN-012 — lokalna reputacja adresów IP

1. **Cel:** przy dobrowolnie włączonym monitoringu połączeń TCP tworzyć wyjaśnialne lokalne ostrzeżenia, gdy zdalny adres należy do listy IP/CIDR jawnie zaimportowanej przez użytkownika.
2. **Stan obecny:** `IpReputation` przechowuje listę w osobnej bazie SQLite, normalizuje IPv4/IPv6 i CIDR, ogranicza import do 20 MiB/250 000 sieci oraz dopasowuje adres offline. `TcpConnectionSnapshotMonitor` sprawdza nowe połączenia TCP i podnosi ryzyko do High przy trafieniu; UDP nie ma adresu zdalnego w użytym Windows API. UI pokazuje liczbę wpisów i czas importu. Lista nie jest dołączana do produktu ani pobierana automatycznie.
3. **Braki:** brak automatycznej aktualizacji feedu, weryfikacji jego pochodzenia/świeżości i usuwania bieżącej listy z UI; jakość ostrzeżenia zależy od ręcznie wybranego źródła. Snapshot TCP co sekundę może pominąć krótkie połączenia. Nie ma dopasowania reputacji dla UDP.
4. **Decyzje architektoniczne:** plik tekstowy z jednym IP/CIDR na wiersz, komentarz `#` dozwolony; dopasowanie lokalne do prefiksów, bez zapytań o adresy do serwera. Trafienie jest ostrzeżeniem, nie blokadą ani dowodem złośliwości. Ruch pozostaje objęty istniejącym ustawieniem opt-in monitoringu sieci.
5. **Zależności:** .NET 10 `System.Net.IPNetwork`, SQLite istniejący w projekcie, lokalne UI i istniejący observer TCP. Nie dodano zewnętrznego pakietu ani feedu.
6. **Etapy implementacji:**
   1. Parser i normalizacja IP/CIDR z limitem i transakcyjnym importem.
   2. Trwały magazyn oraz pamięciowe dopasowanie prefiksu IPv4/IPv6.
   3. Integracja z nowymi zdarzeniami TCP i bezpieczną listą dowodów.
   4. Jawny wybór pliku w UI, status importu i wyjaśnienie ograniczeń.
   5. Testy parsera, rollbacku błędnego importu, restartu bazy i zdarzenia TCP.
   6. Aktualizacja macierzy, ograniczeń i changeloga.
7. **Zmiany w plikach:** `src/Sentinel.Core/Analysis/IpReputation.cs`, `src/Sentinel.Engine/Program.cs`, `src/Sentinel.Engine/TcpConnectionSnapshotMonitor.cs`, testy `IpReputationTests.cs` i `TcpConnectionSnapshotMonitorTests.cs`, Electron/React UI, raport audytu, changelog.
8. **Bezpieczeństwo i prywatność:** feed pozostaje w `ip-reputation.db`; nie jest wysyłany. Alert zapisuje zdalny adres w lokalnej historii, która może trafić do eksportu historii; klient Enterprise otrzymuje tylko dotychczasowe, allowlistowane metadane. Sentinel nie blokuje ani nie kończy połączenia.
9. **Testy:** kontrolowane lokalne fixture IPv4/IPv6, prefiksy, błędny import, trwałość po ponownym otwarciu bazy i alert przy nowym połączeniu TCP. Pełny build klienta obejmuje Engine IPC, Windows sieć, UI i instalator.
10. **Kryteria akceptacji:** brak dopasowania nie podnosi alarmu; trafienie na poprawnej liście daje lokalny alert High z kodem `reputation.ip-feed.match`; zły plik nie usuwa poprzedniej listy; import i dopasowanie nie używają sieci; wyłączony observer nie tworzy zdarzeń.
11. **Ryzyka i ograniczenia:** właściciel musi sprawdzić licencję, pochodzenie, zakres i datę feedu. Zbyt szeroka lub nieaktualna sieć może dać fałszywe alarmy. Współdzielone, CDN i dynamiczne adresy wymagają ostrożnej interpretacji.
12. **Status realizacji:** `IN_PROGRESS` — implementacja gotowa; wybrane testy .NET 16/16 PASS, a pełna bramka `scripts/build-user.ps1 -Installer` 2026-10-22 PASS: .NET 264/264 bez pominięć, Engine IPC, Windows DNS/TCP/UDP, Electron 14/14, `npm audit` 0, UI production build i autotest instalatora. Lokalny artefakt testowy v0.15.38 ma 281303417 B i SHA-256 `7FF19961FDD4AA4527B1CA0182DB113CCD4EC8C51CE8DC2DA792674220BA18F7`; nie jest wydaniem. Test IPC potwierdza import i odrzucenie błędnej podmiany bez utraty poprzedniego feedu; `node scripts/test-engine.cjs --tcp-live` potwierdza dopasowanie kontrolowanego połączenia do własnego interfejsu i alert High. Ręczny test UI na czystym profilu nie został jeszcze wykonany. Nie wbudowano ani nie opublikowano żadnego feedu.
