# Monitorowanie Windows — zakres

Monitorowanie jest lokalne; konkretne stany zależą od ustawień, platformy i uprawnień. `Sentinel.Agent` w sesji użytkownika wywołuje `collect` w `Sentinel.Engine` mniej więcej co sekundę, niezależnie od otwartego okna Electron. To cykliczne zbieranie obsługiwanych migawek i zdarzeń, a nie pełny strumień telemetrii systemowej.

W **nowym profilu** monitorowanie jest domyślnie aktywne dla procesów, pobranych plików, zmian autostartu/trwałości i połączeń TCP/UDP. Dane są lokalne. Istniejące, zapisane preferencje pozostają bez zmian; wstrzymanie ochrony nadal zatrzymuje odpowiednie źródła. Zbieranie tekstu aktywnego okna i automatyczne pobieranie zewnętrznych list pozostają wyłączone.

- **Procesy:** snapshoty procesów PID/nazw co około sekundę. Obrazy procesów są analizowane w ograniczonej kolejce SHA-256/Authenticode. Krótkie procesy mogą zostać pominięte, a ścieżka może być niedostępna.
- **Pobrane pliki:** `FileSystemWatcher` i uzgadnianie w folderze Downloads; domyślnie włączone dla nowych profili. Porównanie SHA-256 dotyczy tylko lokalnie zaimportowanej listy. Brak dopasowania nie oznacza czystego pliku.
- **Autostart/trwałość:** snapshot rejestru Run/RunOnce, Startup, Scheduled Tasks i wybranych ustawień usług/sterowników; domyślnie włączone dla nowych profili, różnicowy baseline i możliwe odmowy dostępu. Nie jest to strumień zdarzeń ciągłych.
- **Sieć:** snapshot TCP/UDP próbkowany cyklicznie; domyślnie włączony dla nowych profili. Krótkie połączenia mogą zostać pominięte; treść i pełny URL nie są odczytywane.
- **DNS:** cache systemu odczytywany przez `ipconfig /displaydns`; kanał DNS Client Operational odczytywany tylko gdy jest dostępny/włączony. Nie obejmuje wiarygodnie DoH, DoT, VPN ani zapytań wyłącznie po IP i nie przypisuje DNS do procesu.
- **Windows Security Center:** Engine odczytuje lokalny, zagregowany stan kategorii antywirusa i zapory przez [`WscGetSecurityProviderHealth` (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/wscapi/nf-wscapi-wscgetsecurityproviderhealth), z cache jednej minuty. API nie identyfikuje konkretnego produktu ani jego wersji sygnatur. Sentinel niczego tu nie włącza/wyłącza i nie zastępuje Defendera.
- **ETW/WMI, WFP:** testowane źródła 4688/ETW nie są dostępne w typowym koncie testowym; WFP jest niewdrożone.
- **Powiadomienia:** agent pokazuje balonik zasobnika dla wykrytych lokalnych dopasowań DNS/hashy, z limitem jednego alertu na typ na 10 minut i krótkim dźwiękiem systemowym. Nie jest to powiadomienie o zablokowanym zagrożeniu; mechanizm blokowania nie istnieje.

## Ręczne sprawdzenie z menu Eksploratora

Instalator rejestruje per-user polecenie `Sprawdź w Sentinel AI` dla pojedynczego zaznaczonego pliku. W Windows 11 klasyczne polecenie może być dostępne pod „Pokaż więcej opcji”. Uruchamia lokalne obliczenie SHA-256 i odczyt stanu Authenticode; nie wykonuje pliku, nie przesyła go do usługi zewnętrznej i nie blokuje go. Wynik rozróżnia dopasowanie do lokalnej listy od braku dopasowania. Wpis jest weryfikowany i usuwany tylko wtedy, gdy polecenie nadal wskazuje na plik Sentinel z danej instalacji. Wybór wielu plików nie jest obecnie obsługiwany.

Więcej ograniczeń i retencji danych: [KNOWN-LIMITATIONS](KNOWN-LIMITATIONS.md). Nie ma ukrytego odszyfrowywania HTTPS ani skanowania całego dysku.
