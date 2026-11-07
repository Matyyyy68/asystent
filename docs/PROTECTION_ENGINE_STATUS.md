# Sentinel Protection Engine — stan weryfikacji

Data audytu: 2026-11-07  
Zakres: bieżący stan gałęzi `codex/sentinel-wmi-process-events`. Cały cel nadal **IN PROGRESS**.

## Dowody wykonania

Pełny Windows CI dla commita [5e6ff0d](https://github.com/Matyyyy68/asystent/commit/5e6ff0db03a97c98d14abe67674e45a7f7090003) zakończył się sukcesem w [run 42394781999](https://github.com/Matyyyy68/asystent/actions/runs/42394781999). Wynik obejmuje .NET 552/552, audyt NuGet, test wydajności, WMI, usługę SCM pod LocalService i ACL, Electron, przekierowany Known Folder Downloads wraz z 120-sekundowym soak, autostart, Chrome/Edge, instalację headless i widoczny cykl instalatora, oraz Enterprise API 23/23 i HTTP smoke. To test izolowanego runnera GitHub; nie jest dowodem działania na czystym, fizycznym komputerze.

## Zaimplementowane i zweryfikowane

- Silnik działa niezależnie od okna aplikacji jako usługa SCM; monitoruje stan kolekcji i podejmuje ograniczone próby restartu.
- Zdarzenia procesów pochodzą z WMI, gdy dostępne; snapshot PID stanowi jawny fallback.
- Kolekcja obejmuje wybrane zdarzenia procesu, Downloads, obserwacje TCP/UDP/DNS oraz wybrane ustawienia trwałości i zabezpieczeń systemu.
- Zdarzenia są normalizowane i korelowane w ograniczonym zakresie przez PID, hash, identyfikatory i okna czasu; historia jest lokalna.
- Ocena ryzyka opiera się na lokalnych regułach. Niezweryfikowany feed ani odpowiedź AI same nie podnoszą liczbowego ryzyka.
- Centralna decyzja odpowiedzi jest zapisywana dla nowych zdarzeń. Powiadomienia historii respektują tę politykę.
- UI może odczytać stan usługi i przeglądać jej historię; pipe stosuje ACL i ograniczenia protokołu.
- Kwarantanna wymaga jawnego działania użytkownika. Rekomendacje nie twierdzą, że ruch lub proces został zablokowany.

## Częściowe / brakujące

- WMI nie jest pełnym kernel ETW i może utracić zdarzenia; pełny strumień ETW nie jest wdrożony.
- Brak kolektora WFP i ogólnego blokowania procesu lub sieci. Pełny file-system monitoring nie jest wdrożony; monitorowanie plików obejmuje Downloads i wybrane ścieżki.
- Migawki sieci mogą pominąć krótkotrwałe przepływy; obserwacja UDP nie dowodzi wysłania datagramu.
- Agent i Service utrzymują oddzielne bazy. Przekazywanie wybranych zdarzeń istnieje, lecz unifikacja incydentów i deduplikacja zdarzeń o różnych ID są niepełne.
- Heurystyki nie są skalibrowanym prawdopodobieństwem. Brakuje niezależnego, reprezentatywnego holdoutu phishingu.
- Brakuje podpisanych feedów i zaufanego, podpisanego mechanizmu automatycznych aktualizacji.
- Licencja produktu nadal wymaga decyzji właściciela. Nie przeprowadzono pełnego cyklu instalacji i restartu na czystym fizycznym Windows.

## Stan dostarczenia

PR [#1](https://github.com/Matyyyy68/asystent/pull/1) pozostaje otwarty i niescalony. Bieżący `main` ma trzy commity spoza wspólnej historii PR, a GitHub raportuje stan merge jako konfliktowy; trzeba uzgodnić rozbieżność przed scaleniem.