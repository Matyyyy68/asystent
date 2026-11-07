# Sentinel Protection Engine — stan weryfikacji

Data audytu: 2026-11-07  
Zakres: bieżący stan gałęzi `codex/sentinel-wmi-process-events`. Cały cel nadal **IN PROGRESS**.

## Dowody wykonania

Pełny Windows CI dla gałęzi zawierającej merge commit [19f90f1](https://github.com/Matyyyy68/asystent/commit/19f90f115da5d71f94fe8660370e5de9c937cd48) i raport [`ff742eb`](https://github.com/Matyyyy68/asystent/commit/ff742eb4dc9ac4c1d91f031f028741561f4d377c) zakończył się sukcesem w [run 42402176917](https://github.com/Matyyyy68/asystent/actions/runs/42402176917). Wynik obejmuje .NET 555/555, audyt NuGet, test wydajności, WMI, usługę SCM pod LocalService i ACL, Electron, przekierowany Known Folder Downloads wraz z 120-sekundowym soak, autostart, Chrome/Edge, instalację headless i widoczny cykl instalatora, oraz Enterprise API 23/23 i HTTP smoke. To test izolowanego runnera GitHub; nie jest dowodem działania na czystym, fizycznym komputerze.

## Zaimplementowane i zweryfikowane

- Silnik działa niezależnie od okna aplikacji jako usługa SCM; monitoruje stan kolekcji i podejmuje ograniczone próby restartu.
- Zdarzenia procesów pochodzą z WMI, gdy dostępne; snapshot PID stanowi jawny fallback.
- Kolekcja obejmuje wybrane zdarzenia procesu, Downloads, obserwacje TCP/UDP/DNS oraz wybrane ustawienia trwałości i zabezpieczeń systemu.
- Zdarzenia są normalizowane i korelowane w ograniczonym zakresie przez PID, hash, identyfikatory i okna czasu; historia jest lokalna.
- Ocena ryzyka opiera się na lokalnych regułach. Niezweryfikowany feed ani odpowiedź AI same nie podnoszą liczbowego ryzyka.
- Centralna decyzja odpowiedzi jest zapisywana dla nowych zdarzeń. Powiadomienia historii respektują tę politykę.
- UI może odczytać stan usługi i przeglądać jej historię; pipe stosuje ACL i ograniczenia protokołu.
- Kwarantanna wymaga jawnego działania użytkownika. Rekomendacje nie twierdzą, że ruch lub proces został zablokowany.
- RiskEngine odrzuca ponad 1024 surowe wejścia albo ponad 256 unikalnych wskaźników; regresje limitów przeszły w pełnym .NET CI. Limity nie są miarą wydajności urządzeń.

## Częściowe / brakujące

- WMI nie jest pełnym kernel ETW i może utracić zdarzenia; pełny strumień ETW nie jest wdrożony.
- Brak kolektora WFP i ogólnego blokowania procesu lub sieci. Pełny file-system monitoring nie jest wdrożony; monitorowanie plików obejmuje Downloads i wybrane ścieżki.
- Migawki sieci mogą pominąć krótkotrwałe przepływy; obserwacja UDP nie dowodzi wysłania datagramu.
- Agent i Service utrzymują oddzielne bazy. Przekazywanie wybranych zdarzeń istnieje, lecz unifikacja incydentów i deduplikacja zdarzeń o różnych ID są niepełne.
- Heurystyki nie są skalibrowanym prawdopodobieństwem. Brakuje niezależnego, reprezentatywnego holdoutu phishingu.
- Brakuje podpisanych feedów i zaufanego, podpisanego mechanizmu automatycznych aktualizacji.
- Licencja produktu nadal wymaga decyzji właściciela. Nie przeprowadzono pełnego cyklu instalacji i restartu na czystym fizycznym Windows.

## Stan dostarczenia

PR [#1](https://github.com/Matyyyy68/asystent/pull/1) pozostaje otwarty i niescalony. Nowsze commity `main` zostały dołączone do gałęzi PR w merge commicie `19f90f1`; zmiany zachowano w UI, workflow CI i lockfile. GitHub potwierdził `mergeable: true`, a pełny Windows CI dla połączonego stanu zakończył się PASS. Samo scalenie PR nadal nie nastąpiło.