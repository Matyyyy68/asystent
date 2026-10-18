# Audyt migracji — 2026-10-17

Repozytorium pobrano z https://github.com/Matyyyy68/asystent.git.

## Potwierdzone obserwacje

- Główna aplikacja jest WPF, a silnik reguł i LocalStore są w osobnym Sentinel.Core.
- SQLite ma migracje do wersji 3, retencję, eksport i kopię; indeks wiedzy FTS5 nie jest bazą reputacji.
- Rozszerzenie MV3 i host Native Messaging istnieją. Host odrzucał wszystkie argumenty, choć Chromium przekazuje origin oraz na Windows opcjonalny `--parent-window`. To uniemożliwiało normalne uruchomienie przez przeglądarkę.
- Zmieniono walidację uruchomienia: akceptowany jest tylko origin rozszerzenia wpisany w manifest hosta i opcjonalny liczbowy uchwyt okna. Dodano testy regresji. Sam test parsera nie potwierdza instalacji i działania w Chrome/Edge.
- Istnieje odrębny backend Enterprise; nie należy go rozbudowywać w ramach migracji User.
- Obecny README opisuje SDK 10.0.402, a global.json wymagał tej wersji. Lokalnie dostępne jest SDK 10.0.302. Minimalną wersję zmieniono na 10.0.300 z rollForward latestFeature.
- Nie ma kolektora DNS/WFP ani importera reputacji. Rozszerzenie ostrzega po obserwacji nawigacji, nie gwarantuje blokady przed załadowaniem.

## Kolejność dalszej implementacji

1. Odtworzyć zależności i uruchomić testy bazowe.
2. Zachować Core i zastąpić WPF powłoką webową z prywatnym IPC do osobnego procesu silnika.
3. Dodać reputację i kolektory systemowe, następnie spiąć historię i statusy.
4. Zbudować instalator, witrynę i wykonać walidację Windows.

Po uruchomieniu następcy WPF przeniesiono do `legacy/` i usunięto z aktywnego solution. Projekt nadal nie spełnia wszystkich kryteriów docelowej ochrony i instalacji.

Źródło kontraktu Native Messaging: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
