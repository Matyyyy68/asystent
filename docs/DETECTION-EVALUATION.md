# Ewaluacja deterministycznej analizy URL

**Data pomiaru:** 2026-10-22  
**Wersja reguł:** `2026.10.3`  
**Zakres:** wyłącznie kolumny `URL` i `label`; żaden adres nie został otwarty, rozwiązany przez DNS ani wysłany do usługi.

## Zestaw i odtwarzanie

Użyto [PhiUSIIL Phishing URL (Website) z UCI](https://archive.ics.uci.edu/dataset/967/phiusiil%2Bphishing%2Burl%2Bdataset), autorzy Arvind Prasad i Shalini Chandra, 2024, DOI [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545). UCI opisuje 235 795 rekordów: 100 945 phishingowych (`label=0`) i 134 850 legalnych (`label=1`). Zbiór ma licencję [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Pobrany snapshot ZIP ma SHA-256 `0A639FD03AEA6308C5B1C10C92AA23C2CE1505447A9137271865CD0BADC9A59A`; archiwum ani CSV nie zostały dodane do repozytorium. Skrypt odczytuje lokalny CSV, używa wyłącznie kolumn `URL` i `label`, pomija cechy strony oraz nie wykonuje połączeń sieciowych:

```powershell
dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release
pwsh -NoProfile -File scripts/evaluate-phiusiil.ps1 -CsvPath C:\ścieżka\PhiUSIIL_Phishing_URL_Dataset.csv
```

W pomiarze cztery wiersze zawierały adres, którego aplikacja nie uznała za poprawny URL HTTP/HTTPS; pozostały w mianowniku jako niewykryte phishingi lub legalne adresy według podanej etykiety.

## Wynik

Klasyfikator uznaje wynik `Moderate` lub wyższy za alarm. Przed regułą `url.auth_structure` (`2026.10.2`) wynik wynosił TP=117, FP=14, TN=134 836, FN=100 828. Po dodaniu reguły łączącej ścieżkę logowania/weryfikacji/płatności ze strukturalną złożonością URL (`2026.10.3`) wynik wyniósł:

| Metryka | Wynik |
|---|---:|
| Wiersze | 235 795 |
| TP / FP | 2 068 / 14 |
| TN / FN | 134 836 / 98 877 |
| Precision w tym zbiorze | 99,3276% |
| Recall w tym zbiorze | 2,0486% |
| False-positive rate wśród etykiet legalnych | 0,0104% |

To pokazuje, że nowa reguła zwiększa liczbę wykryć w tym zbiorze, ale pozostawia bardzo niski recall. Nie jest to ocena produkcyjna: cały zbiór posłużył do eksploracji i pomiaru, nie ma odłożonego holdoutu ani deduplikacji, proporcje etykiet są sztuczne względem ruchu użytkownika, a źródłowe etykiety i adresy nie są niezależnym testem jakości Sentinel. Wysokiej precyzji z tego zestawu nie wolno interpretować jako skalibrowanej pewności. Zbiór zawiera także cechy stron, których Sentinel celowo nie używa; mierzony jest wyłącznie klasyfikator URL.

Reguła `url.auth_structure` daje umiarkowany sygnał, gdy adres łączy token ścieżki takiego jak `login`, `verify`, `account`, `password`, `auth`, `payment` lub `wallet` z co najmniej jedną dodatkową cechą strukturalną (długość URL, głębokość hosta, długa ścieżka albo wiele segmentów). Sama ścieżka logowania lub sama złożoność URL nie uruchamia tej reguły. Regresja obejmuje kontrolowane przykłady i nie zastępuje niezależnego, czasowo odseparowanego zestawu.

Do dalszej walidacji nadal potrzeba reprezentatywnego, deduplikowanego zestawu z wiarygodnym pochodzeniem, oddzielnego holdoutu i kalibracji na realistycznej bazowej częstości ataków. `confidence` pozostaje puste.
