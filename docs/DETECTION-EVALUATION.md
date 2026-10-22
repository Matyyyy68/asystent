# Ewaluacja deterministycznej analizy URL

**Data pomiaru:** 2026-10-22  
**Wersja reguł:** `2026.10.4`
**Zakres:** wyłącznie kolumny `URL` i `label`; żaden adres nie został otwarty, rozwiązany przez DNS ani wysłany do usługi.

## Zestaw i odtwarzanie

Użyto [PhiUSIIL Phishing URL (Website) z UCI](https://archive.ics.uci.edu/dataset/967/phiusiil%2Bphishing%2Burl%2Bdataset), autorzy Arvind Prasad i Shalini Chandra, 2024, DOI [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545). UCI opisuje 235 795 rekordów: 100 945 phishingowych (`label=0`) i 134 850 legalnych (`label=1`). Zbiór ma licencję [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Pobrany snapshot ZIP ma SHA-256 `0A639FD03AEA6308C5B1C10C92AA23C2CE1505447A9137271865CD0BADC9A59A`; archiwum ani CSV nie zostały dodane do repozytorium. Skrypt odczytuje lokalny CSV, używa wyłącznie kolumn `URL` i `label`, pomija cechy strony oraz nie wykonuje połączeń sieciowych:

```powershell
dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release
pwsh -NoProfile -File scripts/evaluate-phiusiil.ps1 -CsvPath C:\ścieżka\PhiUSIIL_Phishing_URL_Dataset.csv
pwsh -NoProfile -File scripts/analyze-phiusiil-features.ps1 -CsvPath C:\ścieżka\PhiUSIIL_Phishing_URL_Dataset.csv
```

W pomiarze cztery wiersze zawierały adres, którego aplikacja nie uznała za poprawny URL HTTP/HTTPS; pozostały w mianowniku jako niewykryte phishingi lub legalne adresy według podanej etykiety.

## Wynik

Klasyfikator uznaje wynik `Moderate` lub wyższy za alarm. Przed `url.auth_structure` (`2026.10.2`) wynik wynosił TP=117, FP=14, TN=134 836, FN=100 828. Po `url.auth_structure` (`2026.10.3`) było TP=2 068, FP=14, TN=134 836, FN=98 877. Reguła `url.structure_combination` (`2026.10.4`) dodała na tym samym, eksplorowanym zestawie 2 300 wykryć; bieżący wynik to:

| Metryka | Wynik |
|---|---:|
| Wiersze | 235 795 |
| TP / FP | 4 368 / 14 |
| TN / FN | 134 836 / 96 577 |
| Precision w tym zbiorze | 99,6805% |
| Recall w tym zbiorze | 4,3271% |
| False-positive rate wśród etykiet legalnych | 0,0104% |

`url.structure_combination` daje umiarkowany sygnał, gdy co najmniej 3 z 4 wymiarów występują jednocześnie: URL ma ≥75 znaków; host jest długi (≥50 znaków), głęboki (≥5 etykiet) albo zawiera ≥3 łączniki; część ścieżki i zapytania ma ≥6 cyfr albo ≥4 parametry; ścieżka zawiera ≥4 ukośniki. Same długie adresy, głęboki host, parametry lub ścieżka nie wywołują tego sygnału. Test regresyjny pokrywa wspólny przypadek oraz każdy pojedynczy wymiar osobno.

Reguła i progi powstały po eksploracji tego samego pełnego zbioru; pomiar v2026.10.4 jest miarą rozwojową, a nie holdoutem ani niezależnym testem. Nie jest to ocena produkcyjna: brak deduplikacji, proporcje etykiet są sztuczne względem ruchu użytkownika, a źródłowe etykiety i adresy nie są niezależnym testem jakości Sentinel. Wysokiej precyzji z tego zestawu nie wolno interpretować jako skalibrowanej pewności. Zbiór zawiera też cechy stron, których Sentinel celowo nie używa; mierzony jest wyłącznie klasyfikator URL.

Reguła `url.auth_structure` nadal łączy token ścieżki taki jak `login`, `verify`, `account`, `password`, `auth`, `payment` lub `wallet` z dodatkową złożonością URL. Obie reguły są lokalne, deterministyczne i nie otwierają adresu. Testy obejmują kontrolowane przykłady, ale nie zastępują niezależnego, czasowo odseparowanego zestawu.

Do dalszej walidacji nadal potrzeba reprezentatywnego, deduplikowanego zestawu z wiarygodnym pochodzeniem, oddzielnego holdoutu i kalibracji na realistycznej bazowej częstości ataków. `confidence` pozostaje puste.
