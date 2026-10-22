# Ewaluacja deterministycznej analizy URL

**Data pomiaru:** 2026-10-22  
**Wersja reguł:** `2026.10.6`
**Zakres:** wyłącznie kolumny `URL` i `label`; żaden adres nie został otwarty, rozwiązany przez DNS ani wysłany do usługi.

## Zestaw i odtwarzanie

Użyto [PhiUSIIL Phishing URL (Website) z UCI](https://archive.ics.uci.edu/dataset/967/phiusiil%2Bphishing%2Burl%2Bdataset), autorzy Arvind Prasad i Shalini Chandra, 2024, DOI [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545). UCI opisuje 235 795 rekordów: 100 945 phishingowych (`label=0`) i 134 850 legalnych (`label=1`). Zbiór ma licencję [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

Pobrany snapshot ZIP ma SHA-256 `0A639FD03AEA6308C5B1C10C92AA23C2CE1505447A9137271865CD0BADC9A59A`; archiwum ani CSV nie zostały dodane do repozytorium. Skrypt odczytuje lokalny CSV, używa wyłącznie kolumn `URL` i `label`, pomija cechy strony oraz nie wykonuje połączeń sieciowych:

```powershell
dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release
pwsh -NoProfile -File scripts/evaluate-phiusiil.ps1 -CsvPath C:\ścieżka\PhiUSIIL_Phishing_URL_Dataset.csv
pwsh -NoProfile -File scripts/evaluate-phiusiil.ps1 -CsvPath C:\ścieżka\PhiUSIIL_Phishing_URL_Dataset.csv -DomainHoldoutPercent 30 -SplitSeed sentinel-f03-domain-holdout-v1
pwsh -NoProfile -File scripts/test-evaluate-phiusiil-split.ps1
pwsh -NoProfile -File scripts/analyze-phiusiil-features.ps1 -CsvPath C:\ścieżka\PhiUSIIL_Phishing_URL_Dataset.csv
```

W pomiarze cztery wiersze zawierały adres, którego aplikacja nie uznała za poprawny URL HTTP/HTTPS; pozostały w mianowniku jako niewykryte phishingi lub legalne adresy według podanej etykiety.

Ewaluator zwraca także `DomainTrain` i `DomainHoldout`: dzieli według SHA-256 ziarna i domeny rejestrowalnej z dołączonej PSL, bez użycia etykiety i niezależnie od kolejności wierszy. Wiersze tej samej domeny pozostają w jednym podziale; niepoprawne URL-e otrzymują grupę opartą na ich lokalnym hashu. Procent holdoutu (domyślnie 30) i ziarno można ustawić parametrami. Test regresyjny sprawdza powtarzalność, brak przecieku subdomen, kompletność macierzy i obsługę niepoprawnego URL-a.

Ten podział usuwa przeciek między subdomenami, ale **nie jest niezależnym wynikiem dla obecnych reguł**: wersję `2026.10.4` rozwijano po obejrzeniu całego zbioru, a `DomainHoldout` metryki ujawniono. Wersja `2026.10.5` zmienia wagę exact-brand i rozpoznaje trzy brandowe TLD na podstawie dokumentacji ICANN/producentów oraz osobnego rankingu Tranco; UCI nie służył do strojenia tej poprawki. Mimo to wyniki `DomainHoldout` są nadal diagnostyczne, nie ślepym testem. Dalsze strojenie powinno używać wyłącznie `DomainTrain`, zamrozić reguły przed odczytem holdoutu i dodać niezależny, czasowo odrębny zbiór.

## Wynik

Klasyfikator uznaje wynik `Moderate` lub wyższy za alarm. Przed `url.auth_structure` (`2026.10.2`) wynik wynosił TP=117, FP=14, TN=134 836, FN=100 828. Po `url.auth_structure` (`2026.10.3`) było TP=2 068, FP=14, TN=134 836, FN=98 877. Reguła `url.structure_combination` (`2026.10.4`) dodała na tym samym, eksplorowanym zestawie 2 300 wykryć. Wersja `2026.10.5` obniża dokładną nazwę marki bez weryfikacji do wagi 1, rozpoznaje `.google`, `.apple` i `.microsoft` jako brandowe TLD oraz zachowuje silną wagę dla literówek i brandu w cudzej subdomenie. Wersja `2026.10.6` dodaje słaby wskaźnik mieszania łaciny z greką lub cyrylicą w jednej etykiecie IDN. Ponowne uruchomienie na tym samym snapshotcie nie zmieniło metryk ani podziału domenowego; wskaźnik nie zmienia sam klasyfikacji do `Moderate`. Ten zbiór był już oglądany, więc wynik nie jest niezależnym testem. Bieżący URL-only wynik to:

| Metryka | Wynik |
|---|---:|
| Wiersze | 235 795 |
| TP / FP | 4 363 / 5 |
| TN / FN | 134 845 / 96 582 |
| Precision w tym zbiorze | 99,8855% |
| Recall w tym zbiorze | 4,3222% |
| False-positive rate wśród etykiet legalnych | 0,0037% |

`url.structure_combination` daje umiarkowany sygnał, gdy co najmniej 3 z 4 wymiarów występują jednocześnie: URL ma ≥75 znaków; host jest długi (≥50 znaków), głęboki (≥5 etykiet) albo zawiera ≥3 łączniki; część ścieżki i zapytania ma ≥6 cyfr albo ≥4 parametry; ścieżka zawiera ≥4 ukośniki. Same długie adresy, głęboki host, parametry lub ścieżka nie wywołują tego sygnału. Test regresyjny pokrywa wspólny przypadek oraz każdy pojedynczy wymiar osobno.

### Stały podział po domenie (diagnostyczny)

Od 2026-10-22 `scripts/evaluate-phiusiil.ps1` raportuje również deterministyczny split, który przypisuje wszystkie URL-e tej samej domeny rejestrowalnej do jednej części. Przy `DomainHoldoutPercent=30` i seedzie `sentinel-f03-domain-holdout-v1` otrzymano:

| Część | Domeny | Wiersze | TP | FP | TN | FN | Precision | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| DomainTrain | 138 385 | 167 041 | 2 665 | 3 | 94 567 | 69 806 | 99,8876% | 3,6773% | 0,0032% |
| DomainHoldout | 58 916 | 68 754 | 1 698 | 2 | 40 278 | 26 776 | 99,8824% | 5,9633% | 0,0050% |

To potwierdza rozdzielenie domen i daje punkt odniesienia do przyszłego strojenia. **Nie jest niezależnym testem obecnych reguł:** progi `2026.10.4` wybrano po analizie całego zbioru, więc także domeny z tej części były pośrednio widziane podczas rozwoju. Nie zmieniano reguł na podstawie powyższych liczb. Kolejne strojenie powinno używać wyłącznie `DomainTrain`, zamrozić reguły przed odczytem `DomainHoldout` oraz dodać czasowo odrębny zbiór.

Reguła i progi powstały po eksploracji tego samego pełnego zbioru; pomiar v2026.10.4 jest miarą rozwojową, a nie holdoutem ani niezależnym testem. Nie jest to ocena produkcyjna: brak deduplikacji, proporcje etykiet są sztuczne względem ruchu użytkownika, a źródłowe etykiety i adresy nie są niezależnym testem jakości Sentinel. Wysokiej precyzji z tego zestawu nie wolno interpretować jako skalibrowanej pewności. Zbiór zawiera też cechy stron, których Sentinel celowo nie używa; mierzony jest wyłącznie klasyfikator URL.

Reguła `url.auth_structure` nadal łączy token ścieżki taki jak `login`, `verify`, `account`, `password`, `auth`, `payment` lub `wallet` z dodatkową złożonością URL. Obie reguły są lokalne, deterministyczne i nie otwierają adresu. Testy obejmują kontrolowane przykłady, ale nie zastępują niezależnego, czasowo odseparowanego zestawu.

### Sanity-check popularnych domen (bez etykiet bezpieczeństwa)

Osobny snapshot Tranco `746PX`, utworzony 2026-10-21, ma SHA-256 `577EB57D995B85DEBB0EE8462DE1C54B73E1ADB67FDFB47D50C870230D9318A4`. Na pierwszych 100 000 nazw lokalnie analizowano wyłącznie syntetyczne `https://<domena>/`; nie wykonywano DNS ani połączeń. Reguły `2026.10.4` wyemitowały 271 sygnałów `url.brand` o wadze ostrzegawczej. W `2026.10.5` pozostało 6 takich trafień; 213 dokładnych etykiet marki otrzymało osobny, słaby sygnał `url.brand_exact`, a domeny w `.google`, `.apple` i `.microsoft` nie są oznaczane jako podszycie. To pokazuje zmianę zachowania na popularnych nazwach, ale **nie jest pomiarem false-positive rate**: ranking nie jest listą zweryfikowanych bezpiecznych witryn, a syntetyczny adres główny nie odzwierciedla wszystkich ścieżek ani treści. Archiwum pozostało poza repozytorium.

Reguły dla `.google`, `.apple` i `.microsoft` opierają się na [ICANN Spec 13 dla Google](https://www.icann.org/en/registry-agreements/details/google), [Apple](https://www.icann.org/en/registry-agreements/details/apple) i [Microsoft](https://www.icann.org/en/registry-agreements/details/microsoft). Dodatkowe przykłady własności sprawdzono w [liście domen Google](https://www.google.com/supported_domains), dokumentacji Microsoft dla [`cloud.microsoft`](https://learn.microsoft.com/microsoft-365/enterprise/cloud-microsoft-domain) oraz [dokumentacji Apple News](https://developer.apple.com/documentation/applenewsformat/supportedurls). Tranco opisuje [metodologię rankingu](https://tranco-list.eu/methodology); ranking popularności nie nadaje domenom etykiety „bezpieczna”.

Do dalszej walidacji nadal potrzeba reprezentatywnego, deduplikowanego zestawu z wiarygodnym pochodzeniem, oddzielnego holdoutu i kalibracji na realistycznej bazowej częstości ataków. `confidence` pozostaje puste.

## Niezależny test czasowy PhishVN — wynik bazowy reguł 2026.10.6

Zidentyfikowano niezależny zbiór [PhishVN v3.1.0 na Mendeley Data](https://data.mendeley.com/datasets/b97hxbxtpd/4), licencjonowany na [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Wersja 4 aktualizuje dokumentację, a dane pozostają bajtowo zgodne z wersją 3. Autorzy publikują oficjalny split train/validation/test grupowany po domenie i czasie; plik `data/splits/url_test.csv` ma 8 941 wierszy. Wersja opisuje 18 997 rekordów rdzenia gold/silver oraz osobne 34 119 rekordów bronze. Raportowanie domyślnie ogranicza się do gold/silver; noisy tier bronze można uwzględnić jawnie, ale nie należy łączyć go z głównym wynikiem bez osobnego oznaczenia.

Pobrano oficjalne `PhishVN_v3.1.0_open.zip` (5 813 309 B, SHA-256 `308351E9D0C0FCA13A81F2F63524A7DEE08CCBA6C775848D125B3DA5525D0AB5`). SHA-256 `data/splits/url_test.csv` to `B692882E8AE26B2C0B217C090E92D3A19307A26ACBFB3C8C89692DB26D409BC9` (1 961 206 B), zgodne z wpisem w dołączonym `MANIFEST.txt`. Archiwum i CSV pozostają w katalogu tymczasowym, poza repozytorium.

Dodany `scripts/evaluate-phishvn.ps1` używa wyłącznie `url`, `label`, `tier` i — jeśli jest obecna — `split`. Ocenia niezmieniony próg `Moderate`, nie dobiera reguł ani progu, nie otwiera URL-i i odrzuca wiersze spoza testu. Raport zawiera SHA-256 i rozmiar bajtowy CSV obliczone z tego samego, tylko do odczytu uchwytu pliku, z którego parser pobiera rekordy. W zbiorze 8 941 rekordów 8 553 adresy są pozbawione schematu; ewaluator dopisuje `https://` wyłącznie jako techniczny prefiks wymagany przez parser, bez uznawania tego za informację o rzeczywistym protokole. Wszystkie 8 941 wierszy przeszły analizę parsera. Uruchomienie:

```powershell
dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release
pwsh -NoProfile -File scripts/evaluate-phishvn.ps1 -CsvPath C:\ścieżka\PhishVN\data\splits\url_test.csv
pwsh -NoProfile -File scripts/evaluate-phishvn.ps1 -CsvPath C:\ścieżka\PhishVN\data\splits\url_test.csv -Tiers gold,silver,bronze
# Dane rozwojowe wolno analizować jawnie; wyników train/val nie raportuj jako testu:
pwsh -NoProfile -File scripts/evaluate-phishvn.ps1 -CsvPath C:\ścieżka\PhishVN\data\splits\url_train.csv -Split train
pwsh -NoProfile -File scripts/evaluate-phishvn.ps1 -CsvPath C:\ścieżka\PhishVN\data\splits\url_val.csv -Split val
pwsh -NoProfile -File scripts/test-evaluate-phishvn.ps1
```

| Tier | Wiersze | Phishing | Legalne | TP | FP | TN | FN | Precision | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Gold + silver (wynik główny) | 4 332 | 487 | 3 845 | 0 | 2 | 3 843 | 487 | 0% | 0% | 0,0520% |
| Gold | 2 673 | 69 | 2 604 | 0 | 2 | 2 602 | 69 | 0% | 0% | 0,0768% |
| Silver | 1 659 | 418 | 1 241 | 0 | 0 | 1 241 | 418 | — | 0% | 0% |
| Bronze (osobno, niższa wiarygodność) | 4 609 | 4 609 | 0 | 0 | 0 | 0 | 4 609 | — | 0% | — |
| Wszystkie tiery (nie używać jako głównego wyniku) | 8 941 | 5 096 | 3 845 | 0 | 2 | 3 843 | 5 096 | 0% | 0% | 0,0520% |

Reguły `2026.10.6` nie wykryły żadnego phishingu przy progu Moderate na tym zewnętrznym teście. Nie zmieniano reguł po obejrzeniu wyniku; niska wykrywalność jest dowodem ograniczenia obecnego zestawu, nie przyczyną do strojenia na teście. F03 pozostaje częściowo wdrożone. Przyszły rozwój lokalizacji/reguł może używać wyłącznie train/validation, a poprawę skuteczności należy potwierdzić na nowym, nieoglądanym holdoucie, ponieważ wynik PhishVN jest już znany. PhishVN jest zlokalizowany na Wietnam i nie zastąpi walidacji na innych językach ani realistycznym ruchu produkcyjnym. Reguły nie są skalibrowane do częstości bazowej, a zero wykryć oznacza, że nie wolno przedstawiać obecnej analizy URL jako skutecznej ochrony phishingowej.

### Diagnostyka rozwojowa (niezależna od testu)

Przy niezmienionych regułach `2026.10.6` wynik train dla gold/silver to 13 080 wierszy: TP=0, FP=3, TN=11 001, FN=2 076 (recall 0%, FPR 0,0273%). Validation: 1 585 wierszy, TP=0, FP=0, TN=1 561, FN=24 (recall 0%, FPR 0%). Wszystkie adresy przeszły parser. To pomiar bazowy, nie poprawa ani niezależne potwierdzenie jakości; potwierdza, że aktualne reguły praktycznie nie pokrywają etykietowanych phishingowych adresów tego zbioru także przed testem. `-Split` jest wymagane dla plików train/val, a ewaluator odrzuca rekord oznaczony innym splitem. Nie dostrajano reguł na tych wynikach w ramach pomiaru.

Diagnoza sygnałów URL `2026.10.6` na gold/silver train wykazała, że `url.tld` występuje w 282/2 076 phishingowych i 42/11 004 legalnych adresach. W validation ten sam słaby warning wystąpił w 0/24 phishingowych i 6/1 561 legalnych adresów. Pozostałe aktualne wskaźniki URL zaobserwowano w tym train wyłącznie przy adresach legalnych. Podniesienie wagi TLD na podstawie train nie poprawia więc validation i zwiększyłoby tam false positive; nie zmieniono reguł. Mała próbka phishingu validation ogranicza wniosek — ta analiza wskazuje brak potwierdzonego kandydata, nie dowodzi braku jakichkolwiek możliwych cech predykcyjnych.

Sprawdziłem też substringy w etykiecie domeny rejestrowalnej dla kandydatów nazw banków/platform z PhishVN. Liczby train liczą wiersze URL (wzorce mogą się nakładać): `vietcombank` 36 phishingowych/1 legalny, `bidv` 16/2, `vpb` 23/1, `shopee` 32/7 i `momo` 12/3. W validation z 24 phishingowych adresów tylko `momo` wystąpiło w jednym, a jednocześnie w dwóch legalnych; wymienione pozostałe nazwy banków/platform nie miały pozytywnego trafienia. Te małe i rozbieżne wyniki nie potwierdzają bezpiecznej reguły brandowej; nie dodano nowej listy marek ani nie zmieniono detekcji.
