# Ewaluacja deterministycznej analizy URL

## Bieżący snapshot PhishTank: aktywne, zweryfikowane phishingi (2026-10-24)

Jednorazowo pobrano oficjalny plik `online-valid.csv.gz` przez HTTPS z `data.phishtank.com`; przekierowanie ręcznie ograniczono do HTTPS na `cdn.phishtank.com`. SHA-256 gzip: `7FE19F854F913571C5F23E0D334DA25171C97866E4F30D9234FF5039403E67E8` (2 065 363 B). Z 57 392 wierszy `verified=yes` i `online=yes` 6 613 osiągnęło próg `Moderate`, 50 779 nie, a 3 URL-e były niepoprawne: recall wierszowy 11,5225%, `URLsOpened=0`, reguły `2026.10.9`. SHA-256 tymczasowego CSV ewaluacyjnego: `BA7CDB0EEF98391E6A977EA309564DB3557ED46925EDCFC511C601365B3F2B44`; archive i CSV usunięto po pomiarze. Nie dostrajano reguł.

To wyłącznie jednopunktowy pomiar czułości na aktywnym feedzie PhishTank, bez przykładów benign. Nie mierzy precision ani FPR; wynik może zawierać powtórzone lub powiązane adresy i nie jest niezależną walidacją produktu. Nie należy porównywać go bezpośrednio z innymi zbiorami. PhishTank opisuje znaczniki czasu zgłoszenia/weryfikacji i ogranicza feed do wpisów zweryfikowanych oraz online w [dokumentacji dla developerów](https://www.phishtank.org/developer_info.php); aktualne [FAQ](https://www.phishtank.org/faq.php) informuje, że użycie API do celów komercyjnych i niekomercyjnych jest dozwolone.

## Diagnostyczny model n-gramów znakowych (2026-10-24)

Sprawdzono czysto lokalny Multinomial Naive Bayes z n-gramami znakowymi 3–5, trenowanymi na surowym URL-u bez schematu, z `alpha=0.1`. Użyto wyłącznie checksumowanych `url_train.csv` i `url_val.csv`, gold+silver; skrypt `scripts/evaluate_phishvn_char_ngram.py` odrzuca inne nazwy plików, kontroluje sumy i split oraz nie otwiera URL-i. Zbiór testowy nie był czytany. Test skryptu: `python scripts/test_evaluate_phishvn_char_ngram.py` (4/4 PASS).

Próg `0` uzyskał na train TP=2 065, FP=398, TN=10 606, FN=11, a na validation TP=22/24, FP=198, TN=1 363, FN=2. Próg alternatywny został wyznaczony wyłącznie z wyników negatywnych train jako 99,9 percentyl (zastosowano `score > threshold`): train TP=1 800, FP=11, TN=10 993, FN=276; validation TP=3, FP=3, TN=1 558, FN=21. Wysoka liczba fałszywych alarmów przy progu 0 i spadek recall przy progu train potwierdzają, że prosty model przeucza się na języku i wzorcach zbioru. Nie dodano modelu ani alarmu do produktu. Walidacja ma tylko 24 pozytywy i była już wielokrotnie użyta diagnostycznie; ten wynik nie jest niezależną walidacją. PhishVN test pozostaje nietknięty.

## Ewaluacja URL-only na PhreshPhish (2026-10-24)

Zamrożone reguły `2026.10.9` przy progu Moderate zmierzono na teście PhreshPhish 1.0.1, revision `eca603e0ecd4f698f8d4d226c088659e72681239`, licencja CC BY 4.0. Odczytano wyłącznie kolumny `sha256`, `url` i `label` z 21 plików Parquet przez 42 żądania HTTP Range (łącznie 22 166 361 B z 9 175 760 158 B); HTML nie pobierano, a URL-i nie otwierano. Pierwszy rekord pominięto, bo został już pobrany w jednorazowym sprawdzeniu API przed przygotowaniem ewaluatora. Pozostałe 168 059 rekordów: 91 259 benign i 76 800 phishing. SHA-256 uporządkowanych identyfikatorów rekordów: `389C98EAF3D02D0E149218F4A8A0E92F06CA2F45821F1CE08A53E3F935CA343C`; SHA-256 wygenerowanego CSV: `001926172EDAD6A7E612AC9B53585E2AC775847D14FFCD58CA1A960B7EE691A1`. Wersja reguł `2026.10.9`: TP=3 808, FP=5 399, TN=85 860, FN=72 992, recall=4,9583%, FPR=5,9161%, precision=41,3598%; 15 URL-i uznano za niepoprawne. `URLsOpened=0`. Wynik potwierdza bardzo słaby recall oraz wysoki FPR na tym korpusie; nie należy używać go jako deklaracji skuteczności produktu ani stroić reguł na tym teście. Dane tymczasowe usunięto po ewaluacji.

Odtworzenie: `npm ci --prefix scripts/research/phreshphish`, następnie `pwsh -NoProfile -File scripts/research/phreshphish/evaluate.ps1`. Skrypt przypina revision i manifest, wymaga odpowiedzi HTTP 206 dla zakresów, odrzuca zakres większy niż 16 MiB, weryfikuje liczbę i etykiety, a katalog tymczasowy tworzy i usuwa w `%TEMP%`. Implementacja evaluatorów CSV jest testowana przez `scripts/test-evaluate-url-label-csv.ps1` i bramkę `scripts/build-user.ps1`.

## Badawczy model URL-only: train, domenowa kalibracja i test (2026-10-24)

Zbadano model SGD logistic loss na znakowych n-gramach URL 3–5 jako oddzielny, niedystrybuowany eksperyment. Użyto tylko PhreshPhish `train` do uczenia, kalibracji i wewnętrznego holdoutu; reguły produktu pozostały bez zmian. Pobrano kolumny `sha256`, `url`, `label` (62 524 010 B przez 112 żądań Range z 27 400 613 420 B Parquet). Train CSV SHA-256 `482DE829B0273D13C47CBBB8532C583986BA928247665C70BB85F7CE11288DCA`; hashe uporządkowanych ID `F05910DE28C3DFEED33C73C4A96CA297135B445DB725C54550652F191EC6B59E`. Deterministyczny podział po registrable domain z repozytoryjnej Public Suffix List, seed `sentinel-phreshphish-train-registrable-domain-v1`: train 349 004 (187 405 benign / 161 599 phish; 148 257 domen), calibration 72 253 (42 306 / 29 947; 31 633 domen), holdout 76 998 (47 018 / 29 980; 31 849 domen). Guard sprawdził rozłączność domen między częściami.

Progi ustalono wyłącznie na benign calibration dla docelowych FPR 0,1%, 0,5% i 1,0%; potem nie zmieniano modelu ani progów. Na wewnętrznym holdoucie odpowiednio: recall/FPR 63,73%/0,1106%, 78,67%/0,6678%, 82,52%/1,2442%. Zamrożone reguły `2026.10.9` na tych samych 76 998 URL-ach: TP=1 037, FP=2 631, TN=44 387, FN=28 943 (recall 3,4590%, FPR 5,5957%).

Następnie kandydat oceniono na oficjalnym PhreshPhish `test`, po wykluczeniu pierwszego wiersza odczytanego wcześniej w sprawdzeniu API; test CSV SHA-256 `001926172EDAD6A7E612AC9B53585E2AC775847D14FFCD58CA1A960B7EE691A1`, uporządkowane ID SHA-256 `389C98EAF3D02D0E149218F4A8A0E92F06CA2F45821F1CE08A53E3F935CA343C`, 168 059 rekordów (91 259 benign / 76 800 phish). Progi zamrożone z kalibracji dały: docelowy FPR 0,1% → TP=40 846, FP=126, TN=91 133, FN=35 954 (recall 53,1849%, FPR 0,1381%); 0,5% → TP=58 256, FP=672, TN=90 587, FN=18 544 (recall 75,8542%, FPR 0,7364%); 1,0% → TP=62 760, FP=1 134, TN=90 125, FN=14 040 (recall 81,7188%, FPR 1,2426%). Wykonano dwa identyczne przebiegi z tym samym modelem i progami; drugi powtórzono wyłącznie dlatego, że pierwsze wyjście raportu było obcięte. Wcześniejszy pomiar obecnych reguł na tym samym teście wyniósł TP=3 808, FP=5 399, TN=85 860, FN=72 992 (recall 4,9583%, FPR 5,9161%). Nie użyto etykiet testowych do fitu, kalibracji ani zmian kandydata.

## Oficjalne benchmarki niskiej częstości (2026-10-24)

Zamrożony kandydat i progi ustalone wyłącznie na train/calibration oceniono na wszystkich 975 oficjalnych podzbiorach: 586 przy bazie 0,05%, 296 przy 0,1%, 59 przy 0,5%, 29 przy 1% i 5 przy 5%. Każdy używa wspólnej listy 90 262 benign rekordów i własnego zbioru phishing; pełny test URL-only zawierał 168 060 rekordów (91 260 benign / 76 800 phish), w tym jeden wiersz odczytany wcześniej przy sprawdzeniu API. Ten wiersz nie brał udziału w fitowaniu ani doborze progów. Dla każdego progu raportujemy średnią po podzbiorach oraz percentile bootstrap 95% CI (10 000 replik, seed 20261024):

| Baza phish | N podzbiorów | Cel FPR z calibration | Precision mean (95% CI) | Recall mean (95% CI) | FPR mean |
|---:|---:|---:|---:|---:|---:|
| 0,05% | 586 | 0,1% | 13,715% (13,563–13,869) | 43,603% (43,049–44,164) | 0,1363% |
| 0,05% | 586 | 0,5% | 4,385% (4,351–4,419) | 66,981% (66,424–67,531) | 0,7279% |
| 0,05% | 586 | 1,0% | 2,912% (2,893–2,931) | 74,130% (73,629–74,623) | 1,2320% |
| 0,1% | 296 | 0,1% | 24,140% (23,890–24,386) | 43,645% (43,041–44,257) | 0,1363% |
| 0,1% | 296 | 0,5% | 8,400% (8,335–8,465) | 66,974% (66,400–67,530) | 0,7279% |
| 0,1% | 296 | 1,0% | 5,661% (5,625–5,698) | 74,159% (73,656–74,658) | 1,2320% |
| 0,5% | 59 | 0,1% | 61,597% (61,246–61,953) | 43,645% (43,009–44,315) | 0,1363% |
| 0,5% | 59 | 0,5% | 31,585% (31,406–31,757) | 66,977% (66,427–67,512) | 0,7279% |
| 0,5% | 59 | 1,0% | 23,200% (23,077–23,325) | 74,168% (73,648–74,685) | 1,2320% |
| 1% | 29 | 0,1% | 76,331% (76,057–76,614) | 43,601% (42,950–44,290) | 0,1363% |
| 1% | 29 | 0,5% | 48,143% (47,939–48,352) | 66,971% (66,403–67,516) | 0,7279% |
| 1% | 29 | 1,0% | 37,780% (37,605–37,949) | 74,128% (73,580–74,685) | 1,2320% |
| 5% | 5 | 0,1% | 94,397% (94,328–94,468) | 43,625% (43,060–44,214) | 0,1363% |
| 5% | 5 | 0,5% | 82,877% (82,788–82,976) | 66,937% (66,517–67,405) | 0,7279% |
| 5% | 5 | 1,0% | 75,991% (75,862–76,156) | 74,085% (73,563–74,772) | 1,2320% |

FPR jest stały między bazami, bo podzbiory dzielą tę samą listę benign; dla FPR CI bootstrap jest zdegenerowany. Przy najniższej bazie precision wynosi 13,7% nawet przy najniższym progu, a dla innych progów spada poniżej 5%. Wynik poprawia recall względem bieżących reguł, lecz nie uzasadnia alertu użytkownika ani automatycznej integracji. Dataset card ogranicza użycie do badań antyphishingowych, więc model pozostaje research-only. Pełne checksumy, progi i 15 zestawów przedziałów są zapisane w [raporcie maszynowym](PHRESHPHISH-OFFICIAL-BENCHMARKS.json); odtworzenie i 10 testów guardów: `scripts/research/phreshphish/train-and-evaluate.ps1`, `test_train_url_model.py`. URL-i nie otwierano; URL/label/hash, benchmarki i pakiety usunięto z `%TEMP%`. [Karta danych i warunki](https://huggingface.co/datasets/phreshphish/phreshphish), [artykuł](https://arxiv.org/abs/2507.10854).

## Kandydat na niezależny holdout PhreshPhish (2026-10-24)

Wstępna inspekcja potwierdziła osobne splity train/test, per-record SHA-256 i licencję CC BY 4.0; karta źródłowa deklaruje zastosowanie do badań antyphishingowych oraz benchmarki o bazowych odsetkach 0,05%–5%. Pliki Parquet testu mają 9,18 GB, ale wybrane kolumny można odczytać przez HTTP Range; pełnych plików ani HTML nie pobrano. Właściwy pomiar i ograniczenia opisano powyżej. [Karta PhreshPhish](https://huggingface.co/datasets/phreshphish/phreshphish), [artykuł źródłowy arXiv](https://arxiv.org/abs/2507.10854).

## Ponowne pobranie i weryfikacja oficjalnego PhishVN v4 (2026-10-23)

Pobrano wyłącznie publiczny pakiet `PhishVN_v3.1.0_open.zip` z Mendeley Data (5 813 309 B, SHA-256 `308351E9D0C0FCA13A81F2F63524A7DEE08CCBA6C775848D125B3DA5525D0AB5`). Z archiwum odczytano `MANIFEST.txt` i wyodrębniono tylko `url_train.csv` oraz `url_val.csv`; `url_test.csv` nie był wyodrębniany ani otwierany. Obie sumy wejściowe zgadzają się z manifestem: train 7 826 219 B / `568E788EDA4BDF62531ADCDDD093373EF6A1E97FEEC1354063AE337325367B61`, validation 1 476 590 B / `D9EF64D29DF6639AF698EF228E5AF5EC6F8AE44C8F1A1DD1367F9BA6D073D81F`. Powtórzony pomiar reguł `2026.10.9`, gold+silver, bez feedu i bez otwierania adresów dał train TP=0, FP=3, TN=11 001, FN=2 076 oraz validation TP=0, FP=0, TN=1 561, FN=24 (`URLsOpened=0`). Wynik potwierdza wcześniejszy baseline; nie powstała nowa reguła ani nowy holdout. Archiwum i pliki CSV pozostają poza repozytorium.

## Aktualizacja pochodzenia PhishVN v4 (2026-10-23)

Oficjalna wersja PhishVN v4 (oznaczona jako v3.1.0) jest aktualizacją dokumentacji; według manifestu wszystkie pliki danych są bajtowo identyczne z v3. Dotychczasowe checksumy i wyniki splitów train/validation pozostają więc aktualne, a nowa wersja nie dostarcza niezależnego zbioru do ponownego pomiaru. Ukończony audyt etykiet na zaślepionej, warstwowej próbce 200 rekordów raportuje zgodność Cohen κ=0,609 dla czterech kategorii i κ=0,725 po zredukowaniu do abuse-vs-legitimate; źródłowa etykieta phishingu miała szacowane 12,1% błędów (95% CI 7,1–20,0%), skoncentrowanych w tier bronze, a etykieta benign 4,0%. Audyt obejmuje cały korpus; nie zakładamy, że gold/silver są bezbłędne. Nasza ewaluacja gold/silver bez zmiany splitu nadal jest pomiarem na bardziej wiarygodnym podzbiorze, nie dowodem pełnej jakości etykiet ani skuteczności produkcyjnej. [Strona PhishVN v4 i checksumy/claim o niezmienionych danych](https://data.mendeley.com/datasets/b97hxbxtpd/4), [instrumenty audytu etykiet](https://github.com/vuthainguyen1602/phishvn).

## Kontrola aktualnego feedu CERT na PhishVN train/validation (2026-10-23)

Porównano aktualny oficjalny feed domen CERT Polska z PhishVN v3.1.0 wyłącznie na splitach `url_train.csv` i `url_val.csv`, dla wierszy gold+silver. Feed z 2026-10-23 14:12:38 UTC zawierał 125 418 domen, SHA-256 `5D751903F91E874736E7A3C90513A2E44B65B1423689FA6D4D065102E996D995`. Train (13 080 wierszy; plik 7 826 219 B, SHA-256 `568E788EDA4BDF62531ADCDDD093373EF6A1E97FEEC1354063AE337325367B61`): TP=0, FP=0, TN=11 004, FN=2 076. Validation (1 585; 1 476 590 B, SHA-256 `D9EF64D29DF6639AF698EF228E5AF5EC6F8AE44C8F1A1DD1367F9BA6D073D81F`): TP=0, FP=0, TN=1 561, FN=24. Nie otwierano URL-i ani nie wykonywano DNS; skrypt dopasowywał wyłącznie hosty do lokalnej bazy feedu, a tymczasową bazę usunął po pomiarze. PhishVN test split nie został przyjęty ani odczytany. Wynik pokazuje, że obecna lista CERT nie uzupełnia pokrycia phishingu w tych dwóch splitach; nie jest oceną całego feedu ani powodem do strojenia URL-owych reguł.

Pomiar można odtworzyć skryptem `scripts/evaluate-phishvn-cert-feed.ps1`, podając wyłącznie oficjalne `url_train.csv` i `url_val.csv`. Źródłem feedu jest [CERT Polska — lista ostrzeżeń](https://cert.pl/lista-ostrzezen/).

**Powtórzenie z aktualnym feedem (2026-10-23 15:02 UTC):** ponowny pomiar tym samym, checksumowanym train/validation pobrał 125 421 domen, feed SHA-256 `CCD086A057422D783D42CF6B96538A4C3B15DA3C0FFECFB01D203911E2F6C1D9`. Wynik pozostał TP=0, FP=0, TN=11 004, FN=2 076 na train oraz TP=0, FP=0, TN=1 561, FN=24 na validation. `RulesVersion=2026.10.9`, `URLsOpened=0`; nie użyto PhishVN test splitu. To potwierdza, że świeża lista CERT nie uzupełnia rozpoznawania URL w tym zbiorze.

**Data pomiaru:** 2026-10-22  
**Wersja reguł:** `2026.10.6`
**Zakres:** wyłącznie kolumny `URL` i `label`; żaden adres nie został otwarty, rozwiązany przez DNS ani wysłany do usługi.

## Weryfikacja aktualnych reguł 2026.10.9 na PhishVN (2026-10-23)

Po zmianie semantyki feedu CERT ponownie uruchomiono ewaluator na oficjalnych splitach PhishVN v3.1.0. Sumy CSV zgodne z `MANIFEST.txt`: train 7 826 219 B / `568E788EDA4BDF62531ADCDDD093373EF6A1E97FEEC1354063AE337325367B61`, validation 1 476 590 B / `D9EF64D29DF6639AF698EF228E5AF5EC6F8AE44C8F1A1DD1367F9BA6D073D81F`, test 1 961 206 B / `B692882E8AE26B2C0B217C090E92D3A19307A26ACBFB3C8C89692DB26D409BC9`. Reguły działały bez lokalnego feedu, a URL-i nie otwierano. Gold+silver: train TP=0, FP=3, TN=11 001, FN=2 076; validation TP=0, FP=0, TN=1 561, FN=24; test TP=0, FP=2, TN=3 843, FN=487. Zmiana `2026.10.9` dotyczy wyłącznie dopasowania wpisów CERT do subdomen, więc nie poprawia offline URL-only detekcji. Zbiór testowy służy wyłącznie jako potwierdzenie bieżącego baseline'u; nie użyto go do doboru reguł. Wynik potwierdza, że F03 nadal ma krytycznie niską wykrywalność, a bez nowej wiarygodnej cechy i niezależnej walidacji nie należy podnosić poziomu alarmów.

## Przegląd kandydatów z train i validation (2026-10-23)

Bez otwierania URL-i sprawdzono kilka prostych cech z pola domeny/URL, wyłącznie na official train i validation gold/silver. Domena z co najmniej czterema cyframi dała train TP=62, FP=72 oraz validation TP=5, FP=12. Co najmniej trzy subdomeny dały train TP=5, FP=1, ale validation TP=0, FP=0. Tokeny logowania/weryfikacji w URL dały train TP=7, FP=45 i validation TP=0, FP=3. Wybrane koniunkcje tych sygnałów nie wykryły pozytywnych przykładów ani w train, ani w validation. Alternatywa „co najmniej cztery cyfry lub trzy subdomeny” wykryła train TP=67 przy FP=73, a validation TP=5 przy FP=12 z 24 pozytywnych. Mała walidacja i fałszywe alarmy nie uzasadniają tych progów jako alertu; nie dodano reguły i nie użyto test splitu do wyboru cechy.

Powtarzalny skan 30 jawnych cech jest dostępny jako `scripts/evaluate-phishvn-feature-candidates.ps1`; test kontraktu i guardów: `scripts/test-evaluate-phishvn-feature-candidates.ps1`. Skrypt przyjmuje tylko `url_train.csv` albo `url_val.csv`, raportuje checksumę wejścia i nie wyświetla adresów. Na train (13 080 gold/silver: 2 076 phishing, 11 004 benign) próg co najmniej 4 cyfr w hoście dał TP=62, FP=72; etykieta hosta ≥25 znaków TP=15, FP=18; token logowania/weryfikacji w pełnym URL TP=7, FP=15. Na validation (1 585: 24 phishing, 1 561 benign) odpowiednio: cyfry TP=5, FP=12; długa etykieta TP=0, FP=2; token w pełnym URL TP=0, FP=1. Próg ≥6 cyfr dał validation TP=3, FP=4. Co najmniej 5 etykiet hosta (prosty proxy liczby subdomen) dało train TP=5, FP=1 023 i validation TP=0, FP=1. Nowa cecha entropii etykiety rejestrowalnej ≥4,0 bitu wykryła 0/2 076 phishingowych train i 0/24 validation przy 0 fałszywych trafień w obu splitach PhishVN. Żaden z tych sygnałów nie uzasadnia samodzielnego alertu Moderate. Zbiór testowy PhishVN nie jest akceptowany przez skrypt i nie został użyty.

## Rozszerzenie listy podszywanych marek (2026-10-23)

Przetestowano z góry wybrane dodatkowe marki: Amazon, Facebook, Instagram, Netflix, LinkedIn, Dropbox, Spotify, Steam, Chase, Wells Fargo, Bank of America i Coinbase. Screening stosował wyłącznie wybrane kodyfikowalne warianty `url.brand` (dokładna nazwa w subdomenie, sufiksy login/secure/account/sso i odległość edycji 1 w zarejestrowanej etykiecie), z allowlistą kanonicznych domen właściciela. Odtwarzalny skrypt `scripts/evaluate-phishvn-brand-candidates.ps1` sprawdza wyłącznie gold/silver train lub validation, wymaga oficjalnej nazwy pliku i checksumy, weryfikuje kolumnę splitu i nie wypisuje URL-i; `scripts/test-evaluate-phishvn-brand-candidates.ps1` sprawdza odrzucenie splitu testowego.

W train (13 080 wierszy, checksum `568E788EDA4BDF62531ADCDDD093373EF6A1E97FEEC1354063AE337325367B61`) nie dopasowano żadnej z dodatkowych marek: TP=0, FP=0, TN=11 004, FN=2 076. W validation (1 585 wierszy, checksum `D9EF64D29DF6639AF698EF228E5AF5EC6F8AE44C8F1A1DD1367F9BA6D073D81F`) także nie było trafień: TP=0, FP=0, TN=1 561, FN=24. PhishVN test split nie został otwarty. Rozszerzenie listy nie poprawia więc pokrycia tego zbioru; nie zmieniono reguł produktu. Wynik nie dowodzi braku kampanii podszywających się pod te marki poza tym benchmarkiem.

## Entropia etykiety rejestrowalnej — diagnostyka URL-Phish i kontrola PhishVN (2026-10-23)

Dodano powtarzalny ewaluator `scripts/evaluate-url-phish-feature-candidates.ps1` oraz jego guard `scripts/test-evaluate-url-phish-feature-candidates.ps1`. Ewaluator liczy dziesięć z góry określonych cech, zapisuje wyłącznie agregaty i checksumę pliku, tworzy deterministyczny split po domenie rejestrowalnej, sprawdza brak przecieku domen i nie otwiera URL-i. Dane: URL-Phish v1 `sentinel-url-phish-v1-65z9twcx3r.csv`, 15 149 338 B, SHA-256 `D68B3CD0648DCF9C775347416AD1A8995E8A025921FBE3871CA6158D4DB3C3A1`; 30% holdout, seed `sentinel-url-phish-domain-v1`.

Cecha entropii etykiety rejestrowalnej ≥4,0 bitu dała w DomainTrain TP=212, FP=11, TN=69 759, FN=10 659, a w DomainHoldout TP=106, FP=1, TN=30 229, FN=5 623. Związek jest mały, a wyniki pochodzą z jednego już wcześniej badanego zbioru i nie stanowią ślepej walidacji. Przy dodaniu tej cechy jako osobnego sygnału Moderate do bieżącego analizatora regułowego (unia obecnego Moderate z entropy hit) wynik DomainTrain zmienił się z TP=491/FP=72 na TP=668/FP=83, a DomainHoldout z TP=1 395/FP=50 na TP=1 484/FP=51. Przyrost holdoutu to 89 trafień i 1 dodatkowy false positive, ale kontrola na niezależnym PhishVN train/validation wykazała 0 wykryć: odpowiednio 0/2 076 i 0/24 phishingowych URL-i przy 0 fałszywych trafień. Różnica wskazuje na zależność od źródła danych; cechy nie dodano do produktu. Znany PhishVN test split nie był odczytywany.

Odtworzenie: zbuduj Core w Release, uruchom `pwsh -NoProfile -File scripts/evaluate-url-phish-feature-candidates.ps1 -CsvPath C:\ścieżka\Dataset.csv`, a dla kontroli generalizacji użyj `scripts/evaluate-phishvn-feature-candidates.ps1` wyłącznie z `url_train.csv` i `url_val.csv`. Nowy guard jest częścią `scripts/build-user.ps1`.

## Kontrola źródła LegitPhish z PhiLegit-100K (2026-10-23)

Pobrano z publicznego [PhiLegit-100K v1](https://data.mendeley.com/datasets/726pyz4j53/1) archiwum RAR (6 258 453 B, SHA-256 `D95A1419F4B2D1CB98C3CE31FEDF7CDABD148F70F42E6ED3DE6244366B525558`), zgodne z metadanymi pliku. Oficjalny README podaje licencję CC BY 4.0, źródła PhiUSIIL i LegitPhish oraz mapowanie etykiet (0=phishing, 1=legitimate). Z pełnego CSV (116 949 776 B, SHA-256 `66D79283FF485A157C961D3575E60009898C871D48ACC74FD9CA689C43FF8BA8`) użyto wyłącznie `source_dataset=LegitPhish`, odrzucając wiersze PhiUSIIL i `Both`; zachowano same URL-e i etykiety, a `features_json` pominięto. Wyfiltrowany plik diagnostyczny miał 19 617 wierszy: 19 450 phishingowych i 167 benign, po odwróceniu etykiet do formatu ewaluatora; SHA-256 `5A6F54F210438CAD9ADECC50400D2615E35B03E51F38F242EE5EAFB248788A65`. Archiwum, pełny CSV i podzbiór pozostawały poza repozytorium.

Podzbiór podzielono deterministycznie 70/30 po domenie rejestrowalnej, seed `sentinel-philegitlegit-domain-v1`; split nie przecinał domen. W DomainHoldout było 6 322 URL-i z 3 550 domen: 6 255 phishingowych i 67 benign. Obecne reguły `2026.10.9` uzyskały TP=3 878, FN=2 377, FP=1, TN=66 (recall 61,98%, FPR 1,49%). Entropia etykiety rejestrowalnej ≥4,0 bitu sama wykryła 3 phishingowe URL-e i 0 benign. Unia z obecnym progiem Moderate dała TP=3 881, FN=2 374, FP=1, TN=66, czyli trzy dodatkowe trafienia bez zmiany liczby FP. Próbka benign w holdoucie (67 URL-i) jest za mała do wiarygodnego oszacowania rzadkich fałszywych alarmów, domeny nie były odseparowane od wcześniej badanych korpusów, a miks źródeł jest mocno niezrównoważony. Wynik jest wyłącznie diagnostyczny; nie uzasadnia wdrożenia cechy ani roszczenia o skuteczności produkcyjnej. Wspierająca kontrola PhishVN pozostaje 0/2 076 trafień w train i 0/24 w validation.

## Dodatkowy test domenowy URL-Phish v1 (2026-10-23)

Pobrano `Dataset.csv` z oficjalnego [Mendeley Data URL-Phish v1](https://data.mendeley.com/datasets/65z9twcx3r/1), autorzy Dam Minh Linh i Tran Cong Hung, DOI `10.17632/65z9twcx3r.1`, licencja [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Artykuł opisuje 100 000 URL-i benign pochodzących z ROR i 11 660 phishingowych z PhishTank z okresu 2024-11–2025-09, a opublikowany podział 75/10/15 jest losowy. Ten test nie używa tamtego podziału ani przygotowanych cech: bierze wyłącznie surowe `url` i `label`, po czym tworzy deterministyczny podział 70/30 po domenie rejestrowalnej, bez przenoszenia domen między grupami.

Snapshot CSV: 15 149 338 B, SHA-256 `D68B3CD0648DCF9C775347416AD1A8995E8A025921FBE3871CA6158D4DB3C3A1`. Plik pozostaje w katalogu tymczasowym i nie jest częścią repozytorium. Powtarzalne odtworzenie wymaga pobrania CSV z oficjalnej strony, zbudowania Core i uruchomienia:

```powershell
dotnet build src/Sentinel.Core/Sentinel.Core.csproj -c Release
pwsh -NoProfile -File scripts/evaluate-url-phish.ps1 -CsvPath C:\ścieżka\Dataset.csv
```

Przy regułach `2026.10.8`, progu `Moderate`, bez feedu i bez otwierania URL-i, ewaluator dwukrotnie zwrócił identyczne wyniki. `DomainTrain`: TP=491, FP=72, TN=69 698, FN=10 380, recall=4,52%, FPR=0,1032%. `DomainHoldout`: TP=1 395, FP=50, TN=30 180, FN=4 334, recall=24,35%, FPR=0,1654%, precision=96,54%. W żadnej próbce nie wykryto niepoprawnego URL-a; żadna domena rejestrowalna nie przecina obu grup.

To pomiar diagnostyczny, nie walidacja produkcyjna ani ślepy test: źródła i etykiety różnią się od PhishVN, część benign pochodzi z wiarygodnych instytucji, a sam wynik holdoutu jest już obejrzany. Nie zmieniano reguł po pomiarze. Wynik nie usuwa krytycznej luki F03 ani niskiego recall na PhishVN; nie należy go uogólniać na rzeczywisty ruch ani interpretować precision jako prawdopodobieństwa bezpieczeństwa.

**Kontrola ryzyka TLD na `DomainTrain`:** w tym zbiorze `.dev` występuje przy 954 URL-ach phishingowych i jednym benign, `.app` przy 326 phishingowych i jednym benign, a `.icu` przy 192 phishingowych i żadnym benign. Rozkład benign jest zbyt wąski, by uzasadnić alarmowanie na podstawie tych sufiksów. Google Registry opisuje `.dev` jako przestrzeń dla programistów i technologii, a `.app` jako przestrzeń dla aplikacji; ich legalne zastosowania są znacznie szersze niż pojedyncze przykłady z tego pliku. ([Google Registry .dev](https://www.registry.google/domains/dev/), [Google Registry .app](https://www.registry.google/domains/app/)). Nie dodano tych ani podobnych TLD do reguł. Sam niski FPR w URL-Phish nie jest wiarygodnym oszacowaniem częstości fałszywych alarmów w produkcji.

Źródła: [rekord zbioru i licencja](https://data.mendeley.com/datasets/65z9twcx3r/1), [artykuł opisujący dane i losowy split](https://doi.org/10.1016/j.dib.2025.112162).

**Zmiany po pomiarze:** wersja `2026.10.7` dodaje analizę do 10 surowych adresów HTTP/HTTPS osadzonych w treści wiadomości, a `2026.10.8` sprawdza te linki oraz jawny URL względem świeżej, lokalnie zaimportowanej listy CERT Polska. Testy benchmarkowe tworzą `ThreatAnalysisEngine` bez feedu, więc wyniki poniżej mierzą wyłącznie reguły URL i nie obejmują dopasowań do lokalnej listy. Metryki nadal dotyczą heurystyk URL; nie są pomiarem nowej kontroli reputacyjnej. F03 pozostaje częściowe.

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

Dokumentacja v3.1.0 odnotowuje ukończony audyt etykiet: zgodność czterech anotatorów Cohen's κ=0,609 (κ=0,725 dla rozróżnienia phishing/benign), oszacowany szum etykiet wśród przykładów phishingowych 12,1% (95% CI 7,1–20,0%), skupiony głównie w tier bronze, oraz 4,0% w benign. To dodatkowo uzasadnia oddzielne raportowanie bronze. Te wartości pochodzą z audytu anotacji, nie są korektą ani walidacją etykiet zbioru użytego w ewaluacji Sentinel. Pliki danych v4 są niezmienione względem v3; szczegóły są w [oficjalnym opisie PhishVN v3.1.0](https://data.mendeley.com/datasets/b97hxbxtpd/4).

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

### Kandydat lokalnej listy nazw banków/platform (train → validation)

Dodany `scripts/evaluate-phishvn-brand-tokens.ps1` mierzy wyłącznie ustaloną listę 12 tokenów w polu `domain`, z granicami tokenu, na oficjalnych splitach train i validation oraz domyślnie tylko gold/silver. Guard odrzuca wiersze spoza splitu, raport zawiera hash i rozmiar obu plików, a żaden URL nie jest otwierany. Fixture test jest uruchamiany przez pełny `scripts/build-user.ps1`.

Lista `vietcombank,vietinbank,agribank,bidv,techcombank,mbbank,vpbank,acb,sacombank,shopee,momo,zalopay` dała train TP=136, FP=16, TN=10 988, FN=1 940 (recall 6,5511%, FPR 0,1454%). Na validation: TP=0, FP=2, TN=1 559, FN=24 (recall 0%, FPR 0,1281%). Pliki: train SHA-256 `568E788EDA4BDF62531ADCDDD093373EF6A1E97FEEC1354063AE337325367B61`, validation `D9EF64D29DF6639AF698EF228E5AF5EC6F8AE44C8F1A1DD1367F9BA6D073D81F`. W validation jest tylko 24 pozytywnych przykładów; wynik nie uzasadnia globalnej listy ani reguły produktu. Nie zmieniono detekcji i testowy split nie był odczytywany.

```powershell
pwsh -NoProfile -File scripts/evaluate-phishvn-brand-tokens.ps1 `
  -TrainCsvPath C:\ścieżka\PhishVN\data\splits\url_train.csv `
  -ValidationCsvPath C:\ścieżka\PhishVN\data\splits\url_val.csv
pwsh -NoProfile -File scripts/test-evaluate-phishvn-brand-tokens.ps1
```

Sprawdziłem też substringy w etykiecie domeny rejestrowalnej dla kandydatów nazw banków/platform z PhishVN. Liczby train liczą wiersze URL (wzorce mogą się nakładać): `vietcombank` 36 phishingowych/1 legalny, `bidv` 16/2, `vpb` 23/1, `shopee` 32/7 i `momo` 12/3. W validation z 24 phishingowych adresów tylko `momo` wystąpiło w jednym, a jednocześnie w dwóch legalnych; wymienione pozostałe nazwy banków/platform nie miały pozytywnego trafienia. Te małe i rozbieżne wyniki nie potwierdzają bezpiecznej reguły brandowej; nie dodano nowej listy marek ani nie zmieniono detekcji.

Pole metadanych PhishVN `suspicious_tld` oznacza 539/2 076 phishingowych i 130/11 004 legalnych URL-i w train oraz 3/24 phishingowe i 23/1 561 legalnych w validation. Nie jest to wyjście ani reguła Sentinel, a jego szersza definicja nie została przeniesiona do produktu. Trzy oznaczone walidacyjne phishingowe adresy mają sufiksy `.help`, `.shop` i `.vip`; każdy z nich samodzielnie daje bieżącemu analizatorowi poziom `Information`, bez wskaźników. W train `.vip` występuje w 80 phishingowych i 8 legalnych wierszach, `.shop` w 4 i 18, a `.help` w 2 i 0. Małe walidacyjne liczby i rozbieżność `.shop` nie uzasadniają obecnie nowej reguły sufiksów ani podniesienia ryzyka.

### Dodatkowy kandydat: cyfry w nazwie domeny (2026-10-23)

W eksploracyjnej analizie gold/silver policzono cyfry w kolumnie `domain` dla progów 1–6, używając wyłącznie oficjalnych plików train i validation. Dla progu co najmniej 4 cyfr train zawiera 62/2 076 phishingowych oraz 72/11 004 legalnych rekordów; validation zawiera 5/24 phishingowych oraz 12/1 561 legalnych. To odpowiednio recall 2,99%/20,83% i FPR 0,654%/0,769%. Oceniane wejścia: `url_train.csv` 7 826 219 B, SHA-256 `568E788EDA4BDF62531ADCDDD093373EF6A1E97FEEC1354063AE337325367B61`; `url_val.csv` 1 476 590 B, SHA-256 `D9EF64D29DF6639AF698EF228E5AF5EC6F8AE44C8F1A1DD1367F9BA6D073D81F`. Baseline `scripts/evaluate-phishvn.ps1` na tych samych wejściach potwierdził przy progu Moderate: train TP=0, FP=3, FN=2 076; validation TP=0, FP=0, FN=24; parser odrzucił 0 adresów i żadnego nie otworzył. Zbiór validation ma tylko 24 pozytywne URL-e, a przegląd progów obejmował oba pliki, więc liczby są eksploracyjne, nie stanowią niezależnego potwierdzenia jakości. Nie dodano reguły: sygnał nie wykrywa większości phishingu, a przy nieznanej i prawdopodobnie niskiej częstości bazowej mógłby dominować fałszywymi ostrzeżeniami. Pliku `url_test.csv` nie użyto w tej analizie; znany wynik testowy dla reguł `2026.10.6` pozostaje niezmieniony i nie jest wynikiem nowej wersji.

### Zbiór parafraz SMS/e-mail P3 — audyt pokrycia tekstu (2026-10-23)

Datasheet PhishVN opisuje oficjalny benchmark jako zbiór URL; wiadomości tekstowe są poza tym zakresem. W pliku `data/attacks/p3_paraphrase.csv` znajdującym się **wewnątrz pobranego archiwum** jest 386 parafraz phishingowych: 193 warianty `a` oznaczone `train` i 193 warianty `b` oznaczone `test`, kanały SMS/e-mail. Ten plik nie jest dołączony do bieżącego repozytorium (checkout nie zawiera katalogu `data/`). W pobranym `PhishVN_v3.1.0_open.zip` (5 813 309 B, SHA-256 `308351E9D0C0FCA13A81F2F63524A7DEE08CCBA6C775848D125B3DA5525D0AB5`) suma SHA-256 pliku P3 wyniosła `45F6214834E135DE9CED7BB9B6DBCE4BE7F9AF76D395C801BE5E62205C443980`, zgodnie z `MANIFEST.txt`. Odtworzenie wymaga pobrania archiwum z [oficjalnej strony PhishVN](https://data.mendeley.com/datasets/b97hxbxtpd/4), sprawdzenia SHA-256 ZIP i pliku względem tych wartości oraz lokalnego rozpakowania; żaden surowy tekst wiadomości nie jest potrzebny w repozytorium.

Sprawdzenie niezmienionych reguł `2026.10.6` na tekście dało 0/193 wykryć przy progu Moderate w wariancie a/train i 0/193 w wariancie b/test; żaden tekst nie wyemitował wskaźnika. To wyłącznie pomiar pokrycia pozytywnych próbek, nie pełna ewaluacja: plik zawiera sam phishing i nie pozwala oszacować false-positive rate. Ponadto wszystkie 193 `src_id` występują w obu rolach: `train` i `test` odpowiadają wariantom a/b tych samych źródeł, więc test nie jest niezależnym holdoutem wiadomości. Nie strojono ani nie zmieniano reguł na podstawie tego pliku. Wynik potwierdza lukę lokalizacji i obsługi wiadomości w języku wietnamskim, ale nie uzasadnia alarmu bez benign próbek i niezależnego podziału po źródłowej wiadomości.
