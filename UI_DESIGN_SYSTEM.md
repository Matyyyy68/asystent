# Sentinel AI — system projektowy UI

Wspólny język wizualny obejmuje klienta WPF i panel administratora hostowany przez serwer. Klient prowadzi użytkownika do trzech informacji: jaki jest stan analizy, co zapisano w lokalnej historii i co można zrobić dalej. Panel administratora używa tych samych kolorów oraz rytmu typograficznego, a zwiększa gęstość danych i liczbę działań.

## Tokeny

| Rola | Jasny motyw | Ciemny motyw |
|---|---|---|
| Tło aplikacji | `#F5F7FA` | `#121925` |
| Powierzchnia | `#FFFFFF` | `#1B2635` |
| Tekst podstawowy | `#202938` | `#F1F5F9` |
| Tekst pomocniczy | `#748094` | `#A9B5C5` |
| Obramowanie | `#E4E9F0` | `#344255` |
| Akcent działania | `#F28C38` | `#F28C38` |
| Akcent nawigacji/info | `#3478F6` | `#75A5FF` |
| Stan poprawny | `#22845A` | `#69D3A0` |
| Uwaga | `#AA6800` | `#F6C66A` |
| Zagrożenie | `#B93838` | `#FF8C8C` |

Stosujemy typografię systemową Segoe UI Variable/Segoe UI. Tekst podstawowy ma co najmniej 14 px, pomocniczy 13 px. Tytuł widoku nie przekracza 26 px. Odstępy bazowe to 4, 8, 12, 16 i 24 px. Promienie wynoszą 9 px dla kontrolek i 16 px dla kart. Cień nie jest potrzebny do oddzielenia powierzchni; używamy subtelnego obramowania.

## Komponenty

- **PrimaryButton** — pomarańczowe, najważniejsze działanie w danym widoku; **SecondaryButton** — spokojne działania poboczne.
- **Card** — biała/ciemna powierzchnia z promieniem 16 px, delikatną ramką i równym paddingiem.
- **SectionTitle**, **MutedText**, **StatValue** — wspólna hierarchia nagłówków, opisów i liczb.
- **StatusBadge** — tekstowy status z kolorem i ikoną; sam kolor nigdy nie przenosi znaczenia.
- **DataGrid/DataTable** — widoczne nagłówki, sortowanie, czytelny fokus i brak nadmiaru danych w wierszu.
- **EmptyState/ErrorState** — krótki opis i dostępne działanie; błędy nie pokazują wyjątków ani sekretów.
- **ConfirmationDialog** — jawne potwierdzenie dla odłączenia urządzenia lub usunięcia danych.
- **ProtectionStatusCard** — klient pokazuje wyłącznie rzeczywisty stan: pauzę, dostępność analizy na żądanie albo aktywną analizę zmian okna.

Style WPF i zasoby kolorów znajdują się w `src/Sentinel.Desktop/Themes/`; aplikacja przełącza `Light.xaml` i `Dark.xaml`, a wartość `System` odczytuje ustawienie Windows. Panel admin używa odpowiadających im zmiennych CSS w `server/src/Sentinel.Server.Api/wwwroot/admin/`. Ikony klienta korzystają z jednego systemowego zestawu Segoe MDL2 Assets. Stany fokus, hover i disabled są częścią wspólnych stylów, a nie lokalnych dekoracji ekranów.

## Stan implementacji

Klient ma ekran startowy oparty na rzeczywistej lokalnej historii, ekran ręcznej i okiennej analizy, historię i ustawienia. Aplikacja ma prawdziwą ikonę zasobnika, zamykanie okna do zasobnika, start do zasobnika jako opcję oraz aktywację istniejącej instancji. Zmiana motywu i wybór startu do zasobnika są zapisywane lokalnie. Klient nie przedstawia analizy regułowej jako gwarantowanej, ciągłej ochrony.

Panel administratora używa tej palety i komponentów przez własne zmienne CSS. Pokazuje wyłącznie dane z dostępnych API: urządzenia, grupy, polityki, zdarzenia, konta i audyt. Dashboard wylicza ryzyko wyłącznie z maksymalnie 100 najnowszych zdarzeń i jawnie opisuje ten zakres. Sekcje AI, bazy wiedzy, diagnostyki, kopii i konfiguracji serwera wskazują brakujące źródła API; nie pokazują fikcyjnych wskaźników ani niedziałających akcji.
