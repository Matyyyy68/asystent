# Filozofia produktu Sentinel AI

**Stan: kierunek docelowy; wdrożenie etapowe, nie ukończone.**

Sentinel AI ma samodzielnie wykonywać lokalne, jawnie opisane kontrole, upraszczać decyzje użytkownika i nie przedstawiać nieznanego wyniku jako potwierdzonego zagrożenia. Interfejs nie może sugerować blokowania, izolacji ani pełnego pokrycia, jeśli aktywny komponent tego nie zapewnia.

## Zasady produktu

- Zwykły widok pokazuje prosty stan oraz źródła, które rzeczywiście odpowiadają.
- Pierwsze uruchomienie automatycznie odpytuje lokalny silnik i uruchamia bieżący cykl zbierania. Nie jest to pełny skan dysku ani ocena bezpieczeństwa całego komputera.
- Reguły, lokalna reputacja i dane systemowe działają bez modelu AI; model pozostaje opcjonalny.
- Nie usuwamy ani nie kwarantannujemy plików na podstawie samego wyniku AI.
- Brak wykrycia nie jest werdyktem bezpieczeństwa. Ograniczone lub niedostępne źródło musi pozostać widoczne jako takie.
- Prywatność i zgoda są częścią zachowania produktu: brak ukrytego przechwytywania treści HTTPS, haseł, ekranu i korespondencji.

## Aktualny etap

Aktualny interfejs ma prostszy ekran główny, automatyczne pierwsze sprawdzenie i zwinięty obszar narzędzi zaawansowanych. `Sentinel.Agent` uruchamia silnik niezależnie od Electron i działa w sesji użytkownika, ale nie jest usługą Windows SCM. Nowe profile włączają lokalne źródła monitorowania; zapisane preferencje pozostają zachowane. Stan ochrony nie oznacza blokowania, kwarantanny ani pełnego pokrycia. Szczegóły: [postęp projektu](PROJECT_PROGRESS.md), [ograniczenia](KNOWN-LIMITATIONS.md).
