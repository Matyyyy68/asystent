# Witryna i kierunek interfejsu Sentinel AI

## Założenie

Publiczna witryna jest pierwszym miejscem dla użytkownika produktu: objaśnia rzeczywiste funkcje, prywatność i sposób rozpoczęcia pracy. Link „Panel zespołu” prowadzi do istniejącego, uwierzytelnianego panelu administratora pod `/admin/`. To nie jest jeszcze portal samoobsługowy klientów — serwer nie obsługuje kont klienta, zgłoszeń serwisowych ani formularza kontaktowego. Oficjalny adres kontaktowy należy dodać, gdy zostanie ustalony. Witryna nie wysyła treści do zewnętrznych usług i nie używa zewnętrznych fontów, skryptów, analityki ani plików cookie.

Makiety interfejsu pokazują dane ilustracyjne i są oznaczone jako podgląd. Funkcje i twierdzenia na stronie odpowiadają aktualnej dokumentacji produktu; nie przedstawiają Sentinel AI jako certyfikowanego antywirusa ani nie obiecują wykrywania wszystkich zagrożeń. Link do instalatora wskazuje bieżący plik wersjonowany w repozytorium.

## Zasady projektu

- Hierarchia strony prowadzi od jednej obietnicy produktu do funkcji, prywatności, konfiguracji firmowej i pobrania.
- Jasne tło, ograniczona paleta granatu, błękitu i mięty oraz typografia systemowa utrzymują kontrast i czytelność bez pobierania zasobów od dostawcy zewnętrznego.
- Desktopowa aplikacja używa pionowej nawigacji z widocznym zaznaczeniem aktywnej sekcji. Przyciski, karty i tabele mają spójne obramowanie, odstępy i stany fokusu.
- Układ strony składa się do jednej kolumny na wąskim ekranie; menu mobilne ma poprawny stan `aria-expanded`, a animacje respektują `prefers-reduced-motion`.
- Interfejs zachowuje istniejące funkcje, lokalne ustawienia motywu i granice prywatności. Nie dodaje fikcyjnych wskaźników do działającej aplikacji.

## Odniesienia projektowe

Wdrożenie wykorzystuje ogólne, sprawdzalne zasady publicznych standardów, a nie kopiuje konkretnej marki:

- [W3C — WCAG 2.2 Quick Reference](https://www.w3.org/WAI/WCAG22/quickref/): klawiatura, widoczny fokus, semantyczne nagłówki, kontrast, ograniczenie ruchu.
- [Microsoft Fluent 2 — Design](https://fluent2.microsoft.design/): czytelna hierarchia, system odstępów i spójne stany komponentów dla interfejsów Windows.
- [Material Design 3 — Layout](https://m3.material.io/foundations/layout/overview): adaptacyjny układ, siatka i przejście z wielu kolumn do układu mobilnego.

## Walidacja

Trasy `/`, `/site.css` i `/site.js` są częścią aplikacji serwera. Test smoke sprawdza, że strona oraz zasoby są serwowane, a nagłówki polityki bezpieczeństwa treści i ochrony przed ramkami pozostają aktywne. Stronę można przetestować lokalnie, uruchamiając API i otwierając `http://127.0.0.1:5080/`; panel zespołu znajduje się pod `/admin/`.
