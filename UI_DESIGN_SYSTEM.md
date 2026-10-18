# System projektowy Sentinel AI User

Aktualny klient to React + TypeScript w `desktop/`, uruchamiany w Electron. Style i komponenty są w `desktop/src/style.css` i `desktop/src/main.tsx`; ikony pochodzą z Lucide. Panel administratora serwera w `server/` jest odrębnym produktem i ma własne style.

## Zasady wizualne

Interfejs używa pomarańczowego akcentu działania, niebieskiego akcentu informacji, czytelnych stanów ryzyka oraz jasnego i ciemnego motywu. Status ma widoczną etykietę i nie opiera się wyłącznie na kolorze. Ruch respektuje `prefers-reduced-motion`; fokus klawiatury pozostaje widoczny.

Ekrany opisują rzeczywisty stan silnika, lokalnej bazy i integracji. Historia pokazuje zdarzenia z SQLite, a widoki DNS i TCP korzystają z systemowych danych z jasno opisanym zakresem. Gdy funkcja nie istnieje, interfejs pokazuje ograniczenie zamiast sugerować aktywną ochronę. Nie ma fikcyjnych liczników zablokowanych ataków.

Electron udostępnia rendererowi tylko ograniczone metody przez preload i `contextBridge`. Renderer nie ma dostępu do Node ani do systemu plików. Motyw, pierwsze uruchomienie, stany pustej historii, błędy silnika i diagnostyka są częścią aktualnego UI.

## Weryfikacja zmian UI

```powershell
cd desktop
npm.cmd run lint
npm.cmd run build
```

Test pełnego przepływu IPC opisuje `CHANGELOG.md`; test na czystym Windows i przeglądarkach wymaga procedury z `docs/USER-VALIDATION.md`.
