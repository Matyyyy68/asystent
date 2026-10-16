# Kopie i przywracanie bazy Sentinel Server

Panel administratora systemu → **Kopie zapasowe** tworzy spójny snapshot bazy SQLite, zapisuje zdarzenie audytowe i pobiera plik `.db`. Kopia zawiera dane urządzeń, zdarzenia, polityki, konta i audyt; traktuj ją jak poufne dane administracyjne i przechowuj w ograniczonym dostępie.

Przywracanie jest operacją offline. Zatrzymaj proces lub usługę Sentinel Server przed podmianą bazy. Przywrócenie starszej kopii cofa także stan urządzeń, sesji, zaproszeń, polityk i audytu do chwili wykonania kopii. Po zatrzymaniu usługi uruchom:

```text
python3 scripts/restore-server-backup.py --backup /bezpieczna/sciezka/sentinel-server-....db --database /var/lib/sentinel-ai/server/sentinel-server.db --service-stopped --yes
```

Na Windows podaj pełne ścieżki Windows i użyj `python` zamiast `python3`, jeśli tak jest zainstalowany. `--service-stopped` i `--yes` są wymagane. Narzędzie sprawdza integralność SQLite i wersję schematu, wykonuje kopię aktualnej bazy do sąsiedniego katalogu `Backups`, przygotowuje nowy plik, weryfikuje go i podmienia bazę atomowo. Gdy serwer nigdy wcześniej nie został uruchomiony, kopia bieżącego pliku nie powstanie.

Po przywróceniu uruchom serwer i sprawdź `/readyz`. Zachowaj kopię sprzed przywrócenia do czasu potwierdzenia poprawności działania.

Testy narzędzia: `python3 -m unittest scripts/test-restore-server-backup.py`.
