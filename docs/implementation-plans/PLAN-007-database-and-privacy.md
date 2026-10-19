# PLAN-007 — baza danych i prywatność

1. **Cel:** odporna lokalna baza z jasną retencją, backup/restore i kontrolą dostępu.
2. **Stan obecny:** SQLite historii/ustawień jest po migracji v6, historia ma retencję i limit odczytu 500 zdarzeń. UI/IPC eksportuje redagowany JSON, tworzy kopie obu baz i przywraca obie bazy po walidacji integralności/schematu/metadanych. Restore historii zachowuje profil instalacji; restore wiedzy odtwarza dokumenty i FTS5. UI jawnie informuje o braku szyfrowania. Testy sprawdzają round-trip, wyszukiwanie po restore i odrzucenie uszkodzonych kopii bez utraty aktywnych danych.
3. **Braki:** limity bazy historii/dysku, test braku miejsca i sprawdzenia ACL ścieżek. Baza wiedzy ogranicza indeks do 100 dokumentów i 20 mln znaków, odrzucając nadmiar bez usuwania istniejących danych. UI/status pokazuje rozmiar DB/WAL/SHM, page count/freelist i rekordy obu baz; 32 równoległe zdarzenia zapisu przechodzą test bez utraty rekordów. Test obciążeniowy, disk-full i ACL nadal wymagają wykonania. Uszkodzone SQLite jest testowane, ale inne rodzaje awarii jeszcze nie.
4. **Decyzje:** ACL per-user; nie obiecywać szyfrowania przy braku klucza; export redaguje dane; backup atomowy i wersjonowany.
5. **Zależności:** wspólny schema, Windows ACL, decyzje retencji.
6. **Etapy:** (a) model threat/data inventory; (b) diagnostyka obu baz i limity importu wiedzy wdrożone; limit historii/dysku nadal wymaga decyzji architektonicznej; (c) backup obu baz i kontrola możliwości otwarcia kopii; (d) UI export/delete/backup/restore; (e) testy disk full/concurrency/ACL.
7. **Pliki:** `LocalStore.cs`, testy, Engine, UI, privacy docs.
8. **Prywatność:** baza nieszyfrowana w spoczynku; minimalizować, redagować logi, jawnie pokazać gdzie leży.
9. **Testy:** eksport bez pełnej treści/URL, kopia obu SQLite, restore dokumentów i wyszukiwania FTS5, restore historii/settings z zachowaniem profilu, odrzucenie corrupt bez zmiany aktywnych danych, retencja, 32 równoległe zapisy PASS, pomiar storage z danymi PASS; dodano test odmowy 101. dokumentu bez utraty indeksu. Brak miejsca i ACL check pozostają niewykonane.
10. **Akceptacja:** kopie przechodzą `integrity_check`; restore obsługiwanych wersji waliduje dane przed transakcją; błędna kopia nie modyfikuje aktywnej bazy; profil instalacji pozostaje bez zmian; eksport nie zawiera surowej treści/URL.
11. **Ryzyka:** SQLite file encryption wymaga osobnej zależności/klucza i może utrudnić naprawę.
12. **Status:** `IN_PROGRESS` — eksport, backup/restore obu baz, pomiar rozmiaru, limity bazy wiedzy i test współbieżnych zapisów wdrożone oraz testowane; testy braku miejsca, obciążeniowe i ACL pozostają.

