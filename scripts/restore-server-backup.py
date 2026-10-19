#!/usr/bin/env python3
"""Restore an offline Sentinel Server SQLite backup with a pre-restore safety copy."""
import argparse
from contextlib import closing
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REQUIRED_TABLES = {"administrators", "admin_sessions", "admin_audit", "devices", "device_groups", "server_policies"}


def readonly_uri(path: Path) -> str:
    return path.resolve().as_uri() + "?mode=ro"


def validate_database(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("Plik bazy nie istnieje albo jest pusty.")
    with closing(sqlite3.connect(readonly_uri(path), uri=True, timeout=5)) as connection:
        with connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
            if result is None or result[0] != "ok":
                raise ValueError("Baza nie przechodzi kontroli integralności SQLite.")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (5, 6, 7):
                raise ValueError(f"Nieobsługiwana wersja schematu bazy: {version}.")
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            missing = REQUIRED_TABLES - tables
            if missing:
                raise ValueError("Plik nie jest bazą Sentinel Server; brak wymaganych tabel.")


def snapshot(source: Path, destination: Path) -> None:
    with closing(sqlite3.connect(readonly_uri(source), uri=True, timeout=5)) as src:
        with closing(sqlite3.connect(destination, timeout=5)) as dst:
            src.backup(dst)
            dst.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            dst.commit()


def restore(backup: Path, database: Path) -> Path | None:
    backup = backup.resolve(strict=True)
    database = database.resolve()
    if backup == database:
        raise ValueError("Plik kopii i docelowa baza muszą być różne.")
    validate_database(backup)
    database.parent.mkdir(parents=True, exist_ok=True)

    safety_copy = None
    if database.exists():
        validate_database(database)
        safety_dir = database.parent / "Backups"
        safety_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        safety_copy = safety_dir / f"pre-restore-{stamp}.db"
        snapshot(database, safety_copy)
        validate_database(safety_copy)

    descriptor, staged_name = tempfile.mkstemp(prefix=".sentinel-restore-", suffix=".db", dir=database.parent)
    os.close(descriptor)
    staged = Path(staged_name)
    try:
        snapshot(backup, staged)
        validate_database(staged)
        with staged.open("rb+") as stream:
            stream.flush()
            os.fsync(stream.fileno())
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(database) + suffix)
            if sidecar.exists():
                sidecar.unlink()
        os.replace(staged, database)
        if os.name != "nt":
            directory_fd = os.open(database.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return safety_copy
    finally:
        staged.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Przywraca kopię Sentinel Server po zatrzymaniu usługi.")
    parser.add_argument("--backup", required=True, type=Path, help="zweryfikowany plik kopii .db")
    parser.add_argument("--database", required=True, type=Path, help="ścieżka aktywnej bazy sentinel-server.db")
    parser.add_argument("--service-stopped", action="store_true", help="potwierdzenie, że Sentinel Server jest zatrzymany")
    parser.add_argument("--yes", action="store_true", help="potwierdzenie podmiany bazy")
    args = parser.parse_args()
    if not args.service_stopped:
        parser.error("Najpierw zatrzymaj usługę/proces Sentinel Server i podaj --service-stopped.")
    if not args.yes:
        parser.error("Podmiana bazy wymaga jawnego potwierdzenia --yes.")
    try:
        safety_copy = restore(args.backup, args.database)
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f"Błąd przywracania: {error}", file=sys.stderr)
        return 1
    print(f"Przywrócono kopię: {args.database.resolve()}")
    if safety_copy:
        print(f"Kopia stanu sprzed przywrócenia: {safety_copy}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
