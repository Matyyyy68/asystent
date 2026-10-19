#!/usr/bin/env python3
import importlib.util
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("restore_server_backup", Path(__file__).with_name("restore-server-backup.py"))
RESTORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESTORE)


def make_database(path: Path, admin: str) -> None:
    with closing(sqlite3.connect(path)) as database:
        with database:
            for name in ("administrators", "admin_sessions", "admin_audit", "devices", "device_groups", "server_policies"):
                database.execute(f"CREATE TABLE {name}(id TEXT PRIMARY KEY)")
            database.execute("CREATE TABLE marker(value TEXT NOT NULL)")
            database.execute("INSERT INTO administrators VALUES(?)", (admin,))
            database.execute("INSERT INTO marker VALUES(?)", (admin,))
            database.execute("PRAGMA user_version=5")


class RestoreBackupTests(unittest.TestCase):
    def test_restore_is_atomic_and_keeps_pre_restore_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="sentinel restore ") as directory:
            root = Path(directory)
            backup, live = root / "backup.db", root / "server.db"
            make_database(backup, "backup-admin")
            make_database(live, "live-admin")

            safety_copy = RESTORE.restore(backup, live)

            self.assertIsNotNone(safety_copy)
            RESTORE.validate_database(live)
            with closing(sqlite3.connect(live)) as database:
                with database:
                    self.assertEqual("backup-admin", database.execute("SELECT id FROM administrators").fetchone()[0])
            RESTORE.validate_database(safety_copy)
            with closing(sqlite3.connect(safety_copy)) as database:
                with database:
                    self.assertEqual("live-admin", database.execute("SELECT id FROM administrators").fetchone()[0])

    def test_invalid_backup_is_rejected_without_changing_live_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup, live = root / "invalid.db", root / "server.db"
            backup.write_bytes(b"not sqlite")
            make_database(live, "live-admin")
            with self.assertRaises((ValueError, sqlite3.Error)):
                RESTORE.restore(backup, live)
            with closing(sqlite3.connect(live)) as database:
                with database:
                    self.assertEqual("live-admin", database.execute("SELECT id FROM administrators").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
