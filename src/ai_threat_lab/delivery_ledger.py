"""Idempotency claims for optional training transports; never stores message contents."""

import sqlite3
from contextlib import closing
from pathlib import Path
from threading import Lock
from typing import Protocol

from .models import ValidationError


class DeliveryLedger(Protocol):
    def claim(self, key: str) -> bool:
        """Atomically reserve an attempt; False means a prior attempt needs manual review."""
        ...


class MemoryLedger:
    def __init__(self) -> None:
        self._keys: set[str] = set()
        self._lock = Lock()

    def claim(self, key: str) -> bool:
        with self._lock:
            if key in self._keys:
                return False
            self._keys.add(key)
            return True


class SQLiteLedger:
    """A persistent ledger for one deployment; provider-side idempotency is still required."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        try:
            with closing(sqlite3.connect(self.path)) as connection, connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS delivery_claims (key TEXT PRIMARY KEY)"
                )
        except sqlite3.Error:
            raise ValidationError("Delivery ledger cannot be opened or initialized") from None

    def claim(self, key: str) -> bool:
        try:
            with closing(sqlite3.connect(self.path)) as connection, connection:
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO delivery_claims(key) VALUES (?)", (key,)
                )
                return cursor.rowcount == 1
        except sqlite3.Error:
            raise ValidationError(
                "Delivery ledger cannot reserve an attempt; dispatch stopped"
            ) from None
