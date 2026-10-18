"""Idempotency claims for optional training transports; never stores message contents."""

import sqlite3
from pathlib import Path
from typing import Protocol


class DeliveryLedger(Protocol):
    def claim(self, key: str) -> bool:
        """Atomically reserve an attempt; False means a prior attempt needs manual review."""
        ...


class MemoryLedger:
    def __init__(self) -> None:
        self._keys: set[str] = set()

    def claim(self, key: str) -> bool:
        if key in self._keys:
            return False
        self._keys.add(key)
        return True


class SQLiteLedger:
    """A persistent ledger for one deployment; provider-side idempotency is still required."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        with sqlite3.connect(self.path) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS delivery_claims (key TEXT PRIMARY KEY)")

    def claim(self, key: str) -> bool:
        with sqlite3.connect(self.path) as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO delivery_claims(key) VALUES (?)", (key,)
            )
            return cursor.rowcount == 1
