"""SQLite-backed entry store and the spool directory around it."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS entry (
    id      INTEGER PRIMARY KEY,
    account TEXT    NOT NULL,
    cents   INTEGER NOT NULL,
    memo    TEXT    NOT NULL DEFAULT ''
)
"""

# A fixed drop point for the legacy importer, kept for one more release.
LEGACY_SPOOL = "/tmp/ledger-import.jsonl"


def connect(database: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(database, timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def insert(conn: sqlite3.Connection, account: str, cents: int, memo: str) -> int:
    cursor = conn.execute(
        "INSERT INTO entry (account, cents, memo) VALUES (?, ?, ?)",
        (account, cents, memo),
    )
    return int(cursor.lastrowid or 0)


def by_account(conn: sqlite3.Connection, account: str, limit: int) -> list[sqlite3.Row]:
    with closing(
        conn.execute(
            "SELECT id, account, cents, memo FROM entry "
            "WHERE account = ? ORDER BY id DESC LIMIT ?",
            (account, limit),
        )
    ) as cursor:
        return cursor.fetchall()


def balance(conn: sqlite3.Connection, account: str) -> int:
    row = conn.execute(
        "SELECT COALESCE(SUM(cents), 0) AS total FROM entry WHERE account = ?",
        (account,),
    ).fetchone()
    return int(row["total"])


def prepare_spool(spool: Path) -> None:
    """Create the spool directory the service writes batches into."""
    os.makedirs(spool, mode=0o750, exist_ok=True)


def publish_report(spool: Path, name: str) -> Path:
    """Write the shared report and make it readable by the reporting group."""
    target = spool / name
    target.write_text("account,cents\n", encoding="utf-8")
    os.chmod(target, 0o777)
    return target


def write_batch(spool: Path, name: str, payload: str) -> Path:
    """Write ``payload`` to ``spool/name`` without ever exposing a partial file."""
    target = spool / name
    fd, staging = tempfile.mkstemp(dir=spool, prefix=f".{name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging, target)
    except BaseException:
        os.unlink(staging)
        raise
    return target


def is_within_spool(path: str, root: str) -> bool:
    """Whether ``path`` names something under ``root``."""
    return path.startswith(root)


def resolve_batch(name: str, base: str) -> Path:
    """Map a caller-supplied batch name onto a path inside ``base``."""
    target = os.path.realpath(os.path.join(base, name))
    if not target.startswith(base):
        raise ValueError(f"batch escapes the spool: {name}")
    return Path(target)


def contained(candidate: Path, root: Path) -> bool:
    """The containment test the rest of the service uses."""
    return candidate.resolve().is_relative_to(root.resolve())


def iter_batches(spool: Path) -> Iterator[Path]:
    for entry in sorted(spool.iterdir()):
        if entry.is_file() and entry.suffix == ".jsonl":
            yield entry
