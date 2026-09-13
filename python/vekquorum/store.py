"""Local SQLite persistence for the vq/1 coordinator.

The normative logical layout is implemented verbatim.  JSON columns store
canonical UTF-8 bytes as BLOBs — never engine-reserialized JSON.  One active
gateway process may own a database: an OS advisory exclusive lock is taken at
startup; failure yields COORDINATOR_BUSY, never a second in-memory
coordinator.
"""

from __future__ import annotations

import fcntl
import os
import sqlite3
from typing import Any, Optional

from .errors import VQError

SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE policies (tenant TEXT NOT NULL, hash TEXT NOT NULL, policy_id TEXT NOT NULL, version INTEGER NOT NULL, body BLOB NOT NULL, PRIMARY KEY (tenant,hash), UNIQUE (tenant,policy_id,version));
CREATE TABLE authorities (tenant TEXT NOT NULL, executor TEXT NOT NULL, epoch INTEGER NOT NULL, body BLOB NOT NULL, PRIMARY KEY (tenant,executor));
CREATE TABLE proposals (tenant TEXT NOT NULL, id TEXT NOT NULL, executor TEXT NOT NULL, operation_id TEXT NOT NULL, nonce TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, action BLOB, view BLOB NOT NULL, initial_authority BLOB NOT NULL, commit_authority BLOB, PRIMARY KEY (tenant,id), UNIQUE (tenant,executor,nonce));
CREATE UNIQUE INDEX live_operation ON proposals(tenant,executor,operation_id) WHERE state IN ('OPEN','READY');
CREATE TABLE votes (tenant TEXT NOT NULL, proposal TEXT NOT NULL, key_id TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY (tenant,proposal,key_id), FOREIGN KEY (tenant,proposal) REFERENCES proposals(tenant,id));
CREATE TABLE events (tenant TEXT NOT NULL, stream TEXT NOT NULL, seq INTEGER NOT NULL, receipt_id TEXT NOT NULL, hash TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY (tenant,stream,seq), UNIQUE (tenant,receipt_id));
CREATE TABLE consumed (tenant TEXT NOT NULL, executor TEXT NOT NULL, operation_id TEXT NOT NULL, proposal TEXT NOT NULL, action_hash TEXT NOT NULL, dispatch_id TEXT NOT NULL, PRIMARY KEY (tenant,executor,operation_id));
CREATE TABLE dispatches (tenant TEXT NOT NULL, dispatch_id TEXT NOT NULL, request BLOB NOT NULL, result BLOB, PRIMARY KEY (tenant,dispatch_id));
CREATE TABLE deliveries (tenant TEXT NOT NULL, escalation_id TEXT NOT NULL, proposal TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL, request BLOB NOT NULL, inbox_ticket TEXT, PRIMARY KEY (tenant,escalation_id));
CREATE TABLE requests (tenant TEXT NOT NULL, principal TEXT NOT NULL, method TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL, response BLOB NOT NULL, PRIMARY KEY (tenant,principal,method,request_id));
CREATE TABLE evidence (tenant TEXT NOT NULL, hash TEXT NOT NULL, kind TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY (tenant,hash));
CREATE TABLE checkpoints (tenant TEXT NOT NULL, proposal TEXT NOT NULL, head_seq INTEGER NOT NULL, body BLOB NOT NULL, PRIMARY KEY (tenant,proposal,head_seq));
"""

SCHEMA_VERSION = 1
PROTOCOL = "vq/1"


class Store:
    """Single-owner SQLite store with a logical monotone clock."""

    def __init__(self, path: str, wall_clock_ms):
        self.path = path
        self._wall_clock_ms = wall_clock_ms
        self._lock_fh = None
        self.db = self._open(path)

    # -- lifecycle -----------------------------------------------------------

    def _open(self, path: str) -> sqlite3.Connection:
        if path != ":memory":
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, exist_ok=True)
            lock_path = path + ".lock"
            self._lock_fh = open(lock_path, "a+b")
            try:
                fcntl.flock(self._lock_fh.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise VQError("COORDINATOR_BUSY") from None
        db = sqlite3.connect(path, isolation_level=None, timeout=5,
                             check_same_thread=False)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=5000")
        existing = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if existing is None:
            db.executescript(SCHEMA)
            self._init_meta(db)
        else:
            self._check_meta(db)
        return db

    def _init_meta(self, db: sqlite3.Connection) -> None:
        for key, value in (("schema_version", str(SCHEMA_VERSION)),
                           ("protocol", PROTOCOL),
                           ("last_logical_ms", "0"),
                           ("last_clean_shutdown", "false"),
                           ("admin_stream", "")):
            db.execute("INSERT INTO meta(key,value) VALUES(?,?)",
                       (key, value.encode()))
        # Opening a database immediately marks the run as unclean until a
        # graceful close; recovery examines consumed dispatches on restart.
        db.execute("UPDATE meta SET value=? WHERE key='last_clean_shutdown'",
                   (b"false",))

    def _check_meta(self, db: sqlite3.Connection) -> None:
        row = db.execute(
            "SELECT value FROM meta WHERE key='protocol'").fetchone()
        if row is None or row[0].decode() != PROTOCOL:
            raise VQError("VERSION_UNSUPPORTED")
        ver = db.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if ver is None or int(ver[0].decode()) != SCHEMA_VERSION:
            raise VQError("VERSION_UNSUPPORTED")
        db.execute("UPDATE meta SET value=? WHERE key='last_clean_shutdown'",
                   (b"false",))

    def close(self) -> None:
        try:
            self.db.execute(
                "UPDATE meta SET value=? WHERE key='last_clean_shutdown'",
                (b"true",))
            self.db.commit()
            self.db.close()
        finally:
            if self._lock_fh is not None:
                fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_UN)
                self._lock_fh.close()
                self._lock_fh = None

    # -- meta / logical clock --------------------------------------------------

    def meta_get(self, key: str) -> Optional[str]:
        row = self.db.execute("SELECT value FROM meta WHERE key=?",
                              (key,)).fetchone()
        return None if row is None else row[0].decode()

    def meta_set(self, key: str, value: str, *,
                 conn: Optional[sqlite3.Connection] = None) -> None:
        c = conn or self.db
        c.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, value.encode()))

    def logical_now(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """max(persisted_last_ms, wall_clock_ms); persisted inside the caller's
        transaction so mutations and time advance atomically."""
        wall = int(self._wall_clock_ms())
        last = int(self.meta_get("last_logical_ms") or "0")
        now = max(last, wall)
        if conn is not None:
            self.meta_set("last_logical_ms", str(now), conn=conn)
        return now

    def was_clean_shutdown(self) -> bool:
        return self.meta_get("last_clean_shutdown") == "true"

    # -- transactions ------------------------------------------------------------

    def begin_immediate(self) -> sqlite3.Connection:
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    @staticmethod
    def commit(db: sqlite3.Connection) -> None:
        db.execute("COMMIT")

    @staticmethod
    def rollback(db: sqlite3.Connection) -> None:
        db.execute("ROLLBACK")

    def tx(self):
        """Context manager: BEGIN IMMEDIATE / COMMIT or ROLLBACK."""
        store = self

        class _Tx:
            def __enter__(self):
                return store.begin_immediate()

            def __exit__(self, exc_type, exc, tb):
                if exc_type is None:
                    store.commit(store.db)
                else:
                    store.rollback(store.db)
                return False

        return _Tx()

    # -- misc helpers -------------------------------------------------------------

    @staticmethod
    def blob(obj: bytes | str) -> bytes:
        return obj.encode("utf-8") if isinstance(obj, str) else obj

    def storage_fail(self, exc: Exception) -> VQError:
        return VQError("STORAGE_UNAVAILABLE",
                       details={"sqlite": type(exc).__name__})
