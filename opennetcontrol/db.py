"""SQLite persistence. Every query is parameterised; no string-built SQL anywhere."""
from __future__ import annotations

import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash BLOB NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')), created REAL NOT NULL, disabled INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS credentials(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, username TEXT NOT NULL, secret_enc BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS devices(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, address TEXT NOT NULL, port INTEGER DEFAULT 22,
  vendor TEXT NOT NULL, platform TEXT NOT NULL, site TEXT DEFAULT '', role TEXT DEFAULT 'switch', tags TEXT DEFAULT '',
  transport TEXT NOT NULL DEFAULT 'ssh', credential_id INTEGER, host_key TEXT, protected_ifaces TEXT DEFAULT '[]',
  mgmt_ip TEXT DEFAULT '', created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots(device_id INTEGER PRIMARY KEY, ts REAL, reachable INTEGER, facts TEXT, error TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS backups(id INTEGER PRIMARY KEY, device_id INTEGER, ts REAL, sha TEXT, config TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS links(a_dev INTEGER, a_if TEXT, b_name TEXT, b_if TEXT, last_seen REAL, PRIMARY KEY(a_dev, a_if, b_name));
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, device_id INTEGER, kind TEXT, key TEXT, severity TEXT, message TEXT,
  opened REAL, closed REAL, status TEXT DEFAULT 'open', incident_id INTEGER);
CREATE INDEX IF NOT EXISTS alerts_open ON alerts(status, device_id);
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, ikey TEXT UNIQUE, root_device_id INTEGER, title TEXT, severity TEXT,
  status TEXT DEFAULT 'open', opened REAL, closed REAL, ack_by TEXT, summary TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS changes(id INTEGER PRIMARY KEY, requester TEXT, approver TEXT, status TEXT, source TEXT, summary TEXT,
  op TEXT, params TEXT, targets TEXT, plan TEXT, results TEXT, created REAL, decided REAL, executed REAL, force_blast INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL, actor TEXT, action TEXT, detail TEXT, prev TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS revoked(jti TEXT PRIMARY KEY, exp REAL);
CREATE TABLE IF NOT EXISTS login_fails(k TEXT, ts REAL);
"""


class DB:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.executescript(SCHEMA)

    def q(self, sql: str, args: tuple = ()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql: str, args: tuple = ()) -> dict | None:
        r = self.q(sql, args)
        return r[0] if r else None

    def x(self, sql: str, args: tuple = ()) -> int:
        with self.lock:
            cur = self.conn.execute(sql, args)
            # INSERT -> new row id; UPDATE/DELETE -> rows affected (lastrowid is stale for these!)
            return cur.lastrowid if sql.lstrip()[:6].upper() == "INSERT" else cur.rowcount

    def tx(self):
        return _Tx(self)


class _Tx:
    def __init__(self, db): self.db = db
    def __enter__(self):
        self.db.lock.acquire(); self.db.conn.execute("BEGIN IMMEDIATE"); return self.db
    def __exit__(self, et, ev, tb):
        try:
            self.db.conn.execute("ROLLBACK" if et else "COMMIT")
        finally:
            self.db.lock.release()


def now() -> float:
    return time.time()


def jdump(o) -> str:
    return json.dumps(o, separators=(",", ":"), default=str)
