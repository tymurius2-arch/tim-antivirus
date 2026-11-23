"""Журнал угроз и событий (SQLite)."""
from __future__ import annotations

import csv
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from timav.core import paths

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,          -- threat | suspicious | scan | update | info | error
    severity TEXT NOT NULL,      -- high | medium | low | info
    source TEXT NOT NULL,        -- scan | realtime | ai | updater | system
    path TEXT DEFAULT '',
    threat TEXT DEFAULT '',
    action TEXT DEFAULT '',
    details TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""


@dataclass
class Event:
    id: int
    ts: float
    kind: str
    severity: str
    source: str
    path: str
    threat: str
    action: str
    details: str


class Journal:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or (paths.data_dir() / "journal.sqlite")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self.listeners: list = []

    def add(self, kind: str, severity: str, source: str, path: str = "", threat: str = "",
            action: str = "", details: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events(ts,kind,severity,source,path,threat,action,details) VALUES(?,?,?,?,?,?,?,?)",
                (time.time(), kind, severity, source, path, threat, action, details))
            self._conn.commit()
            eid = cur.lastrowid
        for cb in list(self.listeners):
            try:
                cb(eid)
            except Exception:
                pass
        return eid

    def update_action(self, eid: int, action: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE events SET action=? WHERE id=?", (action, eid))
            self._conn.commit()

    def query(self, kind: str | None = None, text: str = "", limit: int = 2000) -> list[Event]:
        sql = "SELECT id,ts,kind,severity,source,path,threat,action,details FROM events"
        cond, args = [], []
        if kind:
            cond.append("kind=?")
            args.append(kind)
        if text:
            cond.append("(path LIKE ? OR threat LIKE ? OR details LIKE ?)")
            args += [f"%{text}%"] * 3
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [Event(*r) for r in rows]

    def count(self, kind: str, since: float = 0.0) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events WHERE kind=? AND ts>=?", (kind, since)).fetchone()[0]

    def unresolved_threats(self) -> int:
        """Угрозы, по которым не принято действие (не помещены в карантин/не удалены)."""
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE kind='threat' AND action IN "
                "('', 'обнаружено', 'ошибка', 'detected', 'error')"
            ).fetchone()[0]

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM events")
            self._conn.commit()

    def export_csv(self, target: Path) -> int:
        rows = self.query(limit=1_000_000)
        with open(target, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["Время", "Тип", "Важность", "Источник", "Путь", "Угроза", "Действие", "Подробности"])
            for e in rows:
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.ts)), e.kind, e.severity,
                            e.source, e.path, e.threat, e.action, e.details])
        return len(rows)

    def close(self) -> None:
        with self._lock:
            self._conn.close()
