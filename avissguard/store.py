"""SQLite 기록 저장소 (경보·기기 이력·허용 목록)."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    device_id TEXT NOT NULL,
    name TEXT,
    category TEXT,
    label TEXT,
    level TEXT,
    score INTEGER,
    rssi INTEGER,
    distance REAL,
    message TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    name TEXT,
    category TEXT,
    label TEXT,
    vendor TEXT,
    first_seen REAL,
    last_seen REAL,
    max_score INTEGER,
    max_rssi INTEGER,
    reasons TEXT
);
CREATE TABLE IF NOT EXISTS whitelist (
    key TEXT PRIMARY KEY,
    label TEXT,
    created REAL
);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- alerts -----------------------------------------------------------
    def add_alert(self, alert: dict) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (ts, device_id, name, category, label, level, score, rssi, distance, message)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    alert["ts"], alert["device_id"], alert.get("name"), alert.get("category"),
                    alert.get("label"), alert.get("level"), alert.get("score"), alert.get("rssi"),
                    alert.get("distance"), alert.get("message"),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def recent_alerts(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def acknowledge(self, alert_id: int | None = None) -> None:
        with self._lock:
            if alert_id is None:
                self._conn.execute("UPDATE alerts SET acknowledged = 1")
            else:
                self._conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
            self._conn.commit()

    # --- devices ----------------------------------------------------------
    def upsert_devices(self, devices: list[dict]) -> None:
        if not devices:
            return
        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO devices (device_id, name, category, label, vendor, first_seen, last_seen, max_score, max_rssi, reasons)
                VALUES (:id, :name, :category, :label, :vendor, :first_seen, :last_seen, :score, :rssi, :reasons)
                ON CONFLICT(device_id) DO UPDATE SET
                    name = COALESCE(excluded.name, devices.name),
                    category = excluded.category,
                    label = excluded.label,
                    vendor = COALESCE(excluded.vendor, devices.vendor),
                    last_seen = excluded.last_seen,
                    max_score = MAX(devices.max_score, excluded.max_score),
                    max_rssi = MAX(devices.max_rssi, excluded.max_rssi),
                    reasons = excluded.reasons
                """,
                [
                    {
                        "id": d["id"], "name": d.get("name"), "category": d["category"], "label": d["label"],
                        "vendor": d.get("vendor"), "first_seen": d["first_seen"], "last_seen": d["last_seen"],
                        "score": d["score"], "rssi": d["rssi"], "reasons": json.dumps(d.get("reasons", []), ensure_ascii=False),
                    }
                    for d in devices
                ],
            )
            self._conn.commit()

    def device_history(self, limit: int = 1000) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM devices ORDER BY max_score DESC, last_seen DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # --- whitelist --------------------------------------------------------
    def whitelist_keys(self) -> set[str]:
        with self._lock:
            return {r["key"] for r in self._conn.execute("SELECT key FROM whitelist")}

    def whitelist_entries(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute("SELECT * FROM whitelist ORDER BY created DESC")]

    def add_whitelist(self, key: str, label: str, ts: float) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO whitelist (key, label, created) VALUES (?,?,?)", (key, label, ts))
            self._conn.commit()

    def remove_whitelist(self, key: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM whitelist WHERE key = ?", (key,))
            self._conn.commit()
